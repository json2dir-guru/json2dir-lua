-- json2dir evaluator (plain Lua 5.4, standard library only).
-- Reads the document from the file given as the only argument, checks UTF-8, parses the
-- JSON by hand, validates the whole document (RFC J2D-1 sections 3, 4) and writes a POSIX
-- shell script that creates the tree to stdout. Any problem: message on stderr, exit 1.

local function fail(msg)
  io.stderr:write("json2dir: ", msg, "\n")
  os.exit(1)
end

local path = arg[1]
if not path or arg[2] then fail("usage: lua json2dir.lua input.json") end
local f = io.open(path, "rb")
if not f then fail("cannot read input") end
local src = f:read("a")
f:close()

-- A byte order mark at the start is ignored, as RFC 8259 permits.
if src:sub(1, 3) == "\239\187\191" then src = src:sub(4) end

-- Strict UTF-8: no overlongs, no surrogates (ED A0..BF), nothing above U+10FFFF.
do
  local i, n = 1, #src
  while i <= n do
    local c = src:byte(i)
    local len, lo, hi = 1, 0x80, 0xBF
    if c < 0x80 then len = 1
    elseif c >= 0xC2 and c <= 0xDF then len = 2
    elseif c >= 0xE0 and c <= 0xEF then
      len = 3
      if c == 0xE0 then lo = 0xA0 elseif c == 0xED then hi = 0x9F end
    elseif c >= 0xF0 and c <= 0xF4 then
      len = 4
      if c == 0xF0 then lo = 0x90 elseif c == 0xF4 then hi = 0x8F end
    else
      fail("input is not valid UTF-8")
    end
    for k = 1, len - 1 do
      local b = src:byte(i + k)
      if not b then fail("input is not valid UTF-8") end
      if k == 1 then
        if b < lo or b > hi then fail("input is not valid UTF-8") end
      elseif b < 0x80 or b > 0xBF then
        fail("input is not valid UTF-8")
      end
    end
    i = i + len
  end
end

-- JSON parser. Values: strings are Lua strings, objects {kind="object", keys={...}, map={...}},
-- arrays {kind="array", ...}, other values {kind="number"|"true"|"false"|"null"}.
local pos = 1

local function perr(msg)
  fail("invalid JSON at byte " .. pos .. ": " .. msg)
end

local function skip_ws()
  pos = src:find("[^ \t\r\n]", pos) or #src + 1
end

local function hex4()
  local h = src:sub(pos, pos + 3)
  if not h:match("^%x%x%x%x$") then perr("bad \\u escape") end
  pos = pos + 4
  return tonumber(h, 16)
end

local escapes = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

local function parse_string()
  pos = pos + 1 -- opening quote
  local parts = {}
  while true do
    local s, e = src:find('^[^"\\%c]+', pos)
    if s then
      parts[#parts + 1] = src:sub(s, e)
      pos = e + 1
    end
    local c = src:sub(pos, pos)
    if c == '"' then
      pos = pos + 1
      return table.concat(parts)
    elseif c == "\\" then
      local e2 = src:sub(pos + 1, pos + 1)
      if escapes[e2] then
        parts[#parts + 1] = escapes[e2]
        pos = pos + 2
      elseif e2 == "u" then
        pos = pos + 2
        local u = hex4()
        if u >= 0xD800 and u <= 0xDBFF then
          if src:sub(pos, pos + 1) ~= "\\u" then perr("unpaired surrogate") end
          pos = pos + 2
          local u2 = hex4()
          if u2 < 0xDC00 or u2 > 0xDFFF then perr("unpaired surrogate") end
          u = 0x10000 + (u - 0xD800) * 0x400 + (u2 - 0xDC00)
        elseif u >= 0xDC00 and u <= 0xDFFF then
          perr("unpaired surrogate")
        end
        parts[#parts + 1] = utf8.char(u)
      else
        perr("bad escape")
      end
    elseif c == "" then
      perr("unterminated string")
    elseif src:byte(pos) < 0x20 then
      perr("control character in string")
    else
      -- DEL (0x7F) is a %c in the C locale but allowed in JSON strings.
      parts[#parts + 1] = c
      pos = pos + 1
    end
  end
end

local parse_value

local function parse_object()
  pos = pos + 1
  local obj = { kind = "object", keys = {}, map = {} }
  skip_ws()
  if src:sub(pos, pos) == "}" then
    pos = pos + 1
    return obj
  end
  while true do
    skip_ws()
    if src:sub(pos, pos) ~= '"' then perr("expected a member name") end
    local k = parse_string()
    skip_ws()
    if src:sub(pos, pos) ~= ":" then perr("expected ':'") end
    pos = pos + 1
    local v = parse_value()
    -- Duplicate names: the last occurrence wins.
    if obj.map[k] == nil then obj.keys[#obj.keys + 1] = k end
    obj.map[k] = v
    skip_ws()
    local c = src:sub(pos, pos)
    pos = pos + 1
    if c == "}" then return obj end
    if c ~= "," then pos = pos - 1; perr("expected ',' or '}'") end
  end
end

local function parse_array()
  pos = pos + 1
  local arr = { kind = "array" }
  skip_ws()
  if src:sub(pos, pos) == "]" then
    pos = pos + 1
    return arr
  end
  while true do
    arr[#arr + 1] = parse_value()
    skip_ws()
    local c = src:sub(pos, pos)
    pos = pos + 1
    if c == "]" then return arr end
    if c ~= "," then pos = pos - 1; perr("expected ',' or ']'") end
  end
end

function parse_value()
  skip_ws()
  local c = src:sub(pos, pos)
  if c == "{" then return parse_object()
  elseif c == "[" then return parse_array()
  elseif c == '"' then return parse_string()
  end
  for _, lit in ipairs({ "true", "false", "null" }) do
    if src:sub(pos, pos + #lit - 1) == lit then
      pos = pos + #lit
      return { kind = lit }
    end
  end
  -- Number: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [-+]? [0-9]+)?
  local p = pos
  p = src:match("^-?()", p)
  local q1 = src:match("^0()", p) or src:match("^[1-9]%d*()", p)
  if not q1 then perr("unexpected character") end
  p = q1
  if src:sub(p, p) == "." then p = src:match("^%d+()", p + 1) or perr("bad number") end
  if src:match("^[eE]", p) then p = src:match("^[-+]?%d+()", p + 1) or perr("bad number") end
  pos = p
  return { kind = "number" }
end

local doc = parse_value()
skip_ws()
if pos <= #src then perr("trailing data") end

-- Validation and shell generation.
local function q(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

-- NUL cannot travel in a shell argument, so content is passed as the words between NULs;
-- the script writes them joined by NUL bytes using a constant printf format.
local function content(s)
  local out = {}
  for part in (s .. "\0"):gmatch("([^%z]*)%z") do out[#out + 1] = " " .. q(part) end
  return table.concat(out)
end

local function show(s)
  return '"' .. s:gsub("[%c\"\\]", function(c) return string.format("\\u%04x", c:byte()) end) .. '"'
end

local out = {}
local function emit(s) out[#out + 1] = s end

local function tree(dir, obj)
  local keys = {}
  for i, k in ipairs(obj.keys) do keys[i] = k end
  -- Lua compares strings bytewise in the C locale = UTF-8 byte order of names.
  table.sort(keys)
  for _, name in ipairs(keys) do
    local v = obj.map[name]
    local p = dir .. "/" .. name
    if name == "" or name == "." or name == ".." or name:find("/", 1, true) or name:find("\0", 1, true) then
      fail("invalid name " .. show(name) .. " at " .. show(dir))
    end
    if type(v) == "string" then
      emit("_j2d_file " .. q(p) .. content(v) .. "\n")
    elseif v.kind == "object" then
      emit("_j2d_dir " .. q(p) .. "\n")
      tree(p, v)
    elseif v.kind == "array" then
      if #v ~= 2 or type(v[1]) ~= "string" or type(v[2]) ~= "string" then
        fail('an array must be ["link", target] or ["script", content] at ' .. show(p))
      elseif v[1] == "script" then
        emit("_j2d_script " .. q(p) .. content(v[2]) .. "\n")
      elseif v[1] == "link" then
        if v[2]:find("\0", 1, true) then fail("a link target cannot contain NUL at " .. show(p)) end
        emit("_j2d_link " .. q(p) .. " " .. q(v[2]) .. "\n")
      else
        fail("unknown array kind " .. show(v[1]) .. " at " .. show(p))
      end
    else
      fail(v.kind .. " values are not allowed at " .. show(p))
    end
  end
end

if type(doc) ~= "table" or doc.kind ~= "object" then
  fail("the root of the document must be an object")
end

emit([[
set -eu
_j2d_fail() { printf 'json2dir: cannot create %s\n' "$1" >&2; exit 1; }
# Remove an existing non-directory (a symlink itself, never its target);
# a real directory in the way of a non-object is an error.
_j2d_clear() {
  if [ -L "$1" ]; then rm -f -- "$1" || _j2d_fail "$1"
  elif [ -d "$1" ]; then printf 'json2dir: a directory is in the way: %s\n' "$1" >&2; exit 1
  elif [ -e "$1" ]; then rm -f -- "$1" || _j2d_fail "$1"
  fi
}
_j2d_dir() {
  if [ -L "$1" ] || { [ -e "$1" ] && [ ! -d "$1" ]; }; then rm -f -- "$1" || _j2d_fail "$1"; fi
  if [ ! -d "$1" ]; then mkdir -- "$1" || _j2d_fail "$1"; fi
}
# _j2d_file path part...: the content is the parts joined by NUL bytes.
_j2d_file() {
  _j2d_clear "$1"
  _j2d_path=$1; shift
  {
    printf '%s' "$1"; shift
    for _j2d_part in "$@"; do printf '\000%s' "$_j2d_part"; done
  } > "$_j2d_path" || _j2d_fail "$_j2d_path"
}
_j2d_script() { _j2d_file "$@"; chmod a+x -- "$1" || _j2d_fail "$1"; }
_j2d_link() { _j2d_clear "$1"; ln -s -- "$2" "$1" || _j2d_fail "$1"; }
]])
tree(".", doc)

io.stdout:write(table.concat(out))
