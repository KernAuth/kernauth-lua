-- Lua's standard library has no HTTPS client and no signature check. This file
-- uses curl for the request and the openssl command for the signature.

local API = "https://api.kernauth.com"
local APP_ID = "__PUBLIC_APP_ID__"
local KEY_ID = "__KEY_ID__"
local PUBLIC_KEY = "__PUBLIC_KEY__"
local FIELDS = {
  "protocol_version", "entitlement_id", "application_id", "license_id", "status",
  "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id",
}
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local object_mt = {}

local KernAuth = {}
KernAuth.__index = KernAuth

function KernAuth.new(api, app_id, key_id, public_key)
  return setmetatable({
    api = api or API, app_id = app_id or APP_ID, key_id = key_id or KEY_ID,
    public_key = public_key or PUBLIC_KEY, success = false, message = "", entitlement = nil,
  }, KernAuth)
end

function KernAuth:validate(license_key, installation_id)
  return self:call("validate", license_key, installation_id, "License is active")
end

function KernAuth:call(mode, license_key, installation_id, ok_message)
  local ok, result = pcall(request, mode, license_key, installation_id, self.api, self.app_id, self.key_id, self.public_key)
  if not ok then
    self.success = false
    self.message = tostring(result)
    self.entitlement = nil
    return false
  end
  self.success = true
  self.message = ok_message
  local features = result.features
  if type(features) == "string" then features = parse_json(features) end
  result.features = encode_json(features)
  self.entitlement = result
  return true
end

local function is_object(value)
  return getmetatable(value) == object_mt
end

local function new_object(pairs_list)
  local object = setmetatable({}, object_mt)
  for _, pair in ipairs(pairs_list or {}) do object[pair[1]] = pair[2] end
  return object
end

function b64encode(data)
  local out = {}
  for i = 1, #data, 3 do
    local a, b, c = data:byte(i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    out[#out + 1] = B64:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
    out[#out + 1] = B64:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    out[#out + 1] = b and B64:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1) or "="
    out[#out + 1] = c and B64:sub(n % 64 + 1, n % 64 + 1) or "="
  end
  return table.concat(out)
end

function b64decode(data)
  if type(data) ~= "string" or not data:match("^[A-Za-z0-9+/]+=?=?$") or #data % 4 ~= 0 then return nil end
  local map = {}
  for i = 1, #B64 do map[B64:sub(i, i)] = i - 1 end
  data = data:gsub("=+$", "")
  local out, buffer, bits = {}, 0, 0
  for i = 1, #data do
    local val = map[data:sub(i, i)]
    if not val then return nil end
    buffer = buffer * 64 + val
    bits = bits + 6
    if bits >= 8 then
      bits = bits - 8
      out[#out + 1] = string.char(math.floor(buffer / (2 ^ bits)) % 256)
      buffer = buffer % (2 ^ bits)
    end
  end
  return table.concat(out)
end

local function hex_to_bin(hex)
  return (hex:gsub("%x%x", function(byte) return string.char(tonumber(byte, 16)) end))
end

function parse_json(text)
  local i, n = 1, #text
  local function peek() return text:sub(i, i) end
  local function skip()
    while peek():match("%s") do i = i + 1 end
  end
  local parse_value
  local function parse_string()
    i = i + 1
    local parts = {}
    while i <= n do
      local c = peek()
      if c == '"' then i = i + 1 return table.concat(parts) end
      if c == "\\" then
        local e = text:sub(i + 1, i + 1)
        local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
        if map[e] then
          parts[#parts + 1] = map[e]
          i = i + 2
        elseif e == "u" then
          local cp = tonumber(text:sub(i + 2, i + 5), 16)
          if not cp then error("bad unicode") end
          if cp < 0x80 then parts[#parts + 1] = string.char(cp)
          elseif cp < 0x800 then parts[#parts + 1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + (cp % 64))
          else parts[#parts + 1] = string.char(0xE0 + math.floor(cp / 4096), 0x80 + (math.floor(cp / 64) % 64), 0x80 + (cp % 64)) end
          i = i + 6
        else error("bad escape") end
      else
        parts[#parts + 1] = c
        i = i + 1
      end
    end
    error("unterminated string")
  end
  local function parse_number()
    local start = i
    if peek() == "-" then i = i + 1 end
    if not peek():match("%d") then error("bad number") end
    while peek():match("%d") do i = i + 1 end
    local is_float = false
    if peek() == "." then
      is_float = true
      i = i + 1
      while peek():match("%d") do i = i + 1 end
    end
    if peek() == "e" or peek() == "E" then
      is_float = true
      i = i + 1
      if peek() == "+" or peek() == "-" then i = i + 1 end
      while peek():match("%d") do i = i + 1 end
    end
    local raw = text:sub(start, i - 1)
    if not is_float then return math.tointeger(raw) end
    return tonumber(raw)
  end
  parse_value = function()
    skip()
    local c = peek()
    if c == '"' then return parse_string() end
    if c == "{" then
      i = i + 1
      local object = new_object()
      skip()
      if peek() == "}" then i = i + 1 return object end
      while true do
        skip()
        if peek() ~= '"' then error("bad object key") end
        local key = parse_string()
        skip()
        if peek() ~= ":" then error("bad object") end
        i = i + 1
        object[key] = parse_value()
        skip()
        local mark = peek()
        i = i + 1
        if mark == "}" then return object end
        if mark ~= "," then error("bad object") end
      end
    end
    if c == "[" then
      i = i + 1
      local array = {}
      skip()
      if peek() == "]" then i = i + 1 return array end
      while true do
        array[#array + 1] = parse_value()
        skip()
        local mark = peek()
        i = i + 1
        if mark == "]" then return array end
        if mark ~= "," then error("bad array") end
      end
    end
    if text:sub(i, i + 3) == "true" then i = i + 4 return true end
    if text:sub(i, i + 4) == "false" then i = i + 5 return false end
    if text:sub(i, i + 3) == "null" then i = i + 4 return nil end
    if c == "-" or c:match("%d") then return parse_number() end
    error("bad json at " .. i)
  end
  local value = parse_value()
  skip()
  if i <= n then error("trailing json") end
  return value
end

function encode_json(value)
  local kind = type(value)
  if value == nil then return "null" end
  if kind == "boolean" then return value and "true" or "false" end
  if kind == "number" then
    if math.type(value) == "integer" then return string.format("%d", value) end
    return string.format("%.16g", value)
  end
  if kind == "string" then
    return '"' .. value:gsub('[%z\1-\31\\"]', function(c)
      local map = { ['"'] = '\\"', ["\\"] = "\\\\", ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t" }
      return map[c] or string.format("\\u%04x", c:byte())
    end) .. '"'
  end
  if is_object(value) then
    local keys = {}
    for key in pairs(value) do keys[#keys + 1] = key end
    table.sort(keys)
    local parts = {}
    for _, key in ipairs(keys) do parts[#parts + 1] = encode_json(key) .. ":" .. encode_json(value[key]) end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  if kind == "table" then
    local parts = {}
    for _, item in ipairs(value) do parts[#parts + 1] = encode_json(item) end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  error("bad json value")
end

local function field_string(value)
  if type(value) == "number" and math.type(value) == "integer" then return string.format("%d", value) end
  return tostring(value)
end

function canonical(entitlement)
  local lines = {}
  for _, name in ipairs(FIELDS) do
    local value
    if name == "features" then
      local features = entitlement.features
      if type(features) == "string" then features = parse_json(features) end
      value = encode_json(features)
    else
      value = field_string(entitlement[name])
    end
    if value:find("\n", 1, true) or value:find("\r", 1, true) then error("Invalid entitlement field") end
    lines[#lines + 1] = name .. "=" .. value
  end
  return table.concat(lines, "\n") .. "\n"
end

function instant_ms(text)
  local y, mo, d, h, mi, s, frac = text:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)%.(%d+)Z$")
  if not y then return nil end
  local fields = {
    year = tonumber(y), month = tonumber(mo), day = tonumber(d),
    hour = tonumber(h), min = tonumber(mi), sec = tonumber(s), isdst = false,
  }
  local candidate = os.time(fields)
  local gm = os.date("!*t", candidate)
  gm.isdst = false
  return (candidate + os.difftime(candidate, os.time(gm))) * 1000 + tonumber(frac:sub(1, 3))
end

local function run(command)
  local ok, how, code = os.execute(command)
  return ok == true or ok == 0 or code == 0
end

function verify_grant(grant, nonce, app_id, key_id, public_key, now_ms)
  app_id = app_id or APP_ID
  key_id = key_id or KEY_ID
  public_key = public_key or PUBLIC_KEY
  local ent = grant.entitlement
  if ent.protocol_version ~= 1 or ent.nonce ~= nonce or ent.application_id ~= app_id or
      ent.key_id ~= key_id or ent.status ~= "active" then return false end
  now_ms = now_ms or (os.time() * 1000)
  local expiry_ms = instant_ms(ent.expires_at)
  if not expiry_ms or expiry_ms <= now_ms then return false end
  local raw = b64decode(public_key)
  local signature = b64decode(grant.signature)
  if not raw or #raw ~= 32 or not signature or #signature ~= 64 then return false end
  local base = os.tmpname()
  os.remove(base)
  local pub, msg, sig = base .. ".pem", base .. ".msg", base .. ".sig"
  local function write_file(path, data)
    local handle = assert(io.open(path, "wb"))
    handle:write(data)
    handle:close()
  end
  write_file(pub, "-----BEGIN PUBLIC KEY-----\n" .. b64encode(hex_to_bin("302a300506032b6570032100") .. raw) .. "\n-----END PUBLIC KEY-----\n")
  local message = canonical(ent)
  write_file(msg, message)
  write_file(sig, signature)
  local verified = run(string.format("openssl pkeyutl -verify -pubin -inkey %q -rawin -in %q -sigfile %q >/dev/null 2>&1", pub, msg, sig))
  os.remove(pub)
  os.remove(msg)
  os.remove(sig)
  return verified
end

function request(mode, license_key, installation_id, api, app_id, key_id, public_key)
  local random = assert(io.open("/dev/urandom", "rb"))
  local nonce_raw = random:read(24)
  random:close()
  local nonce = b64encode(nonce_raw):gsub("+", "-"):gsub("/", "_"):gsub("=", "")
  local digest = io.popen(string.format("printf %%s %q | openssl dgst -sha256", "kernauth-device-v1:" .. installation_id), "r")
  local fingerprint = digest:read("*a"):match("(%x+)%s*$")
  digest:close()
  if not fingerprint or #fingerprint ~= 64 then error("fingerprint failed") end
  local body = encode_json(new_object({
    { "protocol_version", 1 }, { "public_app_id", app_id }, { "client_version", "1.0.0" },
    { "license_key", license_key }, { "fingerprint_version", 1 }, { "device_fingerprint", fingerprint },
    { "installation_id", installation_id }, { "nonce", nonce },
  }))
  local req = os.tmpname()
  local resp = os.tmpname()
  local handle = assert(io.open(req, "wb"))
  handle:write(body)
  handle:close()
  local code_text = io.popen(string.format(
    "curl -sS -o %q -w %%{http_code} -X POST -H %q --data-binary @%q %q",
    resp, "content-type: application/json", req, api .. "/v1/client/" .. mode), "r")
  local status = code_text:read("*a")
  code_text:close()
  local response = assert(io.open(resp, "rb"))
  local raw = response:read("*a")
  response:close()
  os.remove(req)
  os.remove(resp)
  if status ~= "200" and status ~= "201" then error(mode .. " failed (" .. status .. ")") end
  local grant = parse_json(raw)
  if not verify_grant(grant, nonce, app_id, key_id, public_key, nil) then error("Invalid or expired signed entitlement") end
  return grant.entitlement or grant["entitlement"]
end

local function trim(value)
  return (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function stdin_tty()
  local handle = io.popen("test -t 0 && printf 1 || printf 0", "r")
  if not handle then return false end
  local text = handle:read("*a")
  handle:close()
  return text == "1"
end

local function license_key()
  local env = trim(os.getenv("KERN_LICENSE_KEY"))
  if env ~= "" then return env end
  if stdin_tty() then io.write("Enter license: ") io.flush() end
  return trim(io.read("*l"))
end

local function machine_hwid()
  if package.config:sub(1, 1) == "\\" then
    local handle = io.popen([[powershell.exe -NoProfile -Command "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"]], "r")
    if not handle then return "" end
    local text = handle:read("*a") or ""
    handle:close()
    return text
  end
  local existing = io.open("/etc/machine-id", "r")
  if existing then
    local text = existing:read("*a")
    existing:close()
    return text
  end
  local handle = io.popen("ioreg -rd1 -c IOPlatformExpertDevice", "r")
  if not handle then return "" end
  local text = handle:read("*a") or ""
  handle:close()
  return text:match('"IOPlatformUUID" = "([^"]+)"') or ""
end

local function installation_id()
  local env = trim(os.getenv("KERN_INSTALLATION_ID"))
  if env ~= "" then return env end
  local hwid = trim(machine_hwid())
  if hwid:match("^[A-Za-z0-9_%-][%w_%-]*$") and #hwid >= 8 and #hwid <= 64 then return hwid end
  error("Could not read the HWID")
end

if arg and arg[0] then
  local invoked = arg[0]:gsub("\\", "/")
  if invoked == "kernauth.lua" or invoked:match("/kernauth%.lua$") then
  local app = KernAuth.new(API, APP_ID, KEY_ID, PUBLIC_KEY)
  if not app:validate(license_key(), installation_id()) then error(app.message) end
  local ent = app.entitlement
  io.write("Status: ", tostring(ent.status), "\n")
  io.write("Features: ", ent.features, "\n")
  io.write("License: ", tostring(ent.license_id), "\n")
  io.write("Check expires: ", tostring(ent.expires_at), "\n")
  end
end
