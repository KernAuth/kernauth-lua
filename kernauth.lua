local M = {}

function M.check_body(app_id, license_key)
  return {
    protocol_version = 1,
    public_app_id = app_id,
    client_version = "1.0.0",
    license_key = license_key,
  }
end

function M.api_message(payload, fallback)
  local message = type(payload) == "table" and type(payload.error) == "table" and payload.error.message or nil
  if type(message) == "string" and message ~= "" then return message end
  return fallback
end

local function encode(body)
  return string.format(
    '{"protocol_version":1,"public_app_id":%s,"client_version":"1.0.0","license_key":%s}',
    string.format("%q", body.public_app_id), string.format("%q", body.license_key))
end

local function decode_message(raw)
  return raw:match('"message"%s*:%s*"([^"]*)"')
end

function M.new(api, app_id)
  return { api = api, app_id = app_id, message = "", expires_at = nil }
end

function M.check(app, license_key)
  local body = encode(M.check_body(app.app_id, license_key))
  local command = string.format(
    "curl -sS -m 10 -w '\\n%%{http_code}' -H 'content-type: application/json' -d '%s' '%s'",
    body, app.api .. "/v1/client/check")
  local handle = io.popen(command, "r")
  if not handle then
    app.message = "check failed"
    return false
  end
  local raw = handle:read("*a") or ""
  handle:close()
  local payload, status = raw:match("^(.*)\n(%d%d%d)%s*$")
  status = tonumber(status or "0")
  local valid = payload and payload:find('"valid"%s*:%s*true', 1, false)
  if status ~= 200 or not valid then
    local message = payload and decode_message(payload) or nil
    app.message = (message and message ~= "") and message or ("check failed (" .. tostring(status) .. ")")
    app.expires_at = nil
    return false
  end
  app.message = "License is active"
  app.expires_at = payload:match('"expires_at"%s*:%s*"([^"]*)"')
  return true
end

return M
