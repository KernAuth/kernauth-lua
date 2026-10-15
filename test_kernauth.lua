dofile("kernauth.lua")

local function new_copy(source, key, value)
  local copy = setmetatable({}, getmetatable(source))
  for name, item in pairs(source) do copy[name] = item end
  copy[key] = value
  return copy
end

local handle = assert(io.open("vectors.json", "rb"))
local fixture = parse_json(handle:read("*a"))
handle:close()
local now = instant_ms("2026-01-01T00:01:00.000Z")

for _, vector in ipairs(fixture.vectors) do
  local ent = vector.fields
  local grant = { entitlement = ent, signature = vector.signature }
  if canonical(ent) ~= vector.canonical then
    io.stderr:write(vector.name, " canonical\n")
    os.exit(1)
  end
  local function check(label, value, expected)
    if value ~= expected then
      io.stderr:write(vector.name, " ", label, "\n")
      os.exit(1)
    end
  end
  check("ok", verify_grant(grant, ent.nonce, ent.application_id, vector.public_key, now), true)
  check("nonce", verify_grant(grant, "wrong", ent.application_id, vector.public_key, now), false)
  check("app", verify_grant(grant, ent.nonce, "pub_other_app", vector.public_key, now), false)
  check("sig", verify_grant({ entitlement = ent, signature = vector.signature .. "AA" }, ent.nonce, ent.application_id, vector.public_key, now), false)
  check("expiry", verify_grant(grant, ent.nonce, ent.application_id, vector.public_key, instant_ms(ent.expires_at)), false)
  local tampered = new_copy(ent, "device_id", "other")
  check("device", verify_grant({ entitlement = tampered, signature = vector.signature }, ent.nonce, ent.application_id, vector.public_key, now), false)
  local revoked = new_copy(ent, "status", "revoked")
  check("status", verify_grant({ entitlement = revoked, signature = vector.signature }, ent.nonce, ent.application_id, vector.public_key, now), false)
end
io.write("Lua vectors passed\n")
