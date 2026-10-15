local kernauth = require("kernauth")

local function license_key()
  local from_env = os.getenv("KERN_LICENSE_KEY")
  if from_env and from_env:match("%S") then return from_env:match("^%s*(.-)%s*$") end
  io.write("Enter license: ")
  io.flush()
  return (io.read() or ""):match("^%s*(.-)%s*$")
end

local app = kernauth.new("https://api.kernauth.com", "__PUBLIC_APP_ID__")
if not kernauth.check(app, license_key()) then
  io.write(app.message, "\n")
  os.exit(1)
end
io.write("Status: active\n")
io.write(app.expires_at and ("Expires: " .. app.expires_at .. "\n") or "Expires: Lifetime\n")
