local kernauth = require("kernauth")

local body = kernauth.check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP")
if body.protocol_version ~= 1 or body.public_app_id ~= "pub_harbor_desktop"
    or body.client_version ~= "1.0.0" or body.license_key ~= "KERN-ABCD-EFGH-IJKL-MNOP" then
  io.stderr:write("lua body\n")
  os.exit(1)
end
if kernauth.api_message({ error = { message = "Update required" } }, "no") ~= "Update required" then
  io.stderr:write("lua message\n")
  os.exit(1)
end
if kernauth.api_message({}, "no") ~= "no" then
  io.stderr:write("lua fallback\n")
  os.exit(1)
end
io.write("Lua check passed\n")
