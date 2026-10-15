# KernAuth Lua example

Paste the public app ID and public key from Developers into `kernauth.lua`. Lua 5.4. The standard library has no HTTPS client, so this file uses curl for the request and the openssl command for the signature.

## Instance

```lua
local app = KernAuth.new(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__PUBLIC_KEY__"
)
```

## Validate

```lua
if not app:validate(license, installation) then
  error(app.message)
end
io.write("Status: ", app.entitlement.status, "\n")
io.write("Features: ", app.entitlement.features, "\n")
io.write("License: ", app.entitlement.license_id, "\n")
io.write("Check expires: ", app.entitlement.expires_at, "\n")
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
lua test_kernauth.lua
lua kernauth.lua
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
