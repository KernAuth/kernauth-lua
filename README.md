# KernAuth Lua example

Example for Lua 5.4. Lua's standard library has no HTTPS or Ed25519, so this file uses `curl` for the request and the `openssl` command for the signature. This file calls validate and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `kernauth.lua`.

```
lua test_kernauth.lua
```

Run from the repository root so the test can read `vectors.json`. Run the example with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```lua
local app = KernAuth.new(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__KEY_ID__",
  "__PUBLIC_KEY__"
)
```

## Validate

```lua
if not app:validate(license, installation) then
  error(app.message)
end
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
