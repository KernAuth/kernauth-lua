# KernAuth Lua example

Paste the public app ID from Developers into `main.lua`. Lua 5.4. The standard library has no HTTPS client, so the library uses curl.

## Start

```lua
local app = kernauth.new("https://api.kernauth.com", "__PUBLIC_APP_ID__")
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
lua test_kernauth.lua
lua main.lua
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
