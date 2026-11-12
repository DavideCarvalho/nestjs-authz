---
"@dudousxd/nestjs-authz": minor
---

Protect Aviary consoles with the Gate. `AuthzModule` now provides the console gate the durable, telescope, media and agent consoles use for `authorize: '<gate name>'`, and exports `authorizeByRoles({ roles })`, `authorizeByPermission(permission)`, `authorizeByToken({ token })` and the console access types (`ConsoleAuthorize`, `ConsoleAuthorizer`, `ConsoleAuthorizeResult`, `ConsoleAuthorizerClass`, `ConsolePolicyCheck`). See "Protecting Aviary consoles" in the docs.
