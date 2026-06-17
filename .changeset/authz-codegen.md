---
"@dudousxd/nestjs-authz-codegen": minor
---

Initial release of `@dudousxd/nestjs-authz-codegen`: a `@dudousxd/nestjs-codegen` extension that
discovers `@Can(ability, Resource?)` decorators on your controllers (and, optionally, `@Policy`
method abilities) and emits a typed `can()` helper into your generated `api.ts`. The discovered
abilities become a string-literal `AuthzAbility` union, so calling `can()` with an ability that
doesn't exist on the server is a compile-time error. Routes carrying a `@Can` also expose a
route-pinned `can()` handle member when a client layer is active.
