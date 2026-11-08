---
"@dudousxd/nestjs-authz": patch
---

Importing `AuthzModule` without `@nestjs/authorization`'s `AuthorizationModule` now fails the boot
with an error naming the missing `AuthorizationModule.forRoot()` import, instead of Nest's
unresolvable-dependency error on `Gate` / `AuthzGuard`.
