---
"@dudousxd/nestjs-authz-inertia": major
---

Share the class-level abilities of every official `@Policy()` (linked with `@PolicyFor` or not,
keyed `<resource>.<method>`), checked through the official `AuthorizationService` for the user
the official guard reads. `resolveClassAbilities` / `createAuthzShare` take a `PolicyIndex`
(was `PolicyRegistry`) and accept `gate.forUser(user)`. The denial filter also redirects the
official guard's 401 to `loginUrl`; without nestjs-context a 403 now goes to `forbiddenUrl`.
Requires `@dudousxd/nestjs-authz` 1.x, NestJS 12 and Node 22+.
