---
"@dudousxd/nestjs-authz-codegen": minor
---

Type client abilities from the official `@Can(Policy, 'ability', byId(Resource))`,
`@Permission` / `PermissionPolicy` permission names, `GatePolicy` abilities and
`@Policy()` / `@PolicyFor()` classes (skipping `before` and `scope`). The 0.8 string
`@Can('update', Post)` and `@Policy(Post)` are no longer read; a policy's resource comes from
`@PolicyFor(Resource)` (else its name). Peers on `@dudousxd/nestjs-authz` `>=0.9.0 <0.10.0`.
