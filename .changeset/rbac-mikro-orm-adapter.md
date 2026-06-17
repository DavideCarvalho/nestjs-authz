---
"@dudousxd/nestjs-authz-mikro-orm": minor
---

New package: `@dudousxd/nestjs-authz-mikro-orm` — a MikroORM RBAC persistence adapter
mirroring `@dudousxd/nestjs-authz-typeorm`. Ships Role/Permission/RolePermission/UserRole
entities (user referenced by id only), a `MikroOrmAuthzStore` POJO with the same method
surface, `AuthzRbacModule.forRoot/forRootAsync` registering the core `ROLE_PROVIDER` +
`PERMISSION_PROVIDER` seams, and non-destructive `ensureAuthzSchema` (native
`updateSchema({ safe: true })`) with an `authzSchemaSql` migration helper. `autoCreateSchema`
defaults to true.
