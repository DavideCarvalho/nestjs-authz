# @dudousxd/nestjs-authz-mikro-orm

## 0.2.0

### Minor Changes

- [#4](https://github.com/DavideCarvalho/nestjs-authz/pull/4) [`8b7711d`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b7711d11bdb25b3407fea742f6c1158afb36296) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - New package: `@dudousxd/nestjs-authz-mikro-orm` — a MikroORM RBAC persistence adapter
  mirroring `@dudousxd/nestjs-authz-typeorm`. Ships Role/Permission/RolePermission/UserRole
  entities (user referenced by id only), a `MikroOrmAuthzStore` POJO with the same method
  surface, `AuthzRbacModule.forRoot/forRootAsync` registering the core `ROLE_PROVIDER` +
  `PERMISSION_PROVIDER` seams, and non-destructive `ensureAuthzSchema` (native
  `updateSchema({ safe: true })`) with an `authzSchemaSql` migration helper. `autoCreateSchema`
  defaults to true.
