# @dudousxd/nestjs-authz-prisma

## 0.2.0

### Minor Changes

- [#4](https://github.com/DavideCarvalho/nestjs-authz/pull/4) [`8b7711d`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b7711d11bdb25b3407fea742f6c1158afb36296) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - New package: `@dudousxd/nestjs-authz-prisma` — a Prisma RBAC persistence adapter mirroring
  `@dudousxd/nestjs-authz-typeorm`. Exposes a `PRISMA_CLIENT` DI token plus a minimal
  **structural** `PrismaAuthzClientLike` interface (no `@prisma/client` import / no
  `prisma generate` step), a `PrismaAuthzStore` with the same method surface, and
  `AuthzRbacModule.forRoot/forRootAsync` registering the core `ROLE_PROVIDER` +
  `PERMISSION_PROVIDER` seams. The schema is consumer-managed (the required `Role`/
  `Permission`/`RolePermission`/`UserRole` models are documented in the README);
  `ensureSchema` is a no-op.
