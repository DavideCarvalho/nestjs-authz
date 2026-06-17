---
"@dudousxd/nestjs-authz-prisma": minor
---

New package: `@dudousxd/nestjs-authz-prisma` — a Prisma RBAC persistence adapter mirroring
`@dudousxd/nestjs-authz-typeorm`. Exposes a `PRISMA_CLIENT` DI token plus a minimal
**structural** `PrismaAuthzClientLike` interface (no `@prisma/client` import / no
`prisma generate` step), a `PrismaAuthzStore` with the same method surface, and
`AuthzRbacModule.forRoot/forRootAsync` registering the core `ROLE_PROVIDER` +
`PERMISSION_PROVIDER` seams. The schema is consumer-managed (the required `Role`/
`Permission`/`RolePermission`/`UserRole` models are documented in the README);
`ensureSchema` is a no-op.
