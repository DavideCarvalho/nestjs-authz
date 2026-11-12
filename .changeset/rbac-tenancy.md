---
"@dudousxd/nestjs-authz-drizzle": minor
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
---

Tenancy for the RBAC modules, following the `@dudousxd/nestjs-context` tenancy switch.

- New `tenancy` option (`'inherit' | false | { enabled?, kinds?, nullRows?, roles? }`, default `'inherit'`). With context tenancy on, permission and role checks are scoped to the request's tenant from `Context.setTenant`. A request with no tenant, inside `Context.allTenants()`, or outside a request sees global assignments only. `kinds` limits the tenant kinds this module honours. With tenancy off nothing changes.
- `tenancy.roles` maps the caller's role inside the tenant (`tenant.role`) to authz roles that apply in that tenant only, e.g. `{ owner: 'org_admin' }`.
- New `tenant` resolver option, `(user) => tenantId | null | undefined`: an explicit tenant that wins over the context.
- MikroORM and Prisma can now store tenant-scoped role assignments like Drizzle and TypeORM: `assignRole`, `removeRole` and `setUserRoles` take `{ tenantId }`, and the read methods take a tenant scope. MikroORM: build the entities with `createAuthzEntitySchemas({}, { tenantScoped: true })`. Prisma: add `tenantId String @default("")` to `UserRole` and its `@@id`, then pass `tenantScoped: true`. Without that, every assignment stays global.
