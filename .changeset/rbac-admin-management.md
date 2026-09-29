---
'@dudousxd/nestjs-authz': minor
'@dudousxd/nestjs-authz-typeorm': minor
'@dudousxd/nestjs-authz-mikro-orm': minor
'@dudousxd/nestjs-authz-prisma': minor
'@dudousxd/nestjs-authz-drizzle': minor
---

Admin management operations on every RBAC store adapter (TypeORM, MikroORM, Prisma, Drizzle), with the same semantics everywhere:

- `deleteRole(roleName): Promise<boolean>` deletes the role, its role→permission links and every user assignment of it (all tenants, all sources) in one transaction. Returns whether the role existed. Permissions are kept.
- `syncRolePermissions(roleName, permissionNames): Promise<void>` replaces the role's permission set with exactly these names (spatie's `syncPermissions`), creating the role and permissions by name when missing.
- `getRolePermissions(roleNames): Promise<Record<string, string[]>>` returns each role's sorted permission names without N+1 queries. Every existing requested role is a key, even with no permissions (`[]`). Roles that don't exist are absent.
- `listRoleAssignments(filter?): Promise<UserRoleAssignment[]>` returns raw `{ userType, userId, role, source, tenantId }` rows for admin listings, ordered by `(userType, userId, role, source, tenantId)`. Filters: `role` (a name or a list), `user`, `source`, and `tenantId`. Omitting `tenantId` applies no tenant filter, `null` returns global assignments only, and a string returns only that tenant's scoped assignments, without the global ones. MikroORM and Prisma have no tenant-scoped assignments, so there a tenant id string matches nothing.
- `removeUser(user): Promise<void>` deletes every role assignment of the user (all tenants, all sources) and, on TypeORM and Drizzle, every direct permission.

Core's `store-kit` exports the `RoleAssignmentFilter` and `UserRoleAssignment` types, plus the `roleFilterNames` and `compareUserRoleAssignments` helpers the adapters share. The adapters now require `@dudousxd/nestjs-authz >= 0.8.0`.
