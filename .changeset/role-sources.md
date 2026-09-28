---
'@dudousxd/nestjs-authz': minor
'@dudousxd/nestjs-authz-typeorm': minor
'@dudousxd/nestjs-authz-mikro-orm': minor
'@dudousxd/nestjs-authz-prisma': minor
'@dudousxd/nestjs-authz-drizzle': minor
---

Per-source role assignments (manual vs SSO/SCIM/…).

Each role assignment now records a `source`, default `'manual'`. Every store adapter gains:

- `setUserRoles(user, roleNames, { source?, tenantId? })` replaces only that source's assignments, so an SSO sync never removes a role that was granted by hand. It creates missing roles and runs in a transaction.
- `assignRole(user, role, { source })` and `removeRole(user, role, { source })`. Without `source`, `removeRole` removes the role from every source.
- `getRoleAssignments(user, scope?)` returns `{ role, source, tenantId }[]`.
- `getRolesForUser` and the Gate seams still return distinct role names.

Core's `store-kit` exports `DEFAULT_ROLE_SOURCE` and `RoleAssignment`. The adapters now require `@dudousxd/nestjs-authz >= 0.7.0`.

**Migration**

- **TypeORM:** `ensureAuthzSchema` / `autoCreateSchema` adds `source varchar(64) NOT NULL DEFAULT 'manual'` to `authz_user_role`, so existing rows become manual assignments. It never rewrites an existing primary key. Until you widen the key, a role can come from only one source per user, and a second-source insert is silently ignored. Widen it once:
  - PostgreSQL: `ALTER TABLE authz_user_role DROP CONSTRAINT <pk_name>, ADD PRIMARY KEY ("userType","userId","roleId","tenantId","source");`
  - MySQL (utf8mb4 needs the shorter key columns): `ALTER TABLE authz_user_role MODIFY roleId varchar(64) NOT NULL, MODIFY source varchar(64) NOT NULL DEFAULT 'manual', DROP PRIMARY KEY, ADD PRIMARY KEY (userType, userId, roleId, tenantId, source);`
  - SQLite: rebuild the table.

  New tables are created with the 5-column key, and `roleId` is now `varchar(64)` so the key fits MySQL's 3072-byte limit.
- **MikroORM:** the column self-heals the same way. The PK does not. See the adapter README for the SQL.
- **Prisma:** opt-in with `roleSources: true` after adding `source String @default("manual")` to `UserRole` and including it in `@@id`. See the adapter README. Without the option the adapter behaves exactly as before.
- **Drizzle:** `createAuthzTables()` now includes the column and the widened key, so regenerate with drizzle-kit. `ensureSchema()` adds the column. See the README for the key SQL.
