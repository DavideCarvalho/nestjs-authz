# @dudousxd/nestjs-authz-drizzle

## 0.1.0

### Minor Changes

- [#55](https://github.com/DavideCarvalho/nestjs-authz/pull/55) [`7b040d8`](https://github.com/DavideCarvalho/nestjs-authz/commit/7b040d8bf187d630726b16031ff7c6fa14d95f5b) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - New package: `@dudousxd/nestjs-authz-drizzle` — the Drizzle ORM (Postgres) sibling of the typeorm/mikro-orm/prisma adapters.

  - `compileScope(constraint, tableOrColumns)` / `applyScope(gate, Entity, table)` compile `gate.scope()` into a Drizzle `SQL` WHERE (fields resolved against the table's columns or an explicit allowlist map; values always bound; `allow-all` → `undefined`, `deny-all` → `1 = 0`).
  - `DrizzleAuthzStore` — the same store surface as the TypeORM adapter (idempotent role/permission upserts, tenant-scoped role assignments, direct user permissions, `getUserAuthz`), over the canonical `authz_*` tables, plus `withDb(tx)` for caller transactions.
  - `createAuthzTables({ tableNames, schema })` returns the tables as `pgTable`s to spread into your drizzle-kit schema; `ensureSchema()` / `authzSchemaDdl()` for non-drizzle-kit setups.
  - `AuthzRbacModule` registers the `PERMISSION_PROVIDER` (with wildcard `getPermissions`) and `ROLE_PROVIDER` seams, tenant-aware via nestjs-context.

- [#58](https://github.com/DavideCarvalho/nestjs-authz/pull/58) [`8b65088`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b6508804216d46384ec3a734a55b9c0ac1e48b6) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Per-source role assignments (manual vs SSO/SCIM/…).

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
