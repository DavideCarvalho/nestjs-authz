# @dudousxd/nestjs-authz-drizzle

## 1.1.0

### Minor Changes

- [#72](https://github.com/DavideCarvalho/nestjs-authz/pull/72) [`58a5d72`](https://github.com/DavideCarvalho/nestjs-authz/commit/58a5d72d2964a7cfae9cbfe8506526c8518ba30a) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Tenancy for the RBAC modules, following the `@dudousxd/nestjs-context` tenancy switch.

  - New `tenancy` option (`'inherit' | false | { enabled?, kinds?, nullRows?, roles? }`, default `'inherit'`). With context tenancy on, permission and role checks are scoped to the request's tenant from `Context.setTenant`. A request with no tenant, inside `Context.allTenants()`, or outside a request sees global assignments only. `kinds` limits the tenant kinds this module honours. With tenancy off nothing changes.
  - `tenancy.roles` maps the caller's role inside the tenant (`tenant.role`) to authz roles that apply in that tenant only, e.g. `{ owner: 'org_admin' }`.
  - New `tenant` resolver option, `(user) => tenantId | null | undefined`: an explicit tenant that wins over the context.
  - MikroORM and Prisma can now store tenant-scoped role assignments like Drizzle and TypeORM: `assignRole`, `removeRole` and `setUserRoles` take `{ tenantId }`, and the read methods take a tenant scope. MikroORM: build the entities with `createAuthzEntitySchemas({}, { tenantScoped: true })`. Prisma: add `tenantId String @default("")` to `UserRole` and its `@@id`, then pass `tenantScoped: true`. Without that, every assignment stays global.

## 1.0.0

### Patch Changes

- Updated dependencies [[`750a6b3`](https://github.com/DavideCarvalho/nestjs-authz/commit/750a6b3f80deea3803dec8df5f9f8cf67a046ac1)]:
  - @dudousxd/nestjs-authz@0.10.0

## 0.3.0

### Minor Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Run on `@dudousxd/nestjs-authz` 0.9 and `@nestjs/authorization`: persisted roles and
  permissions now guard routes through the official guard as the core's `RolePolicy` /
  `PermissionPolicy` (`@Roles('editor')`, `@Permission('posts.publish')`), and the guard and the
  handler's `Gate` calls share one permission and role fetch per request. The store API
  (role sources, admin management, tenant-scoped roles where supported) and `AuthzRbacModule`
  are unchanged. A persisted permission named like a policy ability no longer bypasses that
  policy (see the core changeset). Requires NestJS 12, `@nestjs/authorization` ^0.1.3 and Node 22+.

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - `AuthzRbacModule.forRoot({ connectionName, storeOptions })` (and `forRootAsync({ connectionName, storeOptions, useFactory })`) builds the store from a connection registered with NestJS's `@nestjs/drizzle` / `@nestjs/typeorm`, injecting `getDrizzleToken(connectionName)` / `getDataSourceToken(connectionName)` (`'default'` for the default connection). Both are optional peers. Passing a `store` you built yourself works as before. `AuthzRbacModuleOptions` is now a union of the two forms, and `AuthzRbacModuleAsyncOptions` takes `connectionName` next to `useFactory`.

### Patch Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix packages that could be published without files their `exports` point to. `tsc` builds no longer use a `.tsbuildinfo` that can outlive `dist/` and skip emitting files. A new `check:exports` step (also `prepack`) fails the release if any `exports`/`main`/`types` path is missing.

## 0.2.1

### Patch Changes

- [#66](https://github.com/DavideCarvalho/nestjs-authz/pull/66) [`d5fdd23`](https://github.com/DavideCarvalho/nestjs-authz/commit/d5fdd23a2b72ae61fae0f913f11164bc4d2df77b) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Authorization checks within one request no longer hit the database per check. The Gate memoizes `resolveUser`, the permission set and the provider roles on the request context (keyed by the row a user names, its class or `type` plus `id`, so ORMs without an identity map share entries; a plain object without `type` is keyed by identity, so two users that only share an `id` never share an entry), and compiles the granted set once so a check is a hash lookup plus a scan of the wildcard grants. Providers can set the optional `exhaustivePermissions` flag to say `getPermissions` lists everything `hasPermission` grants; the ORM adapters do, and the MikroORM and Prisma providers now expose `getPermissions` (so persisted wildcard grants such as `posts.*` match there too). Grants changed mid-request apply from the next request.

## 0.2.0

### Minor Changes

- [#61](https://github.com/DavideCarvalho/nestjs-authz/pull/61) [`d1c719d`](https://github.com/DavideCarvalho/nestjs-authz/commit/d1c719d9ee973bc802ba8bf6854246875c4c2da9) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Admin management operations on every RBAC store adapter (TypeORM, MikroORM, Prisma, Drizzle), with the same semantics everywhere:

  - `deleteRole(roleName): Promise<boolean>` deletes the role, its role→permission links and every user assignment of it (all tenants, all sources) in one transaction. Returns whether the role existed. Permissions are kept.
  - `syncRolePermissions(roleName, permissionNames): Promise<void>` replaces the role's permission set with exactly these names (spatie's `syncPermissions`), creating the role and permissions by name when missing.
  - `getRolePermissions(roleNames): Promise<Record<string, string[]>>` returns each role's sorted permission names without N+1 queries. Every existing requested role is a key, even with no permissions (`[]`). Roles that don't exist are absent.
  - `listRoleAssignments(filter?): Promise<UserRoleAssignment[]>` returns raw `{ userType, userId, role, source, tenantId }` rows for admin listings, ordered by `(userType, userId, role, source, tenantId)`. Filters: `role` (a name or a list), `user`, `source`, and `tenantId`. Omitting `tenantId` applies no tenant filter, `null` returns global assignments only, and a string returns only that tenant's scoped assignments, without the global ones. MikroORM and Prisma have no tenant-scoped assignments, so there a tenant id string matches nothing.
  - `removeUser(user): Promise<void>` deletes every role assignment of the user (all tenants, all sources) and, on TypeORM and Drizzle, every direct permission.

  Core's `store-kit` exports the `RoleAssignmentFilter` and `UserRoleAssignment` types, plus the `roleFilterNames` and `compareUserRoleAssignments` helpers the adapters share. The adapters now require `@dudousxd/nestjs-authz >= 0.8.0`.

## 0.1.1

### Patch Changes

- [#59](https://github.com/DavideCarvalho/nestjs-authz/pull/59) [`a4ef88b`](https://github.com/DavideCarvalho/nestjs-authz/commit/a4ef88bb6e4b3a5381815816cf1530ee2114f3cd) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Republish from CI through npm trusted publishing (OIDC) so the release carries a provenance attestation; 0.1.0 was a one-time manual first publish.

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
