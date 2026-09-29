# @dudousxd/nestjs-authz-typeorm

## 0.5.0

### Minor Changes

- [#61](https://github.com/DavideCarvalho/nestjs-authz/pull/61) [`d1c719d`](https://github.com/DavideCarvalho/nestjs-authz/commit/d1c719d9ee973bc802ba8bf6854246875c4c2da9) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Admin management operations on every RBAC store adapter (TypeORM, MikroORM, Prisma, Drizzle), with the same semantics everywhere:

  - `deleteRole(roleName): Promise<boolean>` deletes the role, its role→permission links and every user assignment of it (all tenants, all sources) in one transaction. Returns whether the role existed. Permissions are kept.
  - `syncRolePermissions(roleName, permissionNames): Promise<void>` replaces the role's permission set with exactly these names (spatie's `syncPermissions`), creating the role and permissions by name when missing.
  - `getRolePermissions(roleNames): Promise<Record<string, string[]>>` returns each role's sorted permission names without N+1 queries. Every existing requested role is a key, even with no permissions (`[]`). Roles that don't exist are absent.
  - `listRoleAssignments(filter?): Promise<UserRoleAssignment[]>` returns raw `{ userType, userId, role, source, tenantId }` rows for admin listings, ordered by `(userType, userId, role, source, tenantId)`. Filters: `role` (a name or a list), `user`, `source`, and `tenantId`. Omitting `tenantId` applies no tenant filter, `null` returns global assignments only, and a string returns only that tenant's scoped assignments, without the global ones. MikroORM and Prisma have no tenant-scoped assignments, so there a tenant id string matches nothing.
  - `removeUser(user): Promise<void>` deletes every role assignment of the user (all tenants, all sources) and, on TypeORM and Drizzle, every direct permission.

  Core's `store-kit` exports the `RoleAssignmentFilter` and `UserRoleAssignment` types, plus the `roleFilterNames` and `compareUserRoleAssignments` helpers the adapters share. The adapters now require `@dudousxd/nestjs-authz >= 0.8.0`.

## 0.4.0

### Minor Changes

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

## 0.3.2

### Patch Changes

- [`f079152`](https://github.com/DavideCarvalho/nestjs-authz/commit/f079152627ed223e87fa5b701d0c6917aaa34d9d) - Support NestJS 12.

  The `@nestjs/common` / `@nestjs/core` peer ranges are already `>=10.0.0`, so they
  admit 12 unchanged. The dev/test matrix now runs on `@nestjs/*@12.0.1` (and the
  MikroORM 7 integration app with it), so v12 is covered by CI rather than merely
  allowed by the range. No source changes were needed.

## 0.3.1

### Patch Changes

- [`61b6b92`](https://github.com/DavideCarvalho/nestjs-authz/commit/61b6b9241438b8f30811fcd17b0c0c98f08af3bf) - Internal refactors (behavior-preserving): single-source the ORM store contract (`UserRef`/`UserRefInput`/`UserAuthz`/`normalizeUserRef`) via a new `@dudousxd/nestjs-authz/store-kit` subpath that the typeorm/prisma/mikro-orm adapters re-export under their public names, so the definition can't drift across them. Also single-source the grant preamble and the SQL identifier guard in the core store path.

## 0.3.0

### Minor Changes

- [#9](https://github.com/DavideCarvalho/nestjs-authz/pull/9) [`07d01de`](https://github.com/DavideCarvalho/nestjs-authz/commit/07d01de286e7dfcae5fbeb10b7e8d48533214087) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Ecosystem improvements across the authz packages.

  ### Permissions

  - **Wildcard / hierarchical permissions.** Permission strings now support wildcard
    and hierarchical matching (e.g. `posts:*` or `posts:read:*`), so a single granted
    permission can authorize a family of related actions instead of enumerating each one.

  ### Authorization decisions

  - **Deny reason / message surfaced on `ForbiddenException`.** When a check fails, the
    reason for the denial is propagated onto the thrown `ForbiddenException`, making it
    possible to return a meaningful message to the caller and to debug authorization
    failures.
  - **Gate `after` hook.** The Gate now exposes an `after` hook that runs once a decision
    has been made, enabling cross-cutting concerns such as auditing, logging, and metrics.

  ### Batch authorization

  - **`allowsMany`** for evaluating multiple permission checks in a single call.
  - **Batch `/authz/can` endpoint** so clients can resolve many checks in one round trip.
  - **`createCanBatch`** client helper that batches `can` calls transparently.

  ### Performance

  - **Request-scoped permission cache.** Permissions resolved during a request are cached
    for the lifetime of that request, avoiding repeated lookups on the hot path.

  ### RBAC adapters (TypeORM)

  - **Direct user permissions** granted to a user independent of their roles.
  - **Tenant-scoped roles** so the same role can be assigned per tenant in multi-tenant
    deployments.

  ### Query scoping / policy filter (ABAC)

  - **ORM-neutral constraint AST.** Policies can produce a portable constraint
    representation describing which rows a subject may access.
  - **Per-ORM application.** The constraint AST is translated and applied for
    **TypeORM**, **MikroORM**, and **Prisma**, giving ABAC-style query scoping that
    filters data at the database layer regardless of the ORM in use.

  ### Testing

  - **New `@dudousxd/nestjs-authz-testing` package** with fakes and helpers for testing
    authorization in consumer applications.
  - **Postgres / MySQL testcontainers + contract tests** so the ORM stores are verified
    against real database engines, and a shared contract suite keeps the adapters
    behaviorally consistent.

  ### Housekeeping

  - **Packaging hygiene** across the published packages.

## 0.2.1

### Patch Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - `AuthzRbacModule` now registers a `RoleProvider` under the core `ROLE_PROVIDER` token
  that returns `store.getRolesForUser(...)`, so coarse role checks (`gate.hasRole('teacher')`,
  `@Roles('admin')`) consult the persisted RBAC store too — mirroring the existing
  `PERMISSION_PROVIDER` wiring. Roles from the store are unioned with any read off the user
  object by core's default resolver.

## 0.2.0

### Minor Changes

- [`51d2fbc`](https://github.com/DavideCarvalho/nestjs-authz/commit/51d2fbc6b966c101a6ff0675c42843f040e02703) - Initial release: Laravel-style authorization for NestJS — gates, `@Policy`/`@Can`, the `Gate` service, a default `:id` resource resolver, `before`/`superAdmin` hooks, optional `nestjs-context` current-user with `resolveUser` hydration, and a `PERMISSION_PROVIDER` seam. The `@dudousxd/nestjs-authz-typeorm` adapter adds opt-in RBAC persistence (roles/permissions store, dialect-correct SQL, identifier allowlist, non-destructive schema auto-manage).
