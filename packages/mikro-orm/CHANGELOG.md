# @dudousxd/nestjs-authz-mikro-orm

## 0.5.1

### Patch Changes

- [`f079152`](https://github.com/DavideCarvalho/nestjs-authz/commit/f079152627ed223e87fa5b701d0c6917aaa34d9d) - Support NestJS 12.

  The `@nestjs/common` / `@nestjs/core` peer ranges are already `>=10.0.0`, so they
  admit 12 unchanged. The dev/test matrix now runs on `@nestjs/*@12.0.1` (and the
  MikroORM 7 integration app with it), so v12 is covered by CI rather than merely
  allowed by the range. No source changes were needed.

## 0.5.0

### Minor Changes

- [#18](https://github.com/DavideCarvalho/nestjs-authz/pull/18) [`a5662a2`](https://github.com/DavideCarvalho/nestjs-authz/commit/a5662a2b599d826ae3a0d08e6ad71da7f2e425dc) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Ship typed MikroORM repositories for the four authz entities, and a schema factory for custom table names.

  - New `AuthzRoleRepository`, `AuthzPermissionRepository`, `AuthzRolePermissionRepository` and `AuthzUserRoleRepository` (empty `EntityRepository` subclasses), bound to the entities via `repository: () => ...` on each `EntitySchema` plus an `[EntityRepositoryType]` marker on each entity class. `em.getRepository(RoleEntity)` now returns — and is typed as — `AuthzRoleRepository`, and `MikroOrmModule.forFeature([...AUTHZ_ENTITY_CLASSES])` registers each repository class as its own DI token, so host apps inject by type instead of threading the entity class through every `em.find(RoleEntity, ...)`.
  - New `createAuthzEntitySchemas(tableNames?)` — the supported way to relocate the authz tables. It carries the repository binding and derives the index names from the given table names; hand-writing a replacement `EntitySchema` (the previously documented path) silently dropped both. `AUTHZ_ENTITIES` and `RoleEntitySchema` … `UserRoleEntitySchema` are now produced by this factory with the default names, so they are unchanged.
  - New `AUTHZ_ENTITY_CLASSES` export (the four classes in dependency order) for `MikroOrmModule.forFeature()`, which matches on `meta.class`.
  - `ensureAuthzSchema` / `authzSchemaSql` now read the four physical table names off the live metadata instead of hard-coding the `authz_*` literals, so relocated tables are created too.

  `EntityRepository`, `EntityRepositoryType` and the `repository` option on `EntitySchemaMetadata` all live in `@mikro-orm/core` on both MikroORM 6 and 7, so this adds no peer and no decorator import. Verified against the v6 suite and the pinned `@mikro-orm/core@7` integration suite.

  `MikroOrmAuthzStore` is unchanged.

## 0.4.0

### Minor Changes

- [`45719bb`](https://github.com/DavideCarvalho/nestjs-authz/commit/45719bb958d7abceb8b0edad4c0c3d97f99590cb) - Support MikroORM 7 (peer `@mikro-orm/core` / `@mikro-orm/nestjs` widened to `^6 || ^7`).

  MikroORM 7 relocated the entity decorators (`@Entity/@Property/@PrimaryKey/@Index`) out of `@mikro-orm/core` into a separate `@mikro-orm/decorators` package, and removed `MikroORM.getSchemaGenerator()`. To run on both v6 and v7 from a single codebase with no extra peer:

  - The four authz entities are now defined with `EntitySchema` (the one definition style that lives in `@mikro-orm/core` on both majors) instead of decorators. The entity classes (`RoleEntity` … `UserRoleEntity`) are unchanged as the store's reference; their schemas are also exported (`RoleEntitySchema` … `UserRoleEntitySchema`) for BYO-table-name re-declaration.
  - `ensureAuthzSchema` / `authzSchemaSql` now detect a `MikroORM` instance via its `em` property (present on both v6 and v7) instead of the v7-removed `getSchemaGenerator()`, and read the schema generator off the EM-bound platform.

  Verified end-to-end against `@mikro-orm/core@7` + `@mikro-orm/sqlite@7` (and the existing v6 suite still passes).

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

## 0.2.0

### Minor Changes

- [#4](https://github.com/DavideCarvalho/nestjs-authz/pull/4) [`8b7711d`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b7711d11bdb25b3407fea742f6c1158afb36296) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - New package: `@dudousxd/nestjs-authz-mikro-orm` — a MikroORM RBAC persistence adapter
  mirroring `@dudousxd/nestjs-authz-typeorm`. Ships Role/Permission/RolePermission/UserRole
  entities (user referenced by id only), a `MikroOrmAuthzStore` POJO with the same method
  surface, `AuthzRbacModule.forRoot/forRootAsync` registering the core `ROLE_PROVIDER` +
  `PERMISSION_PROVIDER` seams, and non-destructive `ensureAuthzSchema` (native
  `updateSchema({ safe: true })`) with an `authzSchemaSql` migration helper. `autoCreateSchema`
  defaults to true.
