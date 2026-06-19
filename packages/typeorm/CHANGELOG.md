# @dudousxd/nestjs-authz-typeorm

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
