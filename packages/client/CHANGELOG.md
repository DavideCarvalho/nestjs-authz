# @dudousxd/nestjs-authz-client

## 0.2.1

### Patch Changes

- [#15](https://github.com/DavideCarvalho/nestjs-authz/pull/15) [`7294ff5`](https://github.com/DavideCarvalho/nestjs-authz/commit/7294ff5c01454d9fea6d42a6c3f80eff2f00dc48) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix the exported `VERSION` const shipping as `'0.0.0'`.

  The build is plain `tsc` with no version injection, and `changeset version` only bumps `package.json` — leaving the `export const VERSION` in `src/index.ts` stale, so the published dist reported `'0.0.0'`. The const is now corrected to match each package's `package.json`, and a new `scripts/sync-version.mjs` (chained into the `version-packages` script) re-syncs it on every release bump to prevent future drift. Run with `--check` to fail a build on mismatch.

## 0.2.0

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

## 0.1.1

### Patch Changes

- [#4](https://github.com/DavideCarvalho/nestjs-authz/pull/4) [`8b7711d`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b7711d11bdb25b3407fea742f6c1158afb36296) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Soften the resource-bound fetch-fallback `console.warn` and docstrings: a per-instance
  `can(ability, { type, id })` cache miss under `fallback: 'fetch'` now resolves on the server
  when the app registered a matching `resourceLoaders` entry for that `type` (core feature) —
  it only denies when neither tier-1/2 hydration nor a loader covers it.

## 0.1.0

### Minor Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Extract the framework-neutral ability store into a new `@dudousxd/nestjs-authz-client`
  package and add a `@dudousxd/nestjs-authz-react` package.

  - **`@dudousxd/nestjs-authz-client`** (new): the canonical home for the in-memory
    `AbilityStore`, `createCan` (synchronous cache hit; configurable `fallback: 'deny' | 'fetch'`
    to `POST /authz/can` on a miss), and `hydrateFromInertiaProps` / `hydrateResource`. Pure
    TypeScript plus an injectable `fetch` — no React/Vue/NestJS/Inertia dependency.
  - **`@dudousxd/nestjs-authz-react`** (new): `AuthzProvider` (holds a hydrated `AbilityStore`),
    `useCan(ability, resource?)` (returns `{ allowed, loading }`, synchronous and request-free on a
    cache hit; honors the store's fallback on a miss), and `<Can ability of fallback>`. A missing
    provider fails closed (deny).
  - **`@dudousxd/nestjs-authz-inertia`** (patch): now depends on `@dudousxd/nestjs-authz-client` and
    re-exports its store instead of carrying a private copy. The
    `@dudousxd/nestjs-authz-inertia/client` entry point is unchanged for consumers.
