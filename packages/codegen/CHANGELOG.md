# @dudousxd/nestjs-authz-codegen

## 2.0.0

### Major Changes

- [#74](https://github.com/DavideCarvalho/nestjs-authz/pull/74) [`35421dc`](https://github.com/DavideCarvalho/nestjs-authz/commit/35421dc5b09bd271d5087d26e8536191ef6ba342) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - **Breaking:** require Node.js 24 or newer (`engines.node` is now `>=24`; it was `>=22`, and `>=20` for `-client` and `-react`). CI tests on Node 24 and 26. No API changes: see the Upgrading page in the docs.

## 1.0.0

### Patch Changes

- Updated dependencies [[`750a6b3`](https://github.com/DavideCarvalho/nestjs-authz/commit/750a6b3f80deea3803dec8df5f9f8cf67a046ac1)]:
  - @dudousxd/nestjs-authz@0.10.0

## 0.3.1

### Patch Changes

- [#70](https://github.com/DavideCarvalho/nestjs-authz/pull/70) [`416f0bd`](https://github.com/DavideCarvalho/nestjs-authz/commit/416f0bd7d9340f6f3314017d4925cb89834c4342) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - README fixes: the codegen README no longer describes the removed `PostPolicy` → `Post` name guess and lists `@PolicyFor` among the names that must not be aliased; the core README covers the dropped `DecisionProvider` deny message and the expected boot error under `unannotated: 'allow'`.

## 0.3.0

### Minor Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Abilities of a policy without a `@PolicyFor(Resource)` link are now emitted model-less instead of
  under a resource guessed from the class name (`InvoicePolicy` → `Invoice`). The `Gate` (and the
  `can()` endpoint) resolves a string ability on a resource only through that link, so the guessed
  keys could never resolve. Add `@PolicyFor(Invoice)` to keep the resource key.

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Type client abilities from the official `@Can(Policy, 'ability', byId(Resource))`,
  `@Permission` / `PermissionPolicy` permission names, `GatePolicy` abilities and
  `@Policy()` / `@PolicyFor()` classes (skipping `before` and `scope`). The 0.8 string
  `@Can('update', Post)` and `@Policy(Post)` are no longer read; a policy's resource comes from
  `@PolicyFor(Resource)` (else its name). Peers on `@dudousxd/nestjs-authz` `>=0.9.0 <0.10.0`.

### Patch Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix packages that could be published without files their `exports` point to. `tsc` builds no longer use a `.tsbuildinfo` that can outlive `dist/` and skip emitting files. A new `check:exports` step (also `prepack`) fails the release if any `exports`/`main`/`types` path is missing.

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

## 0.1.0

### Minor Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Initial release of `@dudousxd/nestjs-authz-codegen`: a `@dudousxd/nestjs-codegen` extension that
  discovers `@Can(ability, Resource?)` decorators on your controllers (and, optionally, `@Policy`
  method abilities) and emits a typed `can()` helper into your generated `api.ts`. The discovered
  abilities become a string-literal `AuthzAbility` union, so calling `can()` with an ability that
  doesn't exist on the server is a compile-time error. Routes carrying a `@Can` also expose a
  route-pinned `can()` handle member when a client layer is active.

### Patch Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - The emitted `can()` now delegates to `@dudousxd/nestjs-authz-client` instead of a
  hand-rolled POST. The generated `api.ts` imports `AbilityStore` + `createCan`, exports a
  shared `authzStore` you hydrate once, and `can()` is a thin typed wrapper over the store's
  `createCan` resolver — so a hydrated decision is answered synchronously with NO request,
  and a cache miss uses the same configurable `'fetch'` fallback to the `endpoint`. The
  compile-time `AuthzAbility` string-literal union is unchanged (a wrong ability is still a
  type error). Adds `@dudousxd/nestjs-authz-client` as an optional peer dependency.
