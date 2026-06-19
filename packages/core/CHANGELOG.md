# @dudousxd/nestjs-authz

## 0.6.1

### Patch Changes

- [`61b6b92`](https://github.com/DavideCarvalho/nestjs-authz/commit/61b6b9241438b8f30811fcd17b0c0c98f08af3bf) - Internal refactors (behavior-preserving): single-source the ORM store contract (`UserRef`/`UserRefInput`/`UserAuthz`/`normalizeUserRef`) via a new `@dudousxd/nestjs-authz/store-kit` subpath that the typeorm/prisma/mikro-orm adapters re-export under their public names, so the definition can't drift across them. Also single-source the grant preamble and the SQL identifier guard in the core store path.

## 0.6.0

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

## 0.5.1

### Patch Changes

- [`b91713f`](https://github.com/DavideCarvalho/nestjs-authz/commit/b91713f2a7989d1630302b19feda14e381136532) - perf: memoize per-check work in the authorization path — cache the three `ModuleRef` seam resolutions (permission/context/role) so the `strict: false` container scan runs at most once per seam instead of per check, and cache `PolicyRegistry.classAbilities()` (invalidated on `register()`).

## 0.5.0

### Minor Changes

- [#6](https://github.com/DavideCarvalho/nestjs-authz/pull/6) [`abfa92d`](https://github.com/DavideCarvalho/nestjs-authz/commit/abfa92d5d647aad89a3b7f34d2bee27f6372487c) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Emit authorization decisions on the standard `aviary:authz:decision` channel via
  `@dudousxd/nestjs-diagnostics` (`emit('authz', 'decision', payload)`), instead of
  the bespoke `nestjs-authz:decision` channel. The decision payload shape
  (`AuthzDecisionDiagnostic`, `v: 1`) is unchanged — it now travels inside the
  standard envelope (`{ ts, lib, event, traceId?, payload }`), with `traceId`
  auto-filled from the optional `@dudousxd/nestjs-context` accessor when present.

  Any subscriber that records decisions should now subscribe to
  `aviary:authz:decision` and read `envelope.payload`. The generic
  `@dudousxd/nestjs-diagnostics-telescope` watcher captures these automatically — no
  authz-specific watcher needed.

  BREAKING (pre-1.0): the `AUTHZ_DECISION_CHANNEL` constant is removed (the channel
  name is now derived via `@dudousxd/nestjs-diagnostics`' `channelName('authz',
'decision')`). The dedicated `@dudousxd/nestjs-authz-telescope` package is retired
  in favor of the generic diagnostics watcher.

## 0.4.0

### Minor Changes

- [#4](https://github.com/DavideCarvalho/nestjs-authz/pull/4) [`8b7711d`](https://github.com/DavideCarvalho/nestjs-authz/commit/8b7711d11bdb25b3407fea742f6c1158afb36296) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Add `resourceLoaders` to `AuthzModule.forRoot`/`forRootAsync` options — a map keyed by
  the resource `type` name (e.g. `{ Post: (id) => postRepo.findOneBy({ id: Number(id) }) }`).
  Closes the per-instance gap in the opt-in `POST /authz/can` fallback endpoint: when a loader
  is registered for `resource.type`, the endpoint rehydrates the client's `{ type, id }` shim
  into the REAL entity before authorizing, so an instance-bound `@Policy` matches by constructor
  and its method decides correctly. A loader returning nullish is treated as "not found" (deny).
  Types without a loader keep the prior class-level / ad-hoc-only behavior. Opt-in and additive:
  unset → endpoint behavior unchanged. Also exposes a `RESOURCE_HYDRATOR` token and the
  `ResourceLoader`/`ResourceLoaderMap` types.

## 0.3.0

### Minor Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Add coarse, role-based authorization alongside the granular ability checks.

  - **`@Roles('admin', 'teacher')` + `RolesGuard`**: a route is allowed when the current
    user holds ANY of the listed roles. Registered as an `APP_GUARD` by `AuthzModule`
    (inert on un-annotated routes), it resolves the current user exactly as the `Gate`
    does and denies an unauthenticated request by default.
  - **`Gate.hasRole(role)` / `Gate.hasAnyRole(roles[])`** (and `gate.forUser(user).hasRole(...)`),
    async, resolving the user's effective roles and testing membership.
  - **Pluggable role source, two layers (unioned):**
    1. A default `RoleResolver` that reads roles off the user object — `user.roles`
       (`string[]`) OR `user.role` (`string | string[]`), normalized to a `string[]`.
       This makes role checks work with ZERO RBAC tables. Override via
       `AuthzModule.forRoot({ resolveRoles })`.
    2. An OPTIONAL `ROLE_PROVIDER` seam (`Symbol.for('@dudousxd/nestjs-authz:role-provider')`,
       consulted with `@Optional()`) — mirroring `PERMISSION_PROVIDER` — so an RBAC adapter
       can supply roles from a store. When both yield roles, the Gate unions them; when
       neither does, the check denies.

  Exports the `Roles` decorator, `RolesGuard`, `RoleResolver`, `defaultRoleResolver`,
  `ROLE_PROVIDER`, `ROLES_METADATA`, and a `RoleProvider` interface. Purely additive — the
  existing permission-provider / can-endpoint / diagnostics behavior is unchanged.

### Patch Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Add `@dudousxd/nestjs-authz-inertia`: a 3-tier Inertia integration that lets client `can(...)`
  checks resolve **without a network request** (the Laravel/Inertia model).

  - **Tier 1 — shared props (no request):** `AuthzInertiaModule` (a global interceptor that calls
    `req.inertia.share(...)`) or `createAuthzShare(gate, policyRegistry)` (a factory for
    `InertiaModule.forRoot({ share })`) resolves the current user's class-level abilities — all
    ad-hoc gates + class-level `@Policy` methods — into `props.auth.can` via direct in-process
    `gate.allows(...)` calls.
  - **Tier 2 — per-resource map (no request):** `authorizeResource(gate, instance, abilities)`
    returns a `{ update, delete }` map a controller attaches to a serialized resource.
  - **Tier 3 — fallback endpoint (last resort):** consumes core's opt-in `POST /authz/can`.
  - **Framework-neutral client** (`@dudousxd/nestjs-authz-inertia/client`): an `AbilityStore`,
    `hydrateFromInertiaProps` / `hydrateResource`, and a `createCan` resolver that reads hydrated
    decisions synchronously (no fetch on a cache hit) and only falls back (fetch the endpoint, or
    deny) when the ability/resource is unknown.
  - **Denial filter (`AuthzDenialFilter`):** `AuthzInertiaModule.forRoot` also registers a global
    `APP_FILTER` that converts `@Roles`/`@Can` denials (`ForbiddenException`) into a friendly 303
    redirect on Inertia requests (`X-Inertia` header) — `/login` when unauthenticated, `/403` when
    authenticated-but-forbidden (auth-state read from the optional `CONTEXT_ACCESSOR`). Non-Inertia
    (REST) requests are rethrown and keep the normal 403 JSON. Configurable via
    `forRoot({ denial: { loginUrl, forbiddenUrl, enabled, handler } })` (`enabled: false` opts out;
    `handler(exception, host)` is a full escape hatch). Targets pass the same open-redirect guard
    nestjs-inertia uses, falling back to a safe default if unsafe.

  `@dudousxd/nestjs-authz` (patch): add an opt-in `POST /authz/can` fallback controller behind
  `AuthzModule.forRoot({ canEndpoint: true })` (default off; accepts a custom path string). It runs
  `gate.allows(ability, resource?)` for the current context user and returns `{ allowed }`, failing
  closed for unresolved abilities. Also exposes `Gate.gateNames()` and `PolicyRegistry.classAbilities()`
  so integrations can enumerate a user's class-level abilities.

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Add `@dudousxd/nestjs-authz-telescope`: a `@dudousxd/nestjs-telescope` extension that records every
  authorization decision the `Gate` reaches (ability, allow/deny, the reason it was decided, the user
  and the resource) as an `authorization` Telescope entry plus an "Authorization" dashboard page (a
  top-N of denied abilities and a table of recent decisions) — so a 403 is debuggable. The extension's
  `AuthorizationWatcher` subscribes to the new `nestjs-authz:decision` diagnostics channel; nothing is
  emitted (and nothing recorded) when no observer is listening.

  The core `Gate` now publishes each decision on a dependency-free `node:diagnostics_channel`
  (`nestjs-authz:decision`, exported as `AUTHZ_DECISION_CHANNEL`) after a verdict is reached. The
  emission is gated on `channel.hasSubscribers` and fully guarded, so it is zero-overhead with no
  subscriber and can never affect a check. No existing behavior changes.

## 0.2.0

### Minor Changes

- [`51d2fbc`](https://github.com/DavideCarvalho/nestjs-authz/commit/51d2fbc6b966c101a6ff0675c42843f040e02703) - Initial release: Laravel-style authorization for NestJS — gates, `@Policy`/`@Can`, the `Gate` service, a default `:id` resource resolver, `before`/`superAdmin` hooks, optional `nestjs-context` current-user with `resolveUser` hydration, and a `PERMISSION_PROVIDER` seam. The `@dudousxd/nestjs-authz-typeorm` adapter adds opt-in RBAC persistence (roles/permissions store, dialect-correct SQL, identifier allowlist, non-destructive schema auto-manage).
