# @dudousxd/nestjs-authz-inertia

## 0.1.0

### Minor Changes

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

### Patch Changes

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

- Updated dependencies [[`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7)]:
  - @dudousxd/nestjs-authz-client@0.1.0
