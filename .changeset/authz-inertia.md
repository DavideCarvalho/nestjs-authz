---
"@dudousxd/nestjs-authz-inertia": minor
"@dudousxd/nestjs-authz": patch
---

Add `@dudousxd/nestjs-authz-inertia`: a 3-tier Inertia integration that lets client `can(...)`
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
