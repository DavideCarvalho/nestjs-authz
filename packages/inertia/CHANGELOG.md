# @dudousxd/nestjs-authz-inertia

## 0.3.0

### Minor Changes

- Back on the 0.x line. The 1.x and 2.x versions were published by accident: a release-tooling peer cascade bumped this package to a major, not an API decision. 0.3.0 contains everything those versions shipped (console `authorize` support, tenancy, Node 24+ `engines`) with no other change. Upgrade from 1.x/2.x to 0.3.0; those versions are deprecated.

## 2.0.0

### Major Changes

- [#74](https://github.com/DavideCarvalho/nestjs-authz/pull/74) [`35421dc`](https://github.com/DavideCarvalho/nestjs-authz/commit/35421dc5b09bd271d5087d26e8536191ef6ba342) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - **Breaking:** require Node.js 24 or newer (`engines.node` is now `>=24`; it was `>=22`, and `>=20` for `-client` and `-react`). CI tests on Node 24 and 26. No API changes: see the Upgrading page in the docs.

### Patch Changes

- Updated dependencies [[`35421dc`](https://github.com/DavideCarvalho/nestjs-authz/commit/35421dc5b09bd271d5087d26e8536191ef6ba342)]:
  - @dudousxd/nestjs-authz-client@0.3.0

## 1.0.0

### Patch Changes

- Updated dependencies [[`750a6b3`](https://github.com/DavideCarvalho/nestjs-authz/commit/750a6b3f80deea3803dec8df5f9f8cf67a046ac1)]:
  - @dudousxd/nestjs-authz@0.10.0

## 0.2.0

### Minor Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Share the class-level abilities of every official `@Policy()` (linked with `@PolicyFor` or not,
  keyed `<resource>.<method>`), checked through the official `AuthorizationService` for the user
  the official guard reads. `resolveClassAbilities` / `createAuthzShare` take a `PolicyIndex`
  (was `PolicyRegistry`) and accept `gate.forUser(user)`. The denial filter also redirects the
  official guard's 401 to `loginUrl`; without nestjs-context a 403 now goes to `forbiddenUrl`.
  Requires `@dudousxd/nestjs-authz` 0.9, NestJS 12 and Node 22+.

  **Removed:** the `@dudousxd/nestjs-authz-inertia/client` subpath, which only re-exported the
  client package. Import `AbilityStore`, `createCan`, `hydrateFromInertiaProps` and
  `hydrateResource` from `@dudousxd/nestjs-authz-client` directly.

### Patch Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix packages that could be published without files their `exports` point to. `tsc` builds no longer use a `.tsbuildinfo` that can outlive `dist/` and skip emitting files. A new `check:exports` step (also `prepack`) fails the release if any `exports`/`main`/`types` path is missing.

- Updated dependencies [[`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918)]:
  - @dudousxd/nestjs-authz-client@0.2.2

## 0.1.3

### Patch Changes

- [`f079152`](https://github.com/DavideCarvalho/nestjs-authz/commit/f079152627ed223e87fa5b701d0c6917aaa34d9d) - Support NestJS 12.

  The `@nestjs/common` / `@nestjs/core` peer ranges are already `>=10.0.0`, so they
  admit 12 unchanged. The dev/test matrix now runs on `@nestjs/*@12.0.1` (and the
  MikroORM 7 integration app with it), so v12 is covered by CI rather than merely
  allowed by the range. No source changes were needed.

## 0.1.2

### Patch Changes

- [#15](https://github.com/DavideCarvalho/nestjs-authz/pull/15) [`7294ff5`](https://github.com/DavideCarvalho/nestjs-authz/commit/7294ff5c01454d9fea6d42a6c3f80eff2f00dc48) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix the exported `VERSION` const shipping as `'0.0.0'`.

  The build is plain `tsc` with no version injection, and `changeset version` only bumps `package.json` — leaving the `export const VERSION` in `src/index.ts` stale, so the published dist reported `'0.0.0'`. The const is now corrected to match each package's `package.json`, and a new `scripts/sync-version.mjs` (chained into the `version-packages` script) re-syncs it on every release bump to prevent future drift. Run with `--check` to fail a build on mismatch.

- Updated dependencies [[`7294ff5`](https://github.com/DavideCarvalho/nestjs-authz/commit/7294ff5c01454d9fea6d42a6c3f80eff2f00dc48)]:
  - @dudousxd/nestjs-authz-client@0.2.1

## 0.1.1

### Patch Changes

- Updated dependencies [[`07d01de`](https://github.com/DavideCarvalho/nestjs-authz/commit/07d01de286e7dfcae5fbeb10b7e8d48533214087)]:
  - @dudousxd/nestjs-authz-client@0.2.0

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
