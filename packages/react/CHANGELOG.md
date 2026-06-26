# @dudousxd/nestjs-authz-react

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

### Patch Changes

- Updated dependencies [[`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7)]:
  - @dudousxd/nestjs-authz-client@0.1.0
