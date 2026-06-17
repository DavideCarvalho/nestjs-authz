---
"@dudousxd/nestjs-authz-client": minor
"@dudousxd/nestjs-authz-react": minor
"@dudousxd/nestjs-authz-inertia": patch
---

Extract the framework-neutral ability store into a new `@dudousxd/nestjs-authz-client`
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
