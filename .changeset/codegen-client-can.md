---
"@dudousxd/nestjs-authz-codegen": patch
---

The emitted `can()` now delegates to `@dudousxd/nestjs-authz-client` instead of a
hand-rolled POST. The generated `api.ts` imports `AbilityStore` + `createCan`, exports a
shared `authzStore` you hydrate once, and `can()` is a thin typed wrapper over the store's
`createCan` resolver — so a hydrated decision is answered synchronously with NO request,
and a cache miss uses the same configurable `'fetch'` fallback to the `endpoint`. The
compile-time `AuthzAbility` string-literal union is unchanged (a wrong ability is still a
type error). Adds `@dudousxd/nestjs-authz-client` as an optional peer dependency.
