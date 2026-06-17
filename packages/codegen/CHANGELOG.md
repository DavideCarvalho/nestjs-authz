# @dudousxd/nestjs-authz-codegen

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
