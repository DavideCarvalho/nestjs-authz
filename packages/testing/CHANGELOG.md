# @dudousxd/nestjs-authz-testing

## 0.3.0

### Minor Changes

- Back on the 0.x line. The 1.x and 2.x versions were published by accident: a release-tooling peer cascade bumped this package to a major, not an API decision. 0.3.0 contains everything those versions shipped (console `authorize` support, tenancy, Node 24+ `engines`) with no other change. Upgrade from 1.x/2.x to 0.3.0; those versions are deprecated.

## 2.0.0

### Major Changes

- [#74](https://github.com/DavideCarvalho/nestjs-authz/pull/74) [`35421dc`](https://github.com/DavideCarvalho/nestjs-authz/commit/35421dc5b09bd271d5087d26e8536191ef6ba342) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - **Breaking:** require Node.js 24 or newer (`engines.node` is now `>=24`; it was `>=22`, and `>=20` for `-client` and `-react`). CI tests on Node 24 and 26. No API changes: see the Upgrading page in the docs.

## 1.0.0

### Patch Changes

- Updated dependencies [[`750a6b3`](https://github.com/DavideCarvalho/nestjs-authz/commit/750a6b3f80deea3803dec8df5f9f8cf67a046ac1)]:
  - @dudousxd/nestjs-authz@0.10.0

## 0.2.0

### Minor Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - `buildGate` / `buildBoundGate` are async and compile a Nest testing module with the official
  `AuthorizationModule` and `AuthzModule`, so decisions run through `AuthorizationService`.
  `policies` takes classes (or providers) instead of instances; the `after` option is gone. New:
  `createAuthzTestingModule()`, official-style `expectCan(gate, user, Policy, 'ability', ...args)`,
  and `requirementsOf(Controller, 'method')`. Peers on `@nestjs/authorization`,
  `@nestjs/common`/`core`/`testing` 12.

### Patch Changes

- [#67](https://github.com/DavideCarvalho/nestjs-authz/pull/67) [`32e967f`](https://github.com/DavideCarvalho/nestjs-authz/commit/32e967ffbcd68a97e8effc77af9c16bbbafdc918) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Fix packages that could be published without files their `exports` point to. `tsc` builds no longer use a `.tsbuildinfo` that can outlive `dist/` and skip emitting files. A new `check:exports` step (also `prepack`) fails the release if any `exports`/`main`/`types` path is missing.

## 0.1.1

### Patch Changes

- [#66](https://github.com/DavideCarvalho/nestjs-authz/pull/66) [`d5fdd23`](https://github.com/DavideCarvalho/nestjs-authz/commit/d5fdd23a2b72ae61fae0f913f11164bc4d2df77b) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Authorization checks within one request no longer hit the database per check. The Gate memoizes `resolveUser`, the permission set and the provider roles on the request context (keyed by the row a user names, its class or `type` plus `id`, so ORMs without an identity map share entries; a plain object without `type` is keyed by identity, so two users that only share an `id` never share an entry), and compiles the granted set once so a check is a hash lookup plus a scan of the wildcard grants. Providers can set the optional `exhaustivePermissions` flag to say `getPermissions` lists everything `hasPermission` grants; the ORM adapters do, and the MikroORM and Prisma providers now expose `getPermissions` (so persisted wildcard grants such as `posts.*` match there too). Grants changed mid-request apply from the next request.
