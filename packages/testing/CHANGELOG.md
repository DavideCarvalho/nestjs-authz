# @dudousxd/nestjs-authz-testing

## 0.1.1

### Patch Changes

- [#66](https://github.com/DavideCarvalho/nestjs-authz/pull/66) [`d5fdd23`](https://github.com/DavideCarvalho/nestjs-authz/commit/d5fdd23a2b72ae61fae0f913f11164bc4d2df77b) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - Authorization checks within one request no longer hit the database per check. The Gate memoizes `resolveUser`, the permission set and the provider roles on the request context (keyed by the row a user names, its class or `type` plus `id`, so ORMs without an identity map share entries; a plain object without `type` is keyed by identity, so two users that only share an `id` never share an entry), and compiles the granted set once so a check is a hash lookup plus a scan of the wildcard grants. Providers can set the optional `exhaustivePermissions` flag to say `getPermissions` lists everything `hasPermission` grants; the ORM adapters do, and the MikroORM and Prisma providers now expose `getPermissions` (so persisted wildcard grants such as `posts.*` match there too). Grants changed mid-request apply from the next request.
