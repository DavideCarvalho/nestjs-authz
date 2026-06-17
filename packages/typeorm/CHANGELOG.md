# @dudousxd/nestjs-authz-typeorm

## 0.2.0

### Minor Changes

- [`51d2fbc`](https://github.com/DavideCarvalho/nestjs-authz/commit/51d2fbc6b966c101a6ff0675c42843f040e02703) - Initial release: Laravel-style authorization for NestJS — gates, `@Policy`/`@Can`, the `Gate` service, a default `:id` resource resolver, `before`/`superAdmin` hooks, optional `nestjs-context` current-user with `resolveUser` hydration, and a `PERMISSION_PROVIDER` seam. The `@dudousxd/nestjs-authz-typeorm` adapter adds opt-in RBAC persistence (roles/permissions store, dialect-correct SQL, identifier allowlist, non-destructive schema auto-manage).
