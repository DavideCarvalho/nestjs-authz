# @dudousxd/nestjs-authz-typeorm

## 0.2.1

### Patch Changes

- [#2](https://github.com/DavideCarvalho/nestjs-authz/pull/2) [`2ecb0f4`](https://github.com/DavideCarvalho/nestjs-authz/commit/2ecb0f46342fa4527fc01f1097720f2e7bcf9aa7) Thanks [@DavideCarvalho](https://github.com/DavideCarvalho)! - `AuthzRbacModule` now registers a `RoleProvider` under the core `ROLE_PROVIDER` token
  that returns `store.getRolesForUser(...)`, so coarse role checks (`gate.hasRole('teacher')`,
  `@Roles('admin')`) consult the persisted RBAC store too — mirroring the existing
  `PERMISSION_PROVIDER` wiring. Roles from the store are unioned with any read off the user
  object by core's default resolver.

## 0.2.0

### Minor Changes

- [`51d2fbc`](https://github.com/DavideCarvalho/nestjs-authz/commit/51d2fbc6b966c101a6ff0675c42843f040e02703) - Initial release: Laravel-style authorization for NestJS — gates, `@Policy`/`@Can`, the `Gate` service, a default `:id` resource resolver, `before`/`superAdmin` hooks, optional `nestjs-context` current-user with `resolveUser` hydration, and a `PERMISSION_PROVIDER` seam. The `@dudousxd/nestjs-authz-typeorm` adapter adds opt-in RBAC persistence (roles/permissions store, dialect-correct SQL, identifier allowlist, non-destructive schema auto-manage).
