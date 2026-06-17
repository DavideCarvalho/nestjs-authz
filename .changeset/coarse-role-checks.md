---
"@dudousxd/nestjs-authz": minor
---

Add coarse, role-based authorization alongside the granular ability checks.

- **`@Roles('admin', 'teacher')` + `RolesGuard`**: a route is allowed when the current
  user holds ANY of the listed roles. Registered as an `APP_GUARD` by `AuthzModule`
  (inert on un-annotated routes), it resolves the current user exactly as the `Gate`
  does and denies an unauthenticated request by default.
- **`Gate.hasRole(role)` / `Gate.hasAnyRole(roles[])`** (and `gate.forUser(user).hasRole(...)`),
  async, resolving the user's effective roles and testing membership.
- **Pluggable role source, two layers (unioned):**
  1. A default `RoleResolver` that reads roles off the user object — `user.roles`
     (`string[]`) OR `user.role` (`string | string[]`), normalized to a `string[]`.
     This makes role checks work with ZERO RBAC tables. Override via
     `AuthzModule.forRoot({ resolveRoles })`.
  2. An OPTIONAL `ROLE_PROVIDER` seam (`Symbol.for('@dudousxd/nestjs-authz:role-provider')`,
     consulted with `@Optional()`) — mirroring `PERMISSION_PROVIDER` — so an RBAC adapter
     can supply roles from a store. When both yield roles, the Gate unions them; when
     neither does, the check denies.

Exports the `Roles` decorator, `RolesGuard`, `RoleResolver`, `defaultRoleResolver`,
`ROLE_PROVIDER`, `ROLES_METADATA`, and a `RoleProvider` interface. Purely additive — the
existing permission-provider / can-endpoint / diagnostics behavior is unchanged.
