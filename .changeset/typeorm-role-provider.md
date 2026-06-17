---
"@dudousxd/nestjs-authz-typeorm": patch
---

`AuthzRbacModule` now registers a `RoleProvider` under the core `ROLE_PROVIDER` token
that returns `store.getRolesForUser(...)`, so coarse role checks (`gate.hasRole('teacher')`,
`@Roles('admin')`) consult the persisted RBAC store too — mirroring the existing
`PERMISSION_PROVIDER` wiring. Roles from the store are unioned with any read off the user
object by core's default resolver.
