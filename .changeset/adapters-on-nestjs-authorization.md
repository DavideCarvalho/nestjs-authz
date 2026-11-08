---
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
"@dudousxd/nestjs-authz-drizzle": minor
---

Run on `@dudousxd/nestjs-authz` 0.9 and `@nestjs/authorization`: persisted roles and
permissions now guard routes through the official guard as the core's `RolePolicy` /
`PermissionPolicy` (`@Roles('editor')`, `@Permission('posts.publish')`), and the guard and the
handler's `Gate` calls share one permission and role fetch per request. The store API
(role sources, admin management, tenant-scoped roles where supported) and `AuthzRbacModule`
are unchanged. A persisted permission named like a policy ability no longer bypasses that
policy (see the core changeset). Requires NestJS 12, `@nestjs/authorization` ^0.1.3 and Node 22+.
