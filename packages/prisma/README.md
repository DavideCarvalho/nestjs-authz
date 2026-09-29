# @dudousxd/nestjs-authz-prisma

Prisma RBAC persistence for [`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) —
roles, permissions, and a Gate seam, with **zero connection ownership** (your app owns the
`PrismaClient`; this package never opens a connection and never imports `@prisma/client`).

This is the Prisma sibling of `@dudousxd/nestjs-authz-typeorm`: identical store surface and
`AuthzRbacModule`, consuming a **structural** Prisma client interface.

## Install

```bash
pnpm add @dudousxd/nestjs-authz-prisma @dudousxd/nestjs-authz
```

No `@prisma/client` is required by this package — it depends only on the structural
`PrismaAuthzClientLike` interface, which a real `PrismaClient` satisfies. There is **no
`prisma generate` step** introduced by this adapter.

## Schema (consumer-managed)

Prisma is schema-first: add the four RBAC models to your `schema.prisma` and apply them with
`prisma migrate` / `prisma db push`. The user is referenced **by id only** — this package
never owns a users table.

```prisma
model Role {
  id        String   @id
  name      String   @unique
  guard     String?
  createdAt DateTime @default(now())

  @@map("authz_roles")
}

model Permission {
  id        String   @id
  name      String   @unique
  guard     String?
  createdAt DateTime @default(now())

  @@map("authz_permissions")
}

model RolePermission {
  roleId       String
  permissionId String

  @@id([roleId, permissionId])
  @@map("authz_role_permission")
}

model UserRole {
  userType String
  userId   String
  roleId   String

  @@id([userType, userId, roleId])
  @@index([userType, userId])
  @@map("authz_user_role")
}
```

> Unlike the TypeORM/MikroORM adapters there is **no auto-create** — `store.ensureSchema()`
> is a no-op. Manage the schema with Prisma migrations.

## Usage

```ts
import { AuthzRbacModule } from '@dudousxd/nestjs-authz-prisma';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

@Module({
  imports: [
    // Pass the client directly — the module builds the store. (Or pass a pre-built `store`.)
    AuthzRbacModule.forRoot({ client: prisma }),
  ],
})
export class AppModule {}
```

Or build the store yourself and inject the client via the `PRISMA_CLIENT` token:

```ts
import { PRISMA_CLIENT, PrismaAuthzStore } from '@dudousxd/nestjs-authz-prisma';

AuthzRbacModule.forRootAsync({
  inject: [PRISMA_CLIENT],
  useFactory: (client) => ({ store: new PrismaAuthzStore(client) }),
});
```

Once wired, the Gate consults persisted RBAC:

```ts
await store.givePermissionToRole('editor', 'posts.publish');
await store.assignRole({ type: 'user', id: 7 }, 'editor');

gate.forUser(user).allows('posts.publish'); // true (PERMISSION_PROVIDER seam)
gate.forUser(user).hasRole('editor');       // true (ROLE_PROVIDER seam)
```

## Role sources (manual vs SSO/SCIM)

Every role assignment records a `source`. It defaults to `'manual'`, so existing calls and existing
rows keep their meaning. Needs `roleSources: true`, as described below. A sync replaces only its own source:

```ts
// On each SSO login: exactly these roles come from SSO. Manual grants are untouched.
await store.setUserRoles(user, rolesFromIdpGroups, { source: 'sso' });

await store.assignRole(user, 'editor');                      // source 'manual'
await store.assignRole(user, 'editor', { source: 'scim' });  // a second assignment of the same role
await store.removeRole(user, 'editor', { source: 'scim' });  // still an editor (manual)
await store.removeRole(user, 'editor');                      // no source: removed from every source
await store.getRoleAssignments(user); // [{ role, source, tenantId }]
```

`getRolesForUser` and the Gate seams see the distinct role names from all sources.

### Enabling it (schema change)

Prisma is schema-first, so per-source assignments are **opt-in**. With the default
`roleSources: false`, the store never sends a `source` field and your current schema keeps
working. `setUserRoles` then replaces *all* of the user's roles, and a non-default `source`
throws. To enable per-source assignments:

```prisma
model UserRole {
  userType String
  userId   String
  roleId   String
  source   String @default("manual")

  @@id([userType, userId, roleId, source])
  @@index([userType, userId])
  @@map("authz_user_role")
}
```

Then run `prisma migrate dev`. Existing rows get `source = 'manual'`. Finally, build the store
with the option: `new PrismaAuthzStore(prisma, { roleSources: true })`, or
`AuthzRbacModule.forRoot({ client: prisma, roleSources: true })`. `setUserRoles` uses
`prisma.$transaction` when it's available.

## Admin management

Operations for an admin UI (role editor, member list, account deletion):

```ts
// Replace a role's permissions with exactly this set (spatie's syncPermissions). Creates missing
// roles/permissions by name; the link swap is atomic when the client has `$transaction` (a real `PrismaClient` does).
await store.syncRolePermissions('editor', ['posts.view', 'posts.edit']);

// Each role's permission names in three queries, whatever the number of roles. Existing roles are keys (even with no permissions);
// roles that don't exist are absent.
await store.getRolePermissions(['editor', 'viewer']); // { editor: ['posts.edit', 'posts.view'], viewer: [] }

// Delete a role, its permission links and every assignment of it (all sources). Returns false
// when the role didn't exist. Permissions are kept.
await store.deleteRole('editor');

// Raw assignment rows: { userType, userId, role, source, tenantId }[],
// ordered by (userType, userId, role, source).
await store.listRoleAssignments({ role: ['admin', 'owner'], source: 'sso' });
await store.listRoleAssignments({ user: { type: 'user', id: 7 } });

// Account deleted: drop every role assignment of the user (all sources).
await store.removeUser({ type: 'user', id: 7 });
```

This adapter has no tenant-scoped assignments, so every row has `tenantId: null`:
`listRoleAssignments({ tenantId: null })` lists everything and a tenant id string matches
nothing. Without `roleSources: true` every row is `'manual'`, so filtering by another
`source` matches nothing.

## License

MIT
