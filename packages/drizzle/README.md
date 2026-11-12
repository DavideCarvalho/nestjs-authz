# @dudousxd/nestjs-authz-drizzle

[Drizzle ORM](https://orm.drizzle.team) adapter for
[`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) (Postgres):

- **Query scopes** — compile `gate.scope(Entity)` into a Drizzle `WHERE` (`compileScope` /
  `applyScope`), so list endpoints filter at the database instead of over-fetching.
- **RBAC persistence** — roles, permissions, tenant-scoped role assignments and direct user
  permissions for the official `@nestjs/authorization` policies (the core's `RolePolicy` /
  `PermissionPolicy`) and the `Gate`, through `AuthzRbacModule`. Your app owns the Drizzle database; this
  package never opens a connection.

It's the Drizzle version of `@dudousxd/nestjs-authz-typeorm`. The store surface and
`AuthzRbacModule` are the same, and so are the physical tables and columns, so switching
between adapters leaves your data where it is.

## Install

```bash
pnpm add @dudousxd/nestjs-authz-drizzle @dudousxd/nestjs-authz @nestjs/authorization drizzle-orm
```

Requires NestJS 12, `@nestjs/authorization` ^0.1.3, `@dudousxd/nestjs-authz` 0.9 and Node 24+.
`drizzle-orm` is a peer (`>=0.40.0 <1.0.0`). Any Drizzle Postgres driver works:
`node-postgres`, `postgres-js`, PGlite, Neon, and so on.

## Query scopes

Write a policy `scope` with the ORM-neutral builders from the core:

```ts
import { Policy } from '@nestjs/authorization';
import { PolicyFor, eq, or, type ScopeConstraint } from '@dudousxd/nestjs-authz';

@Policy()
@PolicyFor(Post)
export class PostPolicy {
  scope(user: User): ScopeConstraint {
    return or(eq('authorId', user.id), eq('published', true));
  }
}
```

Then compile it against your Drizzle table:

```ts
import { applyScope, compileScope } from '@dudousxd/nestjs-authz-drizzle';
import { and, eq } from 'drizzle-orm';
import { posts } from './db/schema';

const scope = await applyScope(gate.forUser(user), Post, posts); // = compileScope(await gate.forUser(user).scope(Post), posts)
const rows = await db.select().from(posts).where(and(scope, eq(posts.archived, false)));
```

- A scope `field` resolves to the table's **property key** (`authorId`) first, then to the
  physical column name (`author_id`). A field that matches neither throws, so it never reaches
  the SQL.
- To allowlist columns explicitly, or to scope over a JOIN, pass a column map instead of a
  table: `compileScope(constraint, { authorId: posts.authorId, orgId: orgs.id })`.
- `allow-all` (super-admin, `before` grant, or a permission grant for an entity whose policy
  has no scope method) returns `undefined`.
  Both `.where()` and `and()` ignore it, so no predicate is added. `deny-all` becomes `1 = 0`.
- Values always go through Drizzle's operators. They're bound as parameters and mapped by the
  column (for example, a `Date` becomes a timestamp).

## RBAC store

With the database registered through NestJS's [`@nestjs/drizzle`](https://docs.nestjs.com/data/drizzle),
name the connection and the module builds the store from `getDrizzleToken(connectionName)`:

```ts
import { DrizzleModule } from '@nestjs/drizzle';
import { AuthzRbacModule } from '@dudousxd/nestjs-authz-drizzle';

@Module({
  imports: [
    DrizzleModule.forRoot({ drizzle, connection: process.env.DATABASE_URL }),
    AuthzRbacModule.forRoot({
      connectionName: 'default', // or the `name` given to DrizzleModule
      storeOptions: { schema: 'auth' }, // optional: DrizzleAuthzStore options
    }),
  ],
})
export class AppModule {}
```

`forRootAsync({ connectionName, storeOptions, useFactory })` works the same way, its factory
returning the other options. `@nestjs/drizzle` is an optional peer. Or build the store yourself
from any Drizzle database:

```ts
import { AuthzRbacModule, DrizzleAuthzStore } from '@dudousxd/nestjs-authz-drizzle';

@Module({
  imports: [
    AuthzRbacModule.forRootAsync({
      inject: [DB], // your Drizzle database token
      useFactory: (db: Db) => ({ store: new DrizzleAuthzStore(db) }),
    }),
  ],
})
export class AppModule {}
```

```ts
await store.givePermissionToRole('editor', 'posts.*');
await store.assignRole({ type: 'user', id: 7 }, 'editor');                     // global
await store.assignRole({ type: 'user', id: 7 }, 'admin', { tenantId: 'acme' }); // tenant-scoped
await store.giveUserPermission(7, 'reports.export');                           // direct grant
```

Persisted roles and permissions then guard routes through the official guard:

```ts
@Permission('posts.publish')                                  // posts.* grants it
@Can(PermissionPolicy, 'has', permission('posts.publish'))   // the same, spelled out
@Roles('editor')                                              // @Can(RolePolicy, 'has', roles('editor'))
```

and services, through the `Gate`:

```ts
gate.forUser(user).allows('posts.publish');               // true (PERMISSION_PROVIDER seam)
gate.forUser(user).allows(PermissionPolicy, 'has', 'posts.publish');
gate.forUser(user).hasRole('editor');                     // true (ROLE_PROVIDER seam)
```

The user is the one the official guard reads (`AuthorizationModule.forRoot({ getUser })`,
default `request.user`), mapped to a store ref with `userRefFrom` (default `{ type, id }` or
`{ id }`). Within one request, the guard and the handler's `Gate` calls share one permission
and one role query per user. A permission never bypasses a policy that defines the ability:
`gate.allows('update', post)` is `PostPolicy`'s to decide.

With `@dudousxd/nestjs-context` installed, the module reads the current tenant from the context
accessor. A tenant-scoped role then grants only inside its own tenant. Global roles and direct
grants apply everywhere.

With tenancy on (`ContextModule.forRoot({ tenancy: { enabled: true } })` in
`@dudousxd/nestjs-context`), checks are scoped to the request's tenant from `Context.setTenant(...)`.
A request with no tenant, or inside `Context.allTenants()`, sees global assignments only.

```ts
AuthzRbacModule.forRoot({
  connectionName: 'default',
  tenancy: {
    kinds: ['organization'],                  // optional: tenant kinds this module honours
    roles: { owner: 'org_admin', member: 'org_member' }, // optional: tenant.role → authz roles in that tenant
  },
  tenant: (user) => (user as { orgId?: string }).orgId, // optional: an explicit tenant wins over the context
});
```

`tenancy` defaults to `'inherit'` (follow the context switch); `false` keeps this module out.
Roles mapped with `roles` apply only inside that tenant and only to the context's current user.
The `tenant` resolver returns a tenant id, `null` for the global scope, or `undefined` to fall
back to the context.

To run the store inside your own transaction, use `store.withDb(tx)`.

## Schema

The five tables are plain Drizzle `pgTable`s built by `createAuthzTables`. Re-export them from
the schema file that `drizzle.config.ts` points at, and drizzle-kit will generate the migration:

```ts
// db/schema.ts
import { createAuthzTables } from '@dudousxd/nestjs-authz-drizzle';

export const authz = createAuthzTables(); // or { tableNames: { roles: 'app_roles' }, schema: 'rbac' }
export const {
  roles: authzRoles,
  permissions: authzPermissions,
  rolePermission: authzRolePermission,
  userRole: authzUserRole,
  userPermission: authzUserPermission,
} = authz;
```

Give the store the **same** object with `new DrizzleAuthzStore(db, { tables: authz })`. The
queries and the migration then come from one definition and can't drift apart.

If you don't use drizzle-kit, set `autoCreateSchema: true` on the module, or call
`store.ensureSchema()` yourself. Both run `CREATE TABLE/INDEX IF NOT EXISTS` and never alter or
drop anything. `authzSchemaDdl(tables)` gives you the same DDL as strings for a hand-written
migration. `autoCreateSchema` defaults to `false`, because with Drizzle the schema usually
belongs to drizzle-kit.

| Table (default name)    | Columns                                                      |
| ----------------------- | ------------------------------------------------------------ |
| `authz_roles`           | `id`, `name` (unique), `guard`, `createdAt`                  |
| `authz_permissions`     | `id`, `name` (unique), `guard`, `createdAt`                  |
| `authz_role_permission` | `roleId`, `permissionId` (PK)                                |
| `authz_user_role`       | `userType`, `userId`, `roleId`, `tenantId` (`''` = global) (PK) |
| `authz_user_permission` | `userType`, `userId`, `permissionId` (PK)                    |

Users are referenced **by id only**. This package never owns a users table.

## Role sources (manual vs SSO/SCIM)

Every role assignment records a `source`. It defaults to `'manual'`, so existing calls and existing
rows keep their meaning. A sync replaces only its own source:

```ts
// On each SSO login: exactly these roles come from SSO. Manual grants are untouched.
await store.setUserRoles(user, rolesFromIdpGroups, { source: 'sso', tenantId: 'acme' });

await store.assignRole(user, 'editor');                      // source 'manual'
await store.assignRole(user, 'editor', { source: 'scim' });  // a second assignment of the same role
await store.removeRole(user, 'editor', { source: 'scim' });  // still an editor (manual)
await store.removeRole(user, 'editor');                      // no source: removed from every source
await store.getRoleAssignments(user); // [{ role, source, tenantId }]
```

`getRolesForUser` and the Gate seams see the distinct role names from all sources.

### Migrating an existing database

`authz_user_role` gains a `"source"` column (`NOT NULL DEFAULT 'manual'`), and the primary key
becomes `("userType","userId","roleId","tenantId","source")`.

- **drizzle-kit:** regenerate the migration from `createAuthzTables()`.
- **`ensureSchema()`:** it adds the column (`ADD COLUMN IF NOT EXISTS`, so existing rows become
  manual assignments) but doesn't touch the key. Widen the key once, so that one role can come
  from two sources:

```sql
ALTER TABLE "authz_user_role"
  DROP CONSTRAINT "authz_user_role_pkey",
  ADD CONSTRAINT "authz_user_role_pkey" PRIMARY KEY ("userType","userId","roleId","tenantId","source");
```

## Admin management

Operations for an admin UI (role editor, member list, account deletion):

```ts
// Replace a role's permissions with exactly this set (spatie's syncPermissions). Creates missing
// roles/permissions by name. One transaction.
await store.syncRolePermissions('editor', ['posts.view', 'posts.edit']);

// Each role's permission names in one query. Existing roles are keys (even with no permissions);
// roles that don't exist are absent.
await store.getRolePermissions(['editor', 'viewer']); // { editor: ['posts.edit', 'posts.view'], viewer: [] }

// Delete a role, its permission links and every assignment of it (all tenants, all sources).
// Returns false when the role didn't exist. Permissions are kept.
await store.deleteRole('editor');

// Raw assignment rows: { userType, userId, role, source, tenantId }[],
// ordered by (userType, userId, role, source, tenantId).
await store.listRoleAssignments({ tenantId: 'acme' });  // that tenant's scoped rows ONLY (no globals)
await store.listRoleAssignments({ tenantId: null });    // global rows only
await store.listRoleAssignments({ role: ['admin', 'owner'], source: 'sso' });
await store.listRoleAssignments({ user: { type: 'user', id: 7 } }); // tenantId omitted = every tenant

// Account deleted: drop every role assignment (all tenants/sources) and direct permission.
await store.removeUser({ type: 'user', id: 7 });
```

These run inside the caller's transaction when the store is bound to one
(`store.withDb(tx)`).

## Testing

`pnpm test` runs every spec against an in-process Postgres (PGlite), so it needs no Docker.
`pnpm test:db:pg` runs the integration specs against a real Postgres container. If
`AUTHZ_TEST_PG_HOST`/`AUTHZ_TEST_PG_PORT` are already set, it uses that server instead.

## License

MIT
