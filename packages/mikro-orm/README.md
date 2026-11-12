# @dudousxd/nestjs-authz-mikro-orm

MikroORM RBAC persistence for [`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) —
roles and permissions for the official `@nestjs/authorization` policies, with **zero connection ownership** (your app owns the
`EntityManager`; this package never opens a connection).

This is the MikroORM sibling of `@dudousxd/nestjs-authz-typeorm`: identical store surface
and `AuthzRbacModule`, backed by MikroORM entities.

Works with **MikroORM 6 and 7** (peer `@mikro-orm/core` `^6 || ^7`). The entities are
defined with `EntitySchema` — the one definition style that lives entirely in
`@mikro-orm/core` across both majors (v7 moved the `@Entity/@Property/...` decorators into a
separate `@mikro-orm/decorators` package), so no extra peer is required.

## Install

```bash
pnpm add @dudousxd/nestjs-authz-mikro-orm @dudousxd/nestjs-authz @nestjs/authorization @mikro-orm/core @mikro-orm/nestjs
```

## Entities

The package ships four entities (referencing the user **by id only** — it never owns a
users table):

- `RoleEntity` → `authz_roles`
- `PermissionEntity` → `authz_permissions`
- `RolePermissionEntity` → `authz_role_permission` (pivot)
- `UserRoleEntity` → `authz_user_role` (pivot, keyed by `userType` + `userId`)

Register them with your ORM so MikroORM can discover them:

```ts
import { AUTHZ_ENTITIES } from '@dudousxd/nestjs-authz-mikro-orm';

await MikroORM.init({ entities: [...AUTHZ_ENTITIES /* , your entities */] });
```

### BYO table names

MikroORM resolves table names from entity metadata at discovery time. Build your own set of
schemas with `createAuthzEntitySchemas` and register those instead:

```ts
import { createAuthzEntitySchemas } from '@dudousxd/nestjs-authz-mikro-orm';

const authz = createAuthzEntitySchemas({ roles: 'app_roles', userRole: 'app_user_role' });
await MikroORM.init({ entities: [...authz.all /* , your entities */] });
```

Any subset of `roles` / `permissions` / `rolePermission` / `userRole` may be overridden; the
rest keep their defaults. The factory carries the custom repository binding and derives the
index names from your table names, so nothing is lost by relocating the tables — hand-writing
`new EntitySchema({ class: RoleEntity, tableName })` instead silently drops both. The store and
the schema helpers read the physical names back off the live metadata and never assume a
literal name.

## Repositories

Each entity is bound to a typed repository, so app code injects it by type rather than passing
the entity class to every `EntityManager` call:

```ts
import { AUTHZ_ENTITY_CLASSES, AuthzRoleRepository } from '@dudousxd/nestjs-authz-mikro-orm';
import { MikroOrmModule } from '@mikro-orm/nestjs';

@Module({
  // forFeature matches on the entity CLASS — pass these, not the schemas.
  imports: [MikroOrmModule.forFeature([...AUTHZ_ENTITY_CLASSES])],
})
export class RolesModule {}

@Injectable()
export class RolesService {
  constructor(private readonly roles: AuthzRoleRepository) {}

  findByName(name: string) {
    return this.roles.findOne({ name });
  }
}
```

Without `@mikro-orm/nestjs`, `em.getRepository(RoleEntity)` returns the same instance and is
typed as `AuthzRoleRepository`. The four classes are `AuthzRoleRepository`,
`AuthzPermissionRepository`, `AuthzRolePermissionRepository` and `AuthzUserRoleRepository`;
their bodies are empty — this package ships no query surface beyond `MikroOrmAuthzStore`.

`MikroOrmAuthzStore` is unaffected — it still takes an `EntityManager` and owns no connection.

## Usage

```ts
import {
  AuthzRbacModule,
  MikroOrmAuthzStore,
} from '@dudousxd/nestjs-authz-mikro-orm';
import { EntityManager } from '@mikro-orm/core';

@Module({
  imports: [
    AuthzRbacModule.forRootAsync({
      inject: [EntityManager],
      useFactory: (em: EntityManager) => ({
        store: new MikroOrmAuthzStore(em),
        // autoCreateSchema defaults to true (non-destructive `updateSchema({ safe: true })`)
      }),
    }),
  ],
})
export class AppModule {}
```

Once wired, persisted roles and permissions guard routes through the official
`@nestjs/authorization` guard, as the core's `RolePolicy` / `PermissionPolicy`:

```ts
await store.givePermissionToRole('editor', 'posts.*');
await store.assignRole({ type: 'user', id: 7 }, 'editor');

@Permission('posts.publish')                                  // posts.* grants it
@Can(PermissionPolicy, 'has', permission('posts.publish'))   // the same, spelled out
@Roles('editor')                                              // @Can(RolePolicy, 'has', roles('editor'))
```

and in services, through the `Gate`:

```ts
gate.forUser(user).allows('posts.publish');               // true (PERMISSION_PROVIDER seam)
gate.forUser(user).allows(PermissionPolicy, 'has', 'posts.publish');
gate.forUser(user).hasRole('editor');                     // true (ROLE_PROVIDER seam)
```

The user is the one the official guard reads (`AuthorizationModule.forRoot({ getUser })`,
default `request.user`), mapped to a store ref with `userRefFrom` (default `{ type, id }` or
`{ id }`).

## Schema

`autoCreateSchema` (default `true`) runs `ensureAuthzSchema` on `onModuleInit` via MikroORM's
native **`updateSchema({ safe: true })`** — it creates missing tables and ADDs missing columns,
but never drops/alters/renames existing ones, so it is safe to run on every boot.

To manage the schema with MikroORM migrations instead, set `autoCreateSchema: false` and use
the SQL helper:

```ts
import { authzSchemaSql } from '@dudousxd/nestjs-authz-mikro-orm';

export class AddAuthz extends Migration {
  async up() {
    this.addSql(await authzSchemaSql(this.getEntityManager().getOrm()));
  }
}
```

## Role sources (manual vs SSO/SCIM)

Every role assignment records a `source`. It defaults to `'manual'`, so existing calls and existing
rows keep their meaning. A sync replaces only its own source:

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

### Migrating an existing database

`ensureAuthzSchema` / `autoCreateSchema` add the `source` column to `authz_user_role`
(`NOT NULL DEFAULT 'manual'`), so existing rows become manual assignments. They don't widen the
primary key. Until you widen it, a role can come from only one source per user: assigning it from
a second source fails with a duplicate-key error. Widen the key once:

```sql
-- PostgreSQL (default constraint name; check yours with \d authz_user_role)
ALTER TABLE authz_user_role DROP CONSTRAINT authz_user_role_pkey,
  ADD PRIMARY KEY (user_type, user_id, role_id, source);
-- MySQL
ALTER TABLE authz_user_role DROP PRIMARY KEY, ADD PRIMARY KEY (user_type, user_id, role_id, source);
-- SQLite: recreate the table with the 4-column key (SQLite cannot alter a primary key).
```

## Admin management

Operations for an admin UI (role editor, member list, account deletion):

```ts
// Replace a role's permissions with exactly this set (spatie's syncPermissions). Creates missing
// roles/permissions by name; the link swap is transactional.
await store.syncRolePermissions('editor', ['posts.view', 'posts.edit']);

// Each role's permission names in one query. Existing roles are keys (even with no permissions);
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

`tenantId` filters: omitted = every tenant, `null` = global assignments only, a string = that
tenant's scoped assignments only. Without the tenant column (below) every row has
`tenantId: null`, so a tenant id string matches nothing.

## Tenant-scoped roles

Build the entities with `tenantScoped: true` to assign roles per tenant. The user-role table
gets a `tenant_id` column (default `''`, a global assignment) in its primary key:

```ts
import { createAuthzEntitySchemas } from '@dudousxd/nestjs-authz-mikro-orm';

const authz = createAuthzEntitySchemas({}, { tenantScoped: true }); // or your own table names
MikroOrmModule.forRoot({ entities: [...authz.all /* , your entities */] });

await store.assignRole(user, 'editor', { tenantId: 'acme' }); // only inside acme
await store.assignRole(user, 'viewer');                        // everywhere
await store.getRolesForUser(user, { tenantId: 'acme' });      // ['editor', 'viewer']
await store.getRolesForUser(user);                            // ['viewer']
```

`removeRole` and `setUserRoles` take the same `{ tenantId }` (omitted = the global
assignments). Without `tenantScoped`, every assignment is global and reads ignore the tenant.
`assignRole` and `setUserRoles` with a `tenantId` throw; `removeRole` with one does nothing,
since there is no tenant assignment to remove.

### Migrating an existing database

`ensureAuthzSchema` / `autoCreateSchema` (or `authzSchemaSql` in a migration) add the `tenant_id`
column, so existing rows become global assignments. Widen the primary key once, so the same role
can be assigned in two tenants:

```sql
-- PostgreSQL (default constraint name; check yours with \d authz_user_role)
ALTER TABLE authz_user_role DROP CONSTRAINT authz_user_role_pkey,
  ADD PRIMARY KEY (user_type, user_id, role_id, source, tenant_id);
-- MySQL
ALTER TABLE authz_user_role DROP PRIMARY KEY,
  ADD PRIMARY KEY (user_type, user_id, role_id, source, tenant_id);
-- SQLite: recreate the table with the 5-column key (SQLite cannot alter a primary key).
```

## Tenancy

The RBAC module reads the tenant only when tenancy is on: turn it on with
`ContextModule.forRoot({ tenancy: { enabled: true } })` in `@dudousxd/nestjs-context`. Checks
are then scoped to the request's tenant from `Context.setTenant(...)`.
A request with no tenant, or inside `Context.allTenants()`, sees global assignments only.

```ts
AuthzRbacModule.forRoot({
  store,
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

With tenancy on and the default entities, every assignment is global, so only `roles` and the
`tenant` resolver change what a check sees.

## License

MIT
