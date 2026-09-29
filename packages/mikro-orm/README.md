# @dudousxd/nestjs-authz-mikro-orm

MikroORM RBAC persistence for [`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) —
roles, permissions, and a Gate seam, with **zero connection ownership** (your app owns the
`EntityManager`; this package never opens a connection).

This is the MikroORM sibling of `@dudousxd/nestjs-authz-typeorm`: identical store surface
and `AuthzRbacModule`, backed by MikroORM entities.

Works with **MikroORM 6 and 7** (peer `@mikro-orm/core` `^6 || ^7`). The entities are
defined with `EntitySchema` — the one definition style that lives entirely in
`@mikro-orm/core` across both majors (v7 moved the `@Entity/@Property/...` decorators into a
separate `@mikro-orm/decorators` package), so no extra peer is required.

## Install

```bash
pnpm add @dudousxd/nestjs-authz-mikro-orm @dudousxd/nestjs-authz @mikro-orm/core @mikro-orm/nestjs
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

Once wired, the Gate consults persisted RBAC:

```ts
await store.givePermissionToRole('editor', 'posts.publish');
await store.assignRole({ type: 'user', id: 7 }, 'editor');

gate.forUser(user).allows('posts.publish'); // true (PERMISSION_PROVIDER seam)
gate.forUser(user).hasRole('editor');       // true (ROLE_PROVIDER seam)
```

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

This adapter has no tenant-scoped assignments, so every row has `tenantId: null`:
`listRoleAssignments({ tenantId: null })` lists everything and a tenant id string matches
nothing.

## License

MIT
