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

> BYO table names: MikroORM resolves table names from entity metadata at discovery time,
> so override them by re-declaring these entities with your own `EntitySchema({ tableName })`
> (the `RoleEntitySchema` … `UserRoleEntitySchema` exports are the defaults); the store +
> schema helpers operate purely through the `EntityManager` and never assume a literal name.

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

## License

MIT
