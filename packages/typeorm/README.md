# @dudousxd/nestjs-authz-typeorm

TypeORM RBAC persistence for [`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) —
roles (global or tenant-scoped), permissions (with wildcards) and direct user permissions for the
official `@nestjs/authorization` policies, with **zero connection ownership**: your app owns the
`DataSource`.

## Install

```bash
pnpm add @dudousxd/nestjs-authz-typeorm @dudousxd/nestjs-authz @nestjs/authorization typeorm
```

Entities (`AUTHZ_ENTITIES`), BYO table names, `createAuthzTables` for migrations and
`ensureAuthzSchema` (non-destructive) mirror the MikroORM and Prisma adapters.

## Usage

```ts
import {
  AuthzRbacModule,
  TypeOrmAuthzStore,
} from '@dudousxd/nestjs-authz-typeorm';
import { DataSource } from 'typeorm';

@Module({
  imports: [
    AuthzRbacModule.forRootAsync({
      inject: [DataSource],  // or getDataSourceToken('auth')
      useFactory: (ds: DataSource) => ({
        store: new TypeOrmAuthzStore(ds),
        // autoCreateSchema defaults to true (non-destructive ensureAuthzSchema)
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
await store.assignRole({ type: 'user', id: 7 }, 'admin', { tenantId: 'acme' }); // tenant-scoped

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

## Query scopes

```ts
const qb = repo.createQueryBuilder('post');
await applyScope(qb, gate.forUser(user), Post); // PostPolicy.scope(user) → a parameterized WHERE
```

## License

MIT
