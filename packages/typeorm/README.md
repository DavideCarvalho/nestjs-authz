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

With the connection registered through NestJS's [`@nestjs/typeorm`](https://docs.nestjs.com/techniques/database),
name it and the module builds the store from `getDataSourceToken(connectionName)`:

```ts
import { AuthzRbacModule } from '@dudousxd/nestjs-authz-typeorm';

@Module({
  imports: [
    TypeOrmModule.forRoot({ /* ... */ }),
    AuthzRbacModule.forRoot({
      connectionName: 'default', // or the data source's `name`
      storeOptions: { schema: 'auth' }, // optional: TypeOrmAuthzStore options
      // autoCreateSchema defaults to true (non-destructive ensureAuthzSchema)
    }),
  ],
})
export class AppModule {}
```

`forRootAsync({ connectionName, storeOptions, useFactory })` works the same way, its factory
returning the other options. `@nestjs/typeorm` is an optional peer. Or build the store yourself
from any `DataSource`:

```ts
import { AuthzRbacModule, TypeOrmAuthzStore } from '@dudousxd/nestjs-authz-typeorm';
import { DataSource } from 'typeorm';

@Module({
  imports: [
    AuthzRbacModule.forRootAsync({
      inject: [DataSource], // your connection's token
      useFactory: (ds: DataSource) => ({ store: new TypeOrmAuthzStore(ds) }),
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

## Tenancy

With `@dudousxd/nestjs-context` installed, the module reads the current tenant from the context
accessor (`Context.tenantId()`). A tenant-scoped role then grants only inside its own tenant.
Global roles and direct grants apply everywhere.

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

## Query scopes

```ts
const qb = repo.createQueryBuilder('post');
await applyScope(qb, gate.forUser(user), Post); // PostPolicy.scope(user) → a parameterized WHERE
```

## License

MIT
