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

## License

MIT
