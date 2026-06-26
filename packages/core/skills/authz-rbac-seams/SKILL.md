---
name: authz-rbac-seams
description: >
  Add persisted roles & permissions to @dudousxd/nestjs-authz through its optional,
  grant-only seams. PERMISSION_PROVIDER (a PermissionProvider with hasPermission and an
  optional getPermissions) is the Laravel/spatie Gate::before grant — when the user holds
  a named permission the ability is allowed regardless of policies; getPermissions enables
  segment wildcard matching (granted posts.* satisfies posts.update, * satisfies anything).
  ROLE_PROVIDER (a RoleProvider.getRoles) feeds coarse checks gate.hasRole / @Roles, unioned
  with the user-object defaultRoleResolver (reads user.roles / user.role). Both tokens are
  capability symbols the ORM adapters (@dudousxd/nestjs-authz-typeorm / -prisma / -mikro-orm)
  register via AuthzRbacModule; seams are grant-only — a false result never DENIES, it falls
  through. Covers resolveRoles override and zero-table role checks.
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.6.3"
  framework: nestjs
---

# Persisted RBAC seams

The core stays zero-DB. Persisted roles/permissions plug in through two **optional,
grant-only** seams the Gate consults via `@Optional()` capability tokens:

- `PERMISSION_PROVIDER` → a `PermissionProvider` (the Laravel/spatie `Gate::before` grant).
- `ROLE_PROVIDER` → a `RoleProvider` (feeds `gate.hasRole` / `@Roles`).

When neither is registered, the Gate behaves exactly as before. **Grant-only** means a
provider returning `false`/nullish never DENIES — it falls through to normal resolution.

## Setup

The simplest path is an ORM adapter's `AuthzRbacModule`, which builds a store and
registers both seams. Example with the Prisma adapter (the TypeORM and MikroORM siblings
have an identical `AuthzRbacModule` surface):

```ts
import { Module } from '@nestjs/common';
import { AuthzModule } from '@dudousxd/nestjs-authz';
import { AuthzRbacModule } from '@dudousxd/nestjs-authz-prisma';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

@Module({
  imports: [
    AuthzModule.forRoot({ policies: [PostPolicy] }),
    AuthzRbacModule.forRoot({ client: prisma }), // builds the store, registers the seams
  ],
})
export class AppModule {}
```

Grant permissions/roles through the store, then the Gate consults them automatically:

```ts
await store.givePermissionToRole('editor', 'posts.publish');
await store.assignRole({ type: 'user', id: 7 }, 'editor');

await gate.forUser(user).allows('posts.publish'); // true via PERMISSION_PROVIDER
await gate.forUser(user).hasRole('editor');        // true via ROLE_PROVIDER
```

## Core patterns

### A hand-rolled PermissionProvider

Implement the interface and bind `PERMISSION_PROVIDER` yourself when you do not use an
adapter. Implement `getPermissions` to opt into wildcard matching:

```ts
import type { PermissionProvider, User } from '@dudousxd/nestjs-authz';
import { PERMISSION_PROVIDER } from '@dudousxd/nestjs-authz';

class MyPermissions implements PermissionProvider {
  hasPermission(user: User, permission: string) {
    return this.exactGrants(user).includes(permission); // exact-match fast path
  }
  getPermissions(user: User) {
    return this.grantsFor(user); // e.g. ['posts.*'] — core matches posts.update against it
  }
}
// provide: { provide: PERMISSION_PROVIDER, useClass: MyPermissions }
```

The core runs segment-based wildcard matching against `getPermissions`: a granted
`posts.*` satisfies `posts.update`; `*` satisfies anything. `hasPermission` is the
exact-match contract for providers that do not list grants.

### Zero-table role checks (no provider)

`gate.hasRole` / `@Roles` work with **no** RBAC tables: the `defaultRoleResolver` reads
`user.roles` (`string[]`) OR `user.role` (`string | string[]`) off the user object.
Override the shape with `resolveRoles`:

```ts
AuthzModule.forRoot({
  resolveRoles: (user) => (user as { groups: string[] }).groups, // derive roles differently
});
```

When BOTH a `ROLE_PROVIDER` and the resolver yield roles, the Gate takes their **union**.

## Common mistakes

### 1. Expecting a PermissionProvider to DENY

```ts
// Wrong — returning false to "block" an ability does nothing: the seam is grant-only,
// so a policy/gate can still allow it. This is not how you revoke access.
hasPermission(user: User, permission: string) {
  return this.isBanned(user) ? false : this.grants(user).includes(permission);
}

// Correct — denial belongs in the policy/superAdmin; the provider only GRANTS.
hasPermission(user: User, permission: string) {
  return this.grants(user).includes(permission); // false simply falls through
}
```

Mechanism: the provider grant mirrors `Gate::before` — `true` short-circuits to allow;
`false`/`undefined` falls through to policy/gate resolution and never denies.
Source: `packages/core/src/permission-provider.ts` (grant semantics),
`packages/core/src/gate.ts` (`permissionProviderGrants`, `resolveBase`).

### 2. Re-implementing wildcard matching in your adapter

```ts
// Wrong — manually expanding wildcards inside hasPermission duplicates core logic and
// drifts (e.g. handling 'posts.*' but not '*').
hasPermission(user, permission) {
  return this.grants(user).some((g) => g === '*' || permission.startsWith(g.replace('.*','')));
}

// Correct — expose getPermissions and let the core do segment matching.
getPermissions(user) { return this.grants(user); } // 'posts.*', '*' handled by core
```

Mechanism: when `getPermissions` is present the core applies `permissionSatisfied`
segment matching, so wildcard semantics are identical across every adapter.
Source: `packages/core/src/permission-provider.ts` (getPermissions docs),
`packages/core/src/permission-matcher.ts` (`permissionSatisfied`).

### 3. Granting permissions for an anonymous request

```ts
// Wrong — assuming the permission seam runs for unauthenticated callers.
await gate.allows('posts.publish'); // anonymous → seam is skipped, denies

// Correct — the seam only grants for an authenticated user; resolve/pass one.
await gate.forUser(user).allows('posts.publish');
```

Mechanism: the permission-provider grant is gated on `maybeUser !== NO_USER`, so an
anonymous request never reaches it and follows the default-deny path.
Source: `packages/core/src/gate.ts` (`resolveBase` — `maybeUser !== NO_USER && permissionProviderGrants(...)`).
