# `@dudousxd/nestjs-authz-testing`

Test helpers for [`@dudousxd/nestjs-authz`](../core) on
[`@nestjs/authorization`](https://docs.nestjs.com/security/authorization). `buildGate` compiles
a real Nest testing module with the official `AuthorizationModule` and `AuthzModule`, so every
policy decision goes through the official `AuthorizationService`, exactly as in the app.

```ts
import 'reflect-metadata';
import { Policy } from '@nestjs/authorization';
import { PolicyFor } from '@dudousxd/nestjs-authz';
import { buildGate, expectCan, expectCannot, FakePermissionProvider } from '@dudousxd/nestjs-authz-testing';

@Policy()
@PolicyFor(Post)
class PostPolicy {
  update(user: User | null, post: Post) { return user?.id === post.authorId; }
}

const gate = await buildGate({ policies: [PostPolicy] });
await expectCan(gate, { id: 1 }, PostPolicy, 'update', new Post(10, 1)); // official style
await expectCan(gate, { id: 1 }, 'update', new Post(10, 1));             // via @PolicyFor(Post)
await expectCannot(gate, { id: 2 }, 'update', new Post(10, 1));

// RBAC seam, zero DB; wildcard grants work through the core matcher:
const gate2 = await buildGate({ permissionProvider: new FakePermissionProvider({ '1': ['posts.*'] }) });
await expectCan(gate2, { id: 1 }, 'posts.update');
```

Assert what a route requires without booting HTTP:

```ts
expect(requirementsOf(PostController, 'publish')).toEqual([
  { policy: PermissionPolicy, ability: 'has', staticArgs: ['posts.publish'], dynamic: false },
]);
```

## API

- `buildGate(options?)` → `Promise<Gate>`; `createAuthzTestingModule(options?)` →
  `{ module, gate }` (close `module` when done). Options: `{ policies, providers, controllers,
  gates, superAdmin, resolveRoles, resourceResolver, getUser, permissionProvider, roleProvider }`.
  `policies` are classes (or providers, e.g. `{ provide: PostPolicy, useValue }`).
- `buildBoundGate(user, options?)` → `Promise<BoundGate>`.
- `expectCan(gate, user, ability, resource?)` / `expectCan(gate, user, Policy, ability, ...args)`,
  and `expectCannot(...)`. Accept a `Gate` + user, or a `BoundGate` with `undefined` user.
  `expectCannot` treats an unresolved ability as "cannot".
- `requirementsOf(Controller, 'method')` — the official `@Can()` requirements the guard
  enforces there, class-level first, with the arguments of static resolvers.
- `FakePermissionProvider` / `FakeRoleProvider` — in-memory RBAC seams keyed by user id.
- `AuthzAssertionError` — thrown on assertion failure.

Migrating from 0.x: `buildGate` / `buildBoundGate` are now async, take policy classes instead of
instances, and the `after` option is gone.
