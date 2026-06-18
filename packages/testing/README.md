# `@dudousxd/nestjs-authz-testing`

Test helpers for [`@dudousxd/nestjs-authz`](../core). Build a real `Gate`/`BoundGate`
from fixture users, policies, gates, and an in-memory permission/role provider — no
Nest module, no database — then assert verdicts with `expectCan` / `expectCannot`.

```ts
import 'reflect-metadata';
import { Policy } from '@dudousxd/nestjs-authz';
import { buildGate, expectCan, expectCannot, FakePermissionProvider } from '@dudousxd/nestjs-authz-testing';

@Policy(Post)
class PostPolicy {
  update(user, post) { return user?.id === post.authorId; }
}

const gate = buildGate({ policies: [new PostPolicy()] });
await expectCan(gate, { id: 1 }, 'update', new Post(10, 1));
await expectCannot(gate, { id: 2 }, 'update', new Post(10, 1));

// RBAC seam, zero DB — wildcard grants work via the core matcher:
const gate2 = buildGate({ permissionProvider: new FakePermissionProvider({ '1': ['posts.*'] }) });
await expectCan(gate2, { id: 1 }, 'posts.update');
```

## API

- `buildGate(options?)` → `Gate` from `{ policies, gates, superAdmin, after, resolveRoles, permissionProvider, roleProvider }`.
- `buildBoundGate(user, options?)` → `BoundGate` bound to a fixture user.
- `expectCan(gate, user, ability, resource?)` / `expectCannot(...)` — assert the verdict
  (accept a `Gate` + user, or a `BoundGate` with `undefined` user). `expectCannot`
  treats an unresolved ability as "cannot".
- `FakePermissionProvider` / `FakeRoleProvider` — in-memory RBAC seams keyed by user id.
- `AuthzAssertionError` — thrown on assertion failure.
