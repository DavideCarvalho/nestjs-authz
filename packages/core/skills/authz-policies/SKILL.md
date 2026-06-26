---
name: authz-policies
description: >
  Write authorization policies for @dudousxd/nestjs-authz the Laravel way. Use the
  @Policy(Resource) decorator to map a class to a resource; its methods are abilities
  dispatched by name (view/update/create...) receiving (user, resource). Covers the
  optional before(user, ability) short-circuit hook (true=allow, false=deny,
  undefined=fall through), class-level abilities that omit the resource, returning a
  deny message via PolicyResponse ({ allowed, message }) instead of a bare boolean, and
  the global superAdmin / after hooks with their override semantics (after can only fill
  in when the policy returned nullish; default-deny on no opinion).
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.6.3"
  framework: nestjs
---

# Writing policies

A **policy** is a class decorated with `@Policy(Resource)`. Its methods are **abilities**
dispatched by name: `update(user, post)` answers `gate.authorize('update', post)` and
`@Can('update', Post)`.

## Setup

```ts
import { Policy } from '@dudousxd/nestjs-authz';
import { Post } from './post.entity';
import { User } from './user.entity';

@Policy(Post)
export class PostPolicy {
  // before runs first for any ability this policy defines:
  //   true → allow (short-circuit), false → deny (short-circuit), undefined → fall through
  before(user: User, ability: string) {
    if (user.isAdmin) return true;
  }

  view(user: User, post: Post) {
    return post.published || post.authorId === user.id;
  }

  update(user: User, post: Post) {
    return post.authorId === user.id;
  }

  // class-level ability: no resource instance — receives only the user
  create(user: User) {
    return user.verified;
  }
}
```

`@Policy` also makes the class `@Injectable()`, so it is auto-discovered from the Nest
container (you do not have to list it in `policies: []`, though you may). Register it via
`AuthzModule.forRoot({ policies: [PostPolicy] })` or rely on auto-discovery.

## Core patterns

### Deny messages with PolicyResponse

Return `{ allowed, message }` instead of a bare boolean to surface a reason. The message
rides the thrown `ForbiddenException` body and the diagnostics decision.

```ts
update(user: User, post: Post) {
  if (post.locked) return { allowed: false, message: 'Post is locked' };
  return post.authorId === user.id;
}
```

### Global superAdmin and after hooks

Configured on the module, not the policy. `superAdmin` runs **before** any policy/gate;
truthy grants. `after` (Laravel `Gate::after`) runs **after** resolution:

```ts
AuthzModule.forRoot({
  superAdmin: (user, ability) => (user as User).role === 'root', // truthy → allow
  after: (user, ability, result) => {
    // result is the policy/gate verdict, or undefined when it had "no opinion".
    if (result === undefined) return ability.startsWith('public.'); // only fills in a gap
  },
});
```

### Inheritance

A subclass of a `@Policy`-decorated class still resolves the inherited resource
(`getPolicyResource` uses `getMetadata`, walking the prototype chain), so you can share a
base policy and override individual ability methods.

## Common mistakes

### 1. Falling off the end of a policy method (implicit deny)

```ts
// Wrong — no return on the non-owner branch yields `undefined` = "no opinion" = DENY,
// even for a published post you meant to allow.
view(user: User, post: Post) {
  if (post.authorId === user.id) return true;
}

// Correct — return an explicit boolean for every path.
view(user: User, post: Post) {
  return post.published || post.authorId === user.id;
}
```

Mechanism: a nullish policy return is normalized to `allowed: undefined`, which
default-denies in `resolve` (after giving an `after` hook a chance).
Source: `packages/core/src/gate.ts` (`resolveBase` / `resolve`, `normalizeResult`).

### 2. Putting a `before` grant for an ability the policy does not define

```ts
// Wrong — `before` grants 'publish', but there is no publish() method, so the ability
// is unresolved and throws AbilityNotResolvedException instead of being allowed.
@Policy(Post)
class PostPolicy {
  before(user: User, ability: string) { if (ability === 'publish') return true; }
}

// Correct — define the method; `before` may then short-circuit it.
@Policy(Post)
class PostPolicy {
  before(user: User, ability: string) { if (ability === 'publish') return true; }
  publish(user: User, post: Post) { return post.authorId === user.id; }
}
```

Mechanism: the Gate gates the `before` hook on method existence FIRST — a `before` cannot
answer an ability the policy never declared.
Source: `packages/core/src/gate.ts` (`resolveBase`, "gate it on method existence FIRST").

### 3. Expecting `after` to overturn an explicit policy verdict

```ts
// Wrong — the policy already returned `false`; `after` is observe-only here and its
// return is ignored, so this does NOT re-grant access.
after: (user, ability, result) => true;

// Correct — `after` can only supply a verdict when the policy/gate had no opinion.
after: (user, ability, result) => (result === undefined ? true : undefined);
```

Mechanism: `after` overrides ONLY when `result === undefined` (the base produced no
explicit verdict); when the policy decided, `after` is purely an observer.
Source: `packages/core/src/types.ts` (`AfterHook` docs), `packages/core/src/gate.ts` (`resolve`).
