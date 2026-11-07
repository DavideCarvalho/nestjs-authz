---
name: authz-policies
description: >
  Write policies for @dudousxd/nestjs-authz 0.9: they are official @nestjs/authorization
  policies (@Policy(), abilities taking `user | null`, optional before(), only a literal true
  allows). Our additions: @PolicyFor(Resource) to link a resource to its policy (for
  gate.allows('update', post), gate.scope(Post), client ability maps), the AuthzPolicy base
  class / superAdminBefore() that honor the global superAdmin hook, and a scope(user) method
  for query scoping. Covers migrating the 0.8 @Policy(Resource).
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.9.0"
  framework: nestjs
---

# Writing policies

```ts
import { Policy } from '@nestjs/authorization';
import { AuthzPolicy, PolicyFor, eq } from '@dudousxd/nestjs-authz';

@Policy()
@PolicyFor(Post)                            // optional link; also applies @Policy() itself
export class PostPolicy extends AuthzPolicy { // optional: superAdmin grants every ability
  update(user: User | null, post: Post) {
    return post.authorId === user?.id;
  }
  create(user: User | null) {
    return user?.verified === true;           // no record: a class-level ability
  }
  scope(user: User) {
    return eq('authorId', user.id);           // not an ability; used by gate.scope(Post)
  }
}
```

## Core patterns

- Abilities are the official contract: `ability(user | null, ...args)`, `true` allows,
  anything else denies. A guest denial is a 401, a signed-in one a 403.
- `AuthzPolicy.before()` asks `superAdmin(user, ability, resource)`, then the
  `DECISION_PROVIDER` when one is registered (its allow/deny is final; `undefined` abstains).
  Own `before()`: override and call `super.before(user, ability, ...args)` first to keep both.
  Policies that cannot extend `AuthzPolicy` call `superAdminBefore(user, ability, resource)`
  and `decisionProviderBefore(user, ability, resource)`.
- A persisted permission named like an ability does not bypass the policy: the policy has the
  final word.
- Policies must be singletons (official rule).

## Common mistakes

### 1. Typing the user as `User`

```ts
update(user: User, post: Post) {}          // Wrong — guests reach it as null; @Can rejects it
update(user: User | null, post: Post) {}   // Correct
```

### 2. Returning `{ allowed, message }` or a truthy value

0.x accepted `PolicyResponse`. The official evaluator allows only a literal `true`; a
truthy object denies. Return booleans.

### 3. Expecting superAdmin everywhere

The official guard runs only the policy's own `before()`. A policy that does not extend
`AuthzPolicy` (or call `superAdminBefore`) never sees superAdmin on routes.

### 4. Writing the 0.8 `@Policy(Post)`

0.9 removed it: this package no longer exports `Policy`. Use the official `@Policy()` from
`@nestjs/authorization` plus `@PolicyFor(Post)` (or `@PolicyFor(Post)` alone, which applies
`@Policy()` itself).

Source: `packages/core/src/links.ts`, `packages/core/src/policies/authz-policy.ts`.
