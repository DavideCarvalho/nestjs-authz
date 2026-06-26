---
name: authz-enforcement
description: >
  Enforce authorization in @dudousxd/nestjs-authz with the @Can and @Roles guards and the
  programmatic Gate. @Can('update', Post) resolves a Post instance via the ResourceResolver
  and runs PostPolicy.update; @Can('create', Post, { classLevel: true }) skips loading;
  @Can('access-admin') hits an ad-hoc gate. @Roles('admin','teacher') is the coarse role
  check. Both guards are auto-registered as APP_GUARD and are inert on un-annotated routes.
  Covers the ResourceResolver seam (default IdParamResourceResolver reads :id vs a real ORM
  resolver bound to RESOURCE_RESOLVER) and the Gate API: authorize/allows/denies/allowsMany,
  forUser(user) BoundGate, define(ability, fn), hasRole/hasAnyRole.
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.6.3"
  framework: nestjs
---

# Enforcing authorization

Two paths: **declarative** guards (`@Can`, `@Roles`) and the **programmatic** `Gate`.
Both guards are registered as `APP_GUARD` by `AuthzModule.forRoot`, and both are **inert**
on routes without their decorator (no metadata → allow).

## Setup

```ts
import { Controller, Param, Patch, Post as HttpPost } from '@nestjs/common';
import { Can, Roles } from '@dudousxd/nestjs-authz';
import { Post } from './post.entity';

@Controller('posts')
export class PostController {
  @Patch(':id')
  @Can('update', Post) // load Post by :id, run PostPolicy.update(currentUser, post)
  update(@Param('id') id: string) {}

  @HttpPost()
  @Can('create', Post, { classLevel: true }) // run PostPolicy.create(currentUser) — no instance
  create() {}

  @HttpPost('purge')
  @Roles('admin', 'teacher') // allow if the user holds ANY of these roles
  purge() {}
}
```

## Core patterns

### Programmatic Gate

Inject `Gate` for checks inside services. `authorize` throws `ForbiddenException` on deny;
`allows`/`denies` return a boolean.

```ts
import { Injectable } from '@nestjs/common';
import { Gate } from '@dudousxd/nestjs-authz';

@Injectable()
export class PostService {
  constructor(private readonly gate: Gate) {}

  async update(post: Post) {
    await this.gate.authorize('update', post);        // throws on deny
    if (await this.gate.allows('delete', post)) { /* ... */ }
  }
}
```

`forUser(user)` returns a `BoundGate` that bypasses the context accessor — use it when no
nestjs-context is wired, or to check a user other than the current one:

```ts
await this.gate.forUser(someUser).authorize('update', post);
```

`allowsMany` batch-checks one user in a single pass (resolves the user once, shares a
permission cache — kills the N+1 on a list page):

```ts
const results = await this.gate.allowsMany([
  { ability: 'update', resource: post },
  { ability: 'delete', resource: post },
]); // → [{ ability:'update', resource, allowed }, ...] (order preserved)
```

### Ad-hoc gates

Register a model-less, named ability with `define`, then guard or check it:

```ts
this.gate.define('access-admin', (user) => (user as User).role === 'staff');
await this.gate.allows('access-admin');   // programmatic
// @Can('access-admin')                    // declarative (no resource class)
```

### Custom ResourceResolver

`@Can('update', Post)` needs an instance. The default `IdParamResourceResolver` builds a
`{ id }` shim from the route `:id`. For real entities, implement `ResourceResolver` and
bind `RESOURCE_RESOLVER` (or pass `resourceResolver` to `forRoot`):

```ts
import type { ResourceResolver } from '@dudousxd/nestjs-authz';
import { RESOURCE_RESOLVER } from '@dudousxd/nestjs-authz';
import type { ExecutionContext, Type } from '@nestjs/common';

class OrmResourceResolver implements ResourceResolver {
  async resolve(resource: Type<unknown>, ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<{ params: { id: string } }>();
    return this.repos.get(resource).findOneBy({ id: Number(req.params.id) });
  }
}
// provide: { provide: RESOURCE_RESOLVER, useClass: OrmResourceResolver }
```

## Common mistakes

### 1. Class-level ability without `{ classLevel: true }`

```ts
// Wrong — the guard tries to LOAD a Post (by :id) for a creation route that has none,
// so the resolver returns undefined and the request is denied.
@HttpPost()
@Can('create', Post)
create() {}

// Correct — flag it class-level so the guard skips resource loading.
@HttpPost()
@Can('create', Post, { classLevel: true })
create() {}
```

Mechanism: with a `resource` and no `classLevel`, the guard loads an instance via the
resolver; a `undefined` instance is treated as not-found → deny.
Source: `packages/core/src/guard/can.guard.ts` (`canActivate`), `packages/core/src/decorator/can.decorator.ts`.

### 2. Using the default resolver and expecting real entity fields

```ts
// Wrong — IdParamResourceResolver only sets `{ id }`; `post.authorId` is undefined,
// so an ownership policy reading post.authorId can never match.
AuthzModule.forRoot({ policies: [PostPolicy] });

// Correct — register an ORM-backed resolver so the policy receives a hydrated row.
AuthzModule.forRoot({ policies: [PostPolicy], resourceResolver: new OrmResourceResolver(...) });
```

Mechanism: the default resolver produces a `Object.create(resource.prototype)` shim with
only `id` set (enough for `instance.constructor` matching, not for column reads).
Source: `packages/core/src/resource-resolver.ts` (`IdParamResourceResolver`).

### 3. Ambiguous class-level ability across multiple policies

```ts
// Wrong — both PostPolicy and CommentPolicy define create(); with no resource the Gate
// cannot tell which to run and throws AmbiguousAbilityException.
await this.gate.allows('create');

// Correct — pass the resource class so the Gate selects the right policy.
await this.gate.allows('create', Post);                 // programmatic
// @Can('create', Post, { classLevel: true })            // declarative
```

Mechanism: with no resource the Gate scans all policies for the method; >1 match is an
ambiguous (arbitrary) choice, so it throws instead of guessing.
Source: `packages/core/src/gate.ts` (`resolvePolicy`, `AmbiguousAbilityException`).
