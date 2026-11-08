---
name: authz-enforcement
description: >
  Enforce authorization with @dudousxd/nestjs-authz 0.9 on top of @nestjs/authorization.
  Routes use the official @Can(Policy, 'ability', argsResolver) and its global guard; our
  helpers go inside it: byId(Post) (loads the :id record with the ResourceResolver, kept for
  the handler via authorizedResource), roles(), permission(), ability(), staticCanArgs()
  (static, marked with Symbol.for('@dudousxd/static-can-args')), and the sugar @Roles /
  @Permission. Services use the Gate: allows/denies/authorize with a policy class or a string
  ability, allowsMany, forUser, define, hasRole. Covers migrating the 0.8 string @Can.
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.9.0"
  framework: nestjs
---

# Enforcing authorization

## Routes

```ts
import { Can } from '@nestjs/authorization';
import { GatePolicy, PermissionPolicy, Roles, ability, authorizedResource, byId, permission } from '@dudousxd/nestjs-authz';

@Patch(':id')
@Can(PostPolicy, 'update', byId(Post))            // 403 if the Post is not found
update(@Req() req: Request) {
  const post = authorizedResource(req, Post);       // the record byId loaded
}

@Post(':id/publish')
@Can(PermissionPolicy, 'has', permission('posts.publish')) // or @Permission('posts.publish')
publish() {}

@Get('admin')
@Roles('admin', 'editor')                           // any of; RolePolicy.hasAll for all of
admin() {}

@Get('reports')
@Can(GatePolicy, 'allows', ability('access-admin')) // a gate.define() gate
reports() {}

@Get('me')
@Can.Anyone()                                       // the official way to open a route
me() {}
```

Class-level and method-level requirements all apply (AND); a method's `Can.Anyone()` lifts the
class's. Argument resolvers run in the guard, before pipes, with no DI: `byId` reads the
`ResourceResolver` `AuthzModule` registered at boot.

## Services

```ts
await gate.forUser(user).authorize(PostPolicy, 'update', post); // = AuthorizationService.authorize
await gate.forUser(user).allows('update', post);                // policy linked with @PolicyFor(Post)
await gate.forUser(user).allows('posts.publish');               // persisted permission
await gate.forUser(user).allowsMany([{ ability: 'update', resource: post }]);
gate.define('access-admin', (user) => user.isStaff);
```

String abilities ask, in order: `superAdmin` (it receives the resource too), the external
decision point (`DECISION_PROVIDER`, e.g. the Cerbos adapter — its allow or deny is final,
`undefined` abstains), the linked policy (official evaluation), the persisted permissions,
the ad-hoc gate; else `AbilityNotResolvedException`. The policy has the final word: a
persisted permission named like one of its abilities (`update`) does not bypass it — only
`superAdmin` short-circuits a policy. `authorize()` throws the official `AuthorizationError`.

Without `forUser()`, the user is `@nestjs/authentication`'s `AuthenticationContext.user`
when that package is installed and its scope is active for the call (its answer is final,
so an anonymous call there is a guest), else nestjs-context's user ref
(hydrated once per request by `resolveUser`), else a guest.

Inside a nestjs-context request, every check shares one `resolveUser`, one permission fetch
and one role fetch per user for the whole request — the official guard's `RolePolicy` /
`PermissionPolicy` and the handler's `Gate` calls alike (keyed by the row the user names —
its class or `type` plus `id`; a plain object without `type` is keyed by identity, so two
users that only share an `id` never share an entry). `allowsMany` shares one fetch per
batch even without nestjs-context, and asks a `DECISION_PROVIDER`'s `decideMany` once.

## Common mistakes

### 1. Writing the 0.8 string form

0.9 removed it: `@Can` comes from `@nestjs/authorization` and names the policy.

| 0.8 | 0.9 |
| --- | --- |
| `@Can('update', Post)` | `@Can(PostPolicy, 'update', byId(Post))` |
| `@Can('create', Post, { classLevel: true })` | `@Can(PostPolicy, 'create')` |
| `@Can('access-admin')` | `@Can(GatePolicy, 'allows', ability('access-admin'))` |

### 2. Loading the record again in the handler

Read it with `authorizedResource(req, Post)`.

### 3. Writing an inline resolver for constant args

`@Can(FlagPolicy, 'on', () => ['billing'])` works, but tools cannot read it without a call.
Use `staticCanArgs('billing')`.

Source: `packages/core/src/helpers.ts`, `packages/core/src/gate.ts`, `packages/core/src/decorator/roles.decorator.ts`.
