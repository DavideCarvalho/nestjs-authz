---
name: authz-query-scopes
description: >
  Filter collections to the rows a user may access with @dudousxd/nestjs-authz query
  scopes — the accessibleBy / Pundit policy_scope / Cerbos query-plan concept. gate.scope(
  Entity, ability='viewAny') returns an ORM-neutral ScopeConstraint AST built from scopeAll
  / scopeNone and the where(field, op, value) / eq(field, value) / and(...) / or(...)
  helpers (operators eq, ne, gt, gte, lt, lte, in, nin, isNull, isNotNull). A @Policy scope(
  user, Entity) method produces it (returning true=allow-all, false/nullish=deny-all sugar);
  an ORM adapter such as @dudousxd/nestjs-authz-typeorm's applyScope / applyScopeConstraint
  compiles it to a parameterized, identifier-safe WHERE. Mirrors the Gate's grant order:
  super-admin / permission-provider grant → allow-all; anonymous / no scope → deny-all.
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.6.3"
  framework: nestjs
---

# Query scopes (filtering collections)

A policy **method** decides yes/no for ONE resource. A policy **scope** produces a
constraint that filters a COLLECTION at the DB layer — instead of over-fetch-then-filter.
This is the `accessibleBy` / Pundit `policy_scope` / Cerbos query-plan idea, represented
as a small, serializable condition AST (`ScopeConstraint`).

## Setup

Add a `scope(user, Entity)` method to a `@Policy` class, returning a `ScopeConstraint`
built from the core helpers:

```ts
import { Policy, eq, and, where, scopeAll } from '@dudousxd/nestjs-authz';
import { Post } from './post.entity';
import { User } from './user.entity';

@Policy(Post)
export class PostPolicy {
  scope(user: User, _entity: typeof Post) {
    if (user.isAdmin) return scopeAll;                 // sugar: every row
    // editors see published OR their own posts:
    return and(
      eq('tenantId', user.tenantId),
      where('authorId', 'eq', user.id),
    );
  }
}
```

Resolve it for the current (context) user and apply it with an adapter:

```ts
import { Gate } from '@dudousxd/nestjs-authz';
import { applyScopeConstraint, applyScope } from '@dudousxd/nestjs-authz-typeorm';

const constraint = await this.gate.scope(Post);        // ScopeConstraint (ability defaults to 'viewAny')
const qb = repo.createQueryBuilder('post');
applyScopeConstraint(qb, constraint);                  // adds a parameterized WHERE
const posts = await qb.getMany();

// or fold both steps for the current user:
await applyScope(qb, this.gate, Post);
```

## Core patterns

### The constraint vocabulary

- `scopeAll` (`{ kind: 'all' }`) — every row; no WHERE added.
- `scopeNone` (`{ kind: 'none' }`) — no rows; an always-false predicate.
- `where(field, op, value)` / `eq(field, value)` — a leaf condition. Operators: `eq`,
  `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`, `isNull`, `isNotNull`.
- `and(...nodes)` / `or(...nodes)` — boolean groups. Empty `and()` → allow-all; empty
  `or()` → deny-all; a single node is returned as-is.

### Grant order mirrors the single-resource Gate

`gate.scope` resolves consistently with `gate.allows`: a `superAdmin` grant or a
permission-provider grant for the ability → `scopeAll`; an anonymous user, or no
`scope`/`viewAny` method → `scopeNone`; otherwise the policy's `scope` constraint. A
policy `before` returning `true`/`false` scopes to allow-all/deny-all too.

### Return-value sugar

A `scope` method may return `true` (→ `scopeAll`), `false`/`null`/`undefined` (→
`scopeNone`), or a `ScopeConstraint`. `normalizeScope` handles the coercion.

## Common mistakes

### 1. Hand-filtering after fetching instead of scoping the query

```ts
// Wrong — loads every row then filters in memory: leaks counts, paginates wrong, slow.
const all = await repo.find();
const visible = all.filter((p) => p.authorId === user.id);

// Correct — push the constraint into the SQL WHERE.
const qb = repo.createQueryBuilder('post');
await applyScope(qb, this.gate, Post);
const visible = await qb.getMany();
```

Mechanism: `gate.scope` returns a pure-data AST the adapter compiles to a parameterized
WHERE, so the DB does the filtering and pagination/counts stay correct.
Source: `packages/core/src/scope.ts` (`ScopeConstraint`), `packages/typeorm/src/scope.ts`
(`applyScope` / `applyScopeConstraint`).

### 2. Interpolating user input into a field name

```ts
// Wrong — concatenating a dynamic column name risks SQL injection and is rejected.
return where(`${userSuppliedColumn}` as string, 'eq', value);

// Correct — use known, static field names; values are always bound parameters.
return eq('authorId', user.id);
```

Mechanism: adapters validate every interpolated identifier against `SAFE_IDENTIFIER`
(`/^[A-Za-z_][A-Za-z0-9_]*$/`) and **bind** values as parameters — never concatenate them.
Source: `packages/core/src/scope.ts` (`SAFE_IDENTIFIER`, `assertSafeIdentifier`,
`ScopeCondition` "value is bound as a parameter").

### 3. Returning `undefined` from a scope and expecting "all rows"

```ts
// Wrong — a nullish return is deny-all (no rows), not allow-all.
scope(user: User) {
  if (user.isAdmin) return; // oops
}

// Correct — be explicit; nullish/false = deny-all, true/scopeAll = allow-all.
scope(user: User) {
  return user.isAdmin ? scopeAll : eq('authorId', user.id);
}
```

Mechanism: `normalizeScope` maps `null`/`undefined`/`false` to `scopeNone` (default-deny),
consistent with the Gate's deny-by-default posture.
Source: `packages/core/src/scope.ts` (`normalizeScope`, `ScopeResult`).
