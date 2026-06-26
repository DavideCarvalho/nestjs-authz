---
name: authz-setup
description: >
  Set up @dudousxd/nestjs-authz in a NestJS app — install, peer deps, and wire
  AuthzModule.forRoot / forRootAsync (global module that registers the Gate,
  CanGuard + RolesGuard as APP_GUARD, PolicyRegistry, default IdParamResourceResolver,
  and the opt-in POST /authz/can endpoint). Covers the optional @dudousxd/nestjs-context
  peer (CONTEXT_ACCESSOR) for the current user, and the load-bearing resolveUser hook
  that hydrates the full user entity from a UserRef ({type,id}) so superAdmin and
  policy checks like user.isAdmin / post.authorId === user.id actually see real columns.
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "0.6.3"
  framework: nestjs
---

# Setting up @dudousxd/nestjs-authz

`@dudousxd/nestjs-authz` is **authorization, not authentication**: it reads the
current user and decides what they may do, Laravel Gate/Policy style. The core has
**zero database** dependencies.

## Setup

```sh
pnpm add @dudousxd/nestjs-authz
```

Peer deps: `@nestjs/common`, `@nestjs/core`, `reflect-metadata`.
`@dudousxd/nestjs-context` is an **optional** peer — when present the Gate reads the
current user for free; when absent you pass the user explicitly via `gate.forUser(...)`.

Register the module once (it is `global: true`, so every module sees the `Gate` and the
guards):

```ts
import { Module } from '@nestjs/common';
import { AuthzModule } from '@dudousxd/nestjs-authz';
import { PostPolicy } from './post.policy';

@Module({
  imports: [
    AuthzModule.forRoot({
      policies: [PostPolicy], // optional — @Policy classes are also auto-discovered
      superAdmin: (user) => (user as { isAdmin?: boolean }).isAdmin === true,
    }),
  ],
})
export class AppModule {}
```

`forRoot` registers: `Gate`, `PolicyRegistry`, `CanGuard` **and** `RolesGuard` (both as
`APP_GUARD`, so `@Can` / `@Roles` enforce app-wide), a default `IdParamResourceResolver`
bound to `RESOURCE_RESOLVER`, and a bootstrap provider that fills the `PolicyRegistry` on
init from `policies: []` **and** auto-discovered `@Policy` providers.

## Core patterns

### forRootAsync (config from DI)

Use when policy lists or hooks depend on injected config. Policies returned from the
factory are registered too (the bootstrap reads the **resolved** options).

```ts
AuthzModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    policies: [PostPolicy],
    superAdmin: (user) => (user as { role?: string }).role === config.get('SUPER_ROLE'),
  }),
});
```

`canEndpoint` and `resourceLoaders` may be declared **statically** on the async options
too (controllers are registered at module-definition time, before the factory resolves).

### Wiring the current user via nestjs-context

The Gate resolves the current user structurally through the well-known capability token
`CONTEXT_ACCESSOR` (`capability('context','accessor')` ===
`Symbol.for('@dudousxd/nestjs-context:accessor')`). Install and configure
`@dudousxd/nestjs-context` so requests carry a user; the Gate then needs no wiring. With
**no** accessor and no explicit user, checks treat the request as anonymous and **deny**.

### resolveUser — hydrate the real entity (the critical hook)

On the **context path**, the value handed to `superAdmin`, `after`, `resolveRoles`, and
your policy methods is the raw **`UserRef`** (`{ type, id }`) from nestjs-context — **not**
your hydrated user row. Provide `resolveUser` to load the entity before those run:

```ts
AuthzModule.forRoot({
  resolveUser: (ref) => userRepo.findOneBy({ id: Number(ref.id) }), // ref: { type, id }
  superAdmin: (user) => (user as User).isAdmin, // now sees a real column
});
```

`resolveUser` returning nullish is treated as "no user" (deny). It is **only** applied on
the context path — `gate.forUser(entity)` always uses the value you pass verbatim.

## Common mistakes

### 1. Expecting `superAdmin: u => u.isAdmin` to work without `resolveUser`

```ts
// Wrong — on the context path `user` is just { type, id }; `isAdmin` is undefined,
// so the super-admin grant never fires from a route or gate.allows(...).
AuthzModule.forRoot({ superAdmin: (u) => (u as User).isAdmin });

// Correct — hydrate the entity first.
AuthzModule.forRoot({
  resolveUser: (ref) => userRepo.findOneBy({ id: Number(ref.id) }),
  superAdmin: (u) => (u as User).isAdmin,
});
```

Mechanism: the context accessor yields only a `UserRef` (`{ type, id }`); `resolveUser`
is the hook that turns that ref into your `User` entity before hooks/policies run.
Source: `packages/core/src/types.ts` (`AuthzModuleOptions.superAdmin` / `resolveUser` docs),
`packages/core/src/gate.ts` (`currentUser`).

### 2. Importing AuthzModule in every feature module

```ts
// Wrong — forRoot is global; re-importing creates duplicate providers/options.
@Module({ imports: [AuthzModule.forRoot({ policies: [PostPolicy] })] })
export class PostsModule {}

// Correct — register once in the root module; the Gate is exported globally.
@Module({ imports: [AuthzModule.forRoot({ policies: [PostPolicy] })] })
export class AppModule {}
```

Mechanism: `forRoot`/`forRootAsync` return `{ global: true }`, so a single root
registration exports `Gate`, the guards, and `RESOURCE_RESOLVER` to the whole app.
Source: `packages/core/src/module.ts` (`forRoot` returns `global: true`).

### 3. Reaching for the `canEndpoint` before it is enabled

```ts
// Wrong — POST /authz/can returns 404; the endpoint is OFF by default.
AuthzModule.forRoot({ policies: [PostPolicy] });

// Correct — opt in (true = default path 'authz/can', or pass a custom string).
AuthzModule.forRoot({ policies: [PostPolicy], canEndpoint: true });
```

Mechanism: `canControllers` registers the fallback controller only when `canEndpoint` is
truthy; it is the last-resort path for abilities not already hydrated on the client.
Source: `packages/core/src/module.ts` (`canControllers`), `packages/core/src/types.ts`
(`canEndpoint`).
