---
name: authz-setup
description: >
  Set up @dudousxd/nestjs-authz 1.x, the extras on top of NestJS's first-party
  @nestjs/authorization. Import AuthorizationModule.forRoot() (official: global
  deny-by-default AuthorizationGuard, @Can, AuthorizationService, getUser) next to
  AuthzModule.forRoot / forRootAsync (ours: Gate, RolePolicy / PermissionPolicy /
  GatePolicy, the ResourceResolver byId() uses, superAdmin, the allow+deny decision event,
  the opt-in POST /authz/can endpoint). Covers the optional peers: @nestjs/authentication
  (AuthenticationContext.user is the ambient Gate user) and @dudousxd/nestjs-context
  (fallback ambient user via resolveUser, per-request permission cache, tenant).
metadata:
  type: core
  library: "@dudousxd/nestjs-authz"
  library_version: "1.0.0"
  framework: nestjs
---

# Setting up @dudousxd/nestjs-authz

Authorization decisions belong to [`@nestjs/authorization`](https://docs.nestjs.com/security/authorization).
This package adds RBAC, `@Can` helpers, a service-layer `Gate`, super-admin, query scopes and
frontend glue. It never authenticates.

## Setup

```sh
pnpm add @nestjs/authorization @dudousxd/nestjs-authz
```

NestJS 12, Node 22+. Peers: `@nestjs/common`, `@nestjs/core`, `@nestjs/authorization`,
`reflect-metadata`, `rxjs`; optional `@nestjs/authentication` and `@dudousxd/nestjs-context`.

```ts
import { AuthorizationModule } from '@nestjs/authorization';
import { AuthzModule } from '@dudousxd/nestjs-authz';

@Module({
  imports: [
    AuthorizationModule.forRoot({ getUser: (ctx) => ctx.switchToHttp().getRequest().user }),
    AuthzModule.forRoot({
      superAdmin: (user) => user?.isRoot === true,
      resourceResolver: new OrmResourceResolver(), // for byId(); default builds { id } from :id
    }),
  ],
  providers: [PostPolicy], // official policies are discovered wherever they are providers
})
export class AppModule {}
```

`forRootAsync({ imports, inject, useFactory | useClass | useExisting, canEndpoint })` takes the
same options. `canEndpoint` is static (controllers register before the factory runs).

## Core patterns

- The official module must stay global (its default): the `Gate` injects `AuthorizationService`.
- `getUser` is the only user on routes. The `Gate`'s ambient user (calls without `forUser`) is
  `@nestjs/authentication`'s `AuthenticationContext.user` when that package is installed and
  has one, else nestjs-context's `{ type, id }` ref, hydrated by `resolveUser` once per request.
- Every route needs a declaration: the official guard denies a handler with no `@Can()`,
  `@Can.Anyone()` or `@Public()`.

## Common mistakes

### 1. Importing only AuthzModule

```ts
// Wrong — no AuthorizationService for the Gate, no guard on routes.
imports: [AuthzModule.forRoot()]

// Correct
imports: [AuthorizationModule.forRoot(), AuthzModule.forRoot()]
```

### 2. Passing policies to AuthzModule

```ts
// Wrong (0.x) — `policies` is gone from AuthzModuleOptions.
AuthzModule.forRoot({ policies: [PostPolicy] })

// Correct — register them as providers, or with the official module.
AuthorizationModule.forRoot({ policies: [PostPolicy] })
```

### 3. Leaving routes undeclared after upgrading from 0.x

0.x let un-annotated routes through. The official guard denies them (401 for guests, 403
otherwise). Add `@Can.Anyone()` to routes anyone may call.

Source: `packages/core/src/module.ts`, `packages/core/src/runtime.ts`.
