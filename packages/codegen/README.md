# @dudousxd/nestjs-authz-codegen

A [`@dudousxd/nestjs-codegen`](https://www.npmjs.com/package/@dudousxd/nestjs-codegen) **extension**
that discovers the authorization abilities declared with
[`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz)'s
`@Can(ability, Resource?)` (and, optionally, `@Policy` method abilities) and emits a typed `can()`
helper into your generated `api.ts` — so checking a permission on the frontend is a compile-time
type, not a magic string.

The discovered abilities become a string-literal union (`AuthzAbility`). Calling `can()` with an
ability that doesn't exist on the server is a **type error**.

```bash
pnpm add -D @dudousxd/nestjs-authz-codegen
```

```ts title="nestjs-codegen.config.ts"
import { defineConfig } from '@dudousxd/nestjs-codegen';
import { zodAdapter } from '@dudousxd/nestjs-codegen-zod';
import { nestjsAuthzCodegen } from '@dudousxd/nestjs-authz-codegen';

export default defineConfig({
  validation: zodAdapter,
  extensions: [
    nestjsAuthzCodegen({ endpoint: '/authz/can' }),
    // ...other extensions (tanstack, filter, notifications)
  ],
});
```

## What it emits

Given controllers decorated with `@Can(...)`:

```ts
@Controller('posts')
export class PostsController {
  @Patch(':id')
  @Can('update', Post)
  update() {}

  @Post(':id/publish')
  @Can('access-admin')
  publish() {}
}
```

the generated `api.ts` gains:

```ts
/** Every authorization ability discovered from `@Can`/`@Policy` in your NestJS app. */
export type AuthzAbility = 'update' | 'access-admin';

/** Map of resource class name → the abilities declared against it. */
export const authzAbilities = { Post: ['update'] } as const;

/** Ask the server whether the current user `can` perform `ability`. */
export async function can(
  ability: AuthzAbility,
  resource?: { type: string; id?: string | number } | null,
  init?: RequestInit,
): Promise<boolean> {
  /* POSTs { ability, resource } to '/authz/can', returns the server's `allowed` boolean */
}
```

```ts
await can('update', { type: 'Post', id: 42 }); // ✅
await can('destroy'); // ✗ type error — 'destroy' is not an AuthzAbility
```

Routes carrying a `@Can` also expose a route-pinned `can()` handle member when a client layer
(e.g. TanStack) is active: `api.posts.update.can({ type: 'Post', id: 42 })`.

## Server side

> **Per-instance decisions must be hydrated, not fetched.** The fetch fallback (`POST /authz/can`)
> only resolves **class-level abilities and ad-hoc gates** — the `{ type, id }` resource shim it
> sends never matches a `@Policy` by constructor. A **resource-bound** ability
> (`can('update', { type: 'Post', id })`) that misses the hydrated cache and falls through to the
> endpoint will **deny** (and logs a one-time `console.warn`). Hydrate per-instance decisions via
> shared props / `authorizeResource` (tiers 1-2 of `@dudousxd/nestjs-authz-inertia`) instead.

The runtime `can()` POSTs `{ ability, resource? }` to the configured `endpoint` and expects
`{ allowed: boolean }` back. Expose a tiny controller in your NestJS app that delegates to the
`Gate`:

```ts
@Post('authz/can')
async can(@Body() body: { ability: string; resource?: { type: string; id?: string } | null }) {
  return { allowed: await this.gate.allows(body.ability, body.resource ?? undefined) };
}
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `endpoint` | `'/authz/can'` | Server endpoint the generated `can()` POSTs to (expects `{ allowed }`). |
| `discoverPolicies` | `true` | Also treat `@Policy(Resource)` method names as class-level abilities. |

## Caveats

Decorators are discovered by their **canonical names** — import `@Can` / `@Policy` under their real
names. An aliased import (`import { Can as Authorize } from '@dudousxd/nestjs-authz'`) is NOT
discovered, because codegen matches the decorator identifier (`Can` / `Policy`) syntactically and
does not resolve aliases.
