# @dudousxd/nestjs-authz-client

Framework-neutral, in-memory ability store + `can()` resolver for
[`@dudousxd/nestjs-authz`](../core). Hydrate a user's decisions once (from Inertia
shared props, a JSON island, or any source) and answer client-side `can(...)` checks
**synchronously, with no network request**.

No dependency on React/Vue/NestJS/Inertia — it is pure TypeScript plus an injectable
`fetch`. The `-react` and `-inertia` packages, and the codegen client, all reuse it.

```ts
import {
  AbilityStore,
  hydrateFromInertiaProps,
  hydrateResource,
  createCan,
} from '@dudousxd/nestjs-authz-client';

const store = new AbilityStore();
hydrateFromInertiaProps(store, pageProps); // reads props.auth.can
hydrateResource(store, { type: 'Post', id: post.id }, post.can); // per-instance map

const can = createCan(store);
can('post.create'); // → boolean, synchronously, no fetch
can('update', { type: 'Post', id: post.id }); // → boolean
```

## Fallback on a cache miss

When an ability/resource is not hydrated, `createCan` behaves per `fallback`:

- `'deny'` (default) — returns `false` synchronously.
- `'fetch'` — `POST { ability, resource }` to `endpoint` (default `'/authz/can'`)
  and returns a `Promise<boolean>` from the server's `{ allowed }`.

```ts
const can = createCan(store, { fallback: 'fetch', endpoint: '/authz/can' });
const allowed = can('rare.ability'); // boolean (hit) | Promise<boolean> (miss → fetch)
```

## API

- `AbilityStore` — `setClassAbilities` / `mergeClassAbilities` / `setResourceAbilities` /
  `has` / `peek` / `clear`.
- `hydrateFromInertiaProps(store, props, propKey?)`
- `hydrateResource(store, ref, can)`
- `createCan(store, options?)` → `CanResolver`
