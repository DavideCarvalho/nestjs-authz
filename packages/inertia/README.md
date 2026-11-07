# @dudousxd/nestjs-authz-inertia

Inertia.js integration for [`@dudousxd/nestjs-authz`](../core). It makes client-side
`can(...)` checks resolve **without a network request** by sharing the current
user's abilities as Inertia props — the Laravel/Inertia model.

```bash
pnpm add @dudousxd/nestjs-authz-inertia
# peers: @dudousxd/nestjs-authz, @dudousxd/nestjs-inertia
#        (optional) @dudousxd/nestjs-context
```

## The 3-tier model — prefer props → resource map → endpoint fallback

Authorization decisions reach the front end through three tiers. Prefer the earlier
(no-request) tiers; the endpoint is a last resort.

### Tier 1 — Shared props (no request)

Every Inertia render carries the user's **class-level abilities** (all ad-hoc gates + the
abilities of every official `@Policy()` that take no record, like `create`/`viewAny`) under
`props.auth.can`. The user is the one the official guard reads (`getUser`, default
`request.user`), and each check runs through the official `AuthorizationService`:

```jsonc
{ "auth": { "can": { "post.create": true, "access-admin": false } } }
```

Two equivalent ways to wire it:

**A. Module (auto, via `req.inertia.share`)** — register `AuthzInertiaModule`; a global
interceptor shares the map on every Inertia request:

```ts
@Module({
  imports: [
    AuthorizationModule.forRoot(),
    AuthzModule.forRoot(),
    InertiaModule.forRoot({ /* ... */ }),
    AuthzInertiaModule.forRoot(), // shares props.auth.can automatically
  ],
})
export class AppModule {}
```

**B. Share factory (explicit, via inertia's own seam)** — drop a factory into
`InertiaModule.forRoot({ share })`:

```ts
InertiaModule.forRoot({
  share: createAuthzShare(gate.forUser(user), policyIndex),
})
```

Both resolve abilities by direct in-process `gate.allows(...)` calls — no HTTP round-trip.
The ability name defaults to `"<resourceLower>.<method>"` (e.g. `post.create`), where the
resource is the class linked with `@PolicyFor(Post)`, else the policy name without `Policy`; pass
`abilityNamer: (_, m) => m` for bare method names, or a custom `propKey`.

### Tier 2 — Per-resource `can` map (no request)

For instance-specific decisions (`update`/`delete` of *this* post), serialize a `can`
map onto the resource in your controller:

```ts
const post = await this.posts.find(id);
const can = await authorizeResource(this.gate.forUser(user), post, ['update', 'delete']);
return this.inertia.render('Post/Show', { post: { ...post, can } });
// → { post: { id, title, can: { update: true, delete: false } } }
```

On the client, hydrate it into the store keyed by `type#id` so `can('update', post)`
answers synchronously. (`authorizeResourceForUser` checks an explicit user.)

### Tier 3 — Fallback endpoint (request, last resort)

For abilities not hydrated on the client, enable the opt-in endpoint in **core**:

```ts
AuthzModule.forRoot({ canEndpoint: true }) // POST /authz/can → { allowed }
// or a custom path: canEndpoint: 'api/authz/can'
```

It runs `gate.allows(ability, resource?)` for the caller (read the way the official guard
reads it) and returns
`{ allowed }`. Off by default. This is the path the codegen-emitted `can()` targets.

> **Class-level by default; per-instance with a loader.** Out of the box the endpoint resolves
> **class-level abilities and ad-hoc gates** only — the `{ type, id }` shim it receives never
> matches a policy linked with `@PolicyFor` by constructor, so a **resource-bound** ability that misses the cache and
> falls through to `/authz/can` will **deny**. To make per-instance decisions resolve at tier 3,
> register `resourceLoaders` keyed by the resource `type`:
>
> ```ts
> AuthzModule.forRoot({
>   canEndpoint: true,
>   resourceLoaders: { Post: (id) => postRepo.findOneBy({ id: Number(id) }) },
> })
> ```
>
> The endpoint then loads the real entity before authorizing, so the linked policy matches
> and decides correctly (a loader returning nullish → deny / not found). Prefer hydrating via
> tiers 1-2 (shared props / `authorizeResource`) when you can; use `resourceLoaders` for the
> abilities that genuinely need a tier-3 round-trip.

## Client store (framework-neutral)

The store lives in `@dudousxd/nestjs-authz-client`: a tiny in-memory store + resolver with no
framework dependency — `-react` and the codegen client reuse it. Install it next to this package.

```ts
import { AbilityStore, hydrateFromInertiaProps, hydrateResource, createCan } from '@dudousxd/nestjs-authz-client';

const store = new AbilityStore();
hydrateFromInertiaProps(store, page.props);              // tier 1: props.auth.can
hydrateResource(store, { type: 'Post', id: post.id }, post.can); // tier 2

const can = createCan(store, { fallback: 'fetch', endpoint: '/authz/can' });

can('post.create');                       // → true   (sync, no request)
can('update', { type: 'Post', id: 7 });   // → false  (sync, from resource map)
can('mystery');                           // fallback: 'deny' → false; 'fetch' → Promise<boolean>
```

- **Cache hit** → returns a `boolean` synchronously, never touches the network.
- **Cache miss** → `fallback: 'deny'` (default) returns `false`; `fallback: 'fetch'`
  POSTs to the tier-3 endpoint and returns a `Promise<boolean>`. A **resource-bound**
  miss under `'fetch'` resolves on the server only if the app registered a `resourceLoaders`
  entry for that `type`; otherwise it denies (and `createCan` logs a one-time `console.warn`)
  — hydrate per-instance decisions via tiers 1-2 or register a loader.

## License

MIT
