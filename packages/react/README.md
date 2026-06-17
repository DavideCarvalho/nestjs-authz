# @dudousxd/nestjs-authz-react

React provider, `useCan` hook, and `<Can>` component for
[`@dudousxd/nestjs-authz`](../core). Reads a hydrated
[`AbilityStore`](../client) — so `can(...)` checks resolve **synchronously, with no
network request** (the Laravel/Inertia model).

```tsx
import { AbilityStore, hydrateFromInertiaProps } from '@dudousxd/nestjs-authz-client';
import { AuthzProvider, useCan, Can } from '@dudousxd/nestjs-authz-react';

// App root — hydrate once from Inertia props (or any source) and pass the store in.
const store = hydrateFromInertiaProps(new AbilityStore(), pageProps);

function App() {
  return (
    <AuthzProvider store={store}>
      <Toolbar />
    </AuthzProvider>
  );
}

function Toolbar() {
  const { allowed } = useCan('post.create'); // boolean, first render, no fetch
  return (
    <>
      {allowed && <NewPostButton />}
      <Can ability="update" of={{ type: 'Post', id: post.id }} fallback={<Locked />}>
        <EditButton />
      </Can>
    </>
  );
}
```

## `AuthzProvider`

Holds an `AbilityStore` for a subtree. Either pass a hydrated `store`, or let the
provider create an empty one and seed it from `abilities`. `options` configures the
miss behavior (`fallback: 'deny' | 'fetch'`, `endpoint`, `fetchImpl`); the default is
`'deny'`, so the tree never fetches.

## `useCan(ability, resource?)`

Returns `{ allowed, loading }`.

- **Cache hit** → `allowed` is the cached `boolean` on the first render, `loading`
  is `false`. No request, no suspense.
- **Cache miss** → follows the provider's fallback. `'deny'` (default) returns
  `false` synchronously. `'fetch'` returns `false` with `loading: true`, then
  re-renders with the resolved verdict.
- **No provider** → fails closed (`false`).

## `<Can ability of fallback>`

Renders `children` when allowed, otherwise `fallback` (default nothing). Thin wrapper
over `useCan`, so the no-request guarantee holds.
