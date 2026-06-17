# @dudousxd/nestjs-authz-telescope

A [`@dudousxd/nestjs-telescope`](https://www.npmjs.com/package/@dudousxd/nestjs-telescope) **extension**
that records every authorization decision the
[`@dudousxd/nestjs-authz`](https://github.com/DavideCarvalho/nestjs-authz) `Gate` reaches — the
ability, allow/deny, the reason it was decided, the user and the resource — as a Telescope entry and
a dashboard panel. So when a request 403s, you can see exactly **which** ability was denied and
**why**.

```bash
pnpm add -D @dudousxd/nestjs-authz-telescope
```

```ts title="app.module.ts"
import { TelescopeModule } from '@dudousxd/nestjs-telescope';
import { nestjsAuthzTelescope } from '@dudousxd/nestjs-authz-telescope';

@Module({
  imports: [
    AuthzModule.forRoot({ policies: [PostPolicy] }),
    TelescopeModule.forRoot({
      extensions: [nestjsAuthzTelescope()],
    }),
  ],
})
export class AppModule {}
```

That's it — no decorators, no monkey-patching. The Gate publishes each decision on a
`node:diagnostics_channel` (`nestjs-authz:decision`); the extension's watcher subscribes and records.
When nothing subscribes, the Gate emits nothing — zero overhead.

## What it records

Every `gate.allows(...)` / `gate.authorize(...)` / `gate.denies(...)` produces one `authorization`
entry:

```jsonc
{
  "type": "authorization",
  "familyHash": "update:deny",
  "tags": ["ability:update", "decision:deny", "reason:policy", "resource:Post", "denied"],
  "content": {
    "ability": "update",
    "allowed": false,
    "reason": "policy",      // super-admin | permission-provider | policy-before | policy | gate | anonymous
    "user": "User#42",
    "resource": "Post#7"
  }
}
```

The `reason` names the resolution path that produced the verdict, so a deny is never a mystery.

## Dashboard

The extension contributes an **Authorization** page (under a "Security" nav group) with:

- a **top-N of the most denied abilities**, and
- a **table of the most recent decisions** (ability, decision, reason, user, resource).

It also registers `authorization` as a navigable entry type so the decisions are filterable in the
main Telescope feed.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `topDeniedLimit` | `10` | How many denied abilities to surface in the top-N panel. |
| `recentLimit` | `50` | How many recent decisions to list in the table panel. |

## How it works

`@dudousxd/nestjs-authz`'s `Gate` publishes each decision on the `nestjs-authz:decision`
diagnostics channel — a dependency-free, loosely-coupled seam. This package's `AuthorizationWatcher`
subscribes on module init; because publishing is synchronous inside the check, recorded entries land
in the active request/job batch. Malformed or wrong-version payloads are dropped, and recording is
fully guarded so a Telescope error can never break an authorization check.
