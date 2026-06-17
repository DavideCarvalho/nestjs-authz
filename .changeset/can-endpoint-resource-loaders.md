---
"@dudousxd/nestjs-authz": minor
---

Add `resourceLoaders` to `AuthzModule.forRoot`/`forRootAsync` options — a map keyed by
the resource `type` name (e.g. `{ Post: (id) => postRepo.findOneBy({ id: Number(id) }) }`).
Closes the per-instance gap in the opt-in `POST /authz/can` fallback endpoint: when a loader
is registered for `resource.type`, the endpoint rehydrates the client's `{ type, id }` shim
into the REAL entity before authorizing, so an instance-bound `@Policy` matches by constructor
and its method decides correctly. A loader returning nullish is treated as "not found" (deny).
Types without a loader keep the prior class-level / ad-hoc-only behavior. Opt-in and additive:
unset → endpoint behavior unchanged. Also exposes a `RESOURCE_HYDRATOR` token and the
`ResourceLoader`/`ResourceLoaderMap` types.
