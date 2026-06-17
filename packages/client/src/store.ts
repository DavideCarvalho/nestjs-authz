/**
 * Framework-neutral, in-memory ability store + `can()` resolver for the front end.
 *
 * The store is hydrated from Inertia shared props (`props.auth.can`) and from any
 * per-resource `can` maps a controller serialized onto a resource. `can(...)` then
 * answers SYNCHRONOUSLY from the cache — no network request — and only falls back
 * (configurable: fetch the `/authz/can` endpoint, or deny) when the ability/resource
 * is genuinely unknown.
 *
 * No dependency on React/Vue/NestJS/Inertia — `-react`, `-inertia`, and the codegen
 * client can all reuse this.
 *
 * @module store
 */

/** A flat `ability -> verdict` record. */
export type CanMap = Record<string, boolean>;

/** A resource identifiable by `type` + `id` (for keying per-instance maps). */
export interface ResourceRef {
  type: string;
  id?: string | number | null;
}

/** Inertia shared-props subset the store reads from. */
export interface HydratableProps {
  auth?: { can?: CanMap | null } | null;
  [key: string]: unknown;
}

/** Strategy when an ability/resource is NOT in the store. */
export type FallbackMode = 'deny' | 'fetch';

export interface AbilityStoreOptions {
  /** Prop key the class-ability map nests under (matches the server's `propKey`). Default `'auth'`. */
  propKey?: string;
  /**
   * What to do when `can(...)` is asked about an ability/resource not in the store.
   * - `'deny'` (default): return `false` synchronously.
   * - `'fetch'`: POST to {@link AbilityStoreOptions.endpoint} and resolve a Promise.
   */
  fallback?: FallbackMode;
  /** Endpoint the `'fetch'` fallback POSTs `{ ability, resource }` to. Default `'/authz/can'`. */
  endpoint?: string;
  /** Injectable fetch (for tests / non-browser runtimes). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

/** Build the cache key for a per-instance decision. */
function resourceKey(ref: ResourceRef): string {
  return `${ref.type}#${ref.id ?? ''}`;
}

/**
 * In-memory store of class-level abilities + per-resource `can` maps.
 *
 * Class abilities are keyed by ability name; per-resource maps are keyed by
 * `type#id` then ability name.
 */
export class AbilityStore {
  private readonly classAbilities: CanMap = {};
  private readonly resourceAbilities = new Map<string, CanMap>();

  /** Replace the class-level ability map. */
  setClassAbilities(map: CanMap): this {
    for (const k of Object.keys(this.classAbilities)) delete this.classAbilities[k];
    Object.assign(this.classAbilities, map);
    return this;
  }

  /** Merge additional class-level abilities (does not clear existing). */
  mergeClassAbilities(map: CanMap): this {
    Object.assign(this.classAbilities, map);
    return this;
  }

  /** Store a per-instance `can` map for a resource. */
  setResourceAbilities(ref: ResourceRef, map: CanMap): this {
    this.resourceAbilities.set(resourceKey(ref), { ...map });
    return this;
  }

  /** True when `ability` (optionally on `resource`) has a cached verdict. */
  has(ability: string, resource?: ResourceRef): boolean {
    if (resource) {
      const map = this.resourceAbilities.get(resourceKey(resource));
      return map !== undefined && map[ability] !== undefined;
    }
    return this.classAbilities[ability] !== undefined;
  }

  /**
   * Synchronous lookup. Returns the cached verdict, or `undefined` when unknown.
   * Never performs I/O.
   */
  peek(ability: string, resource?: ResourceRef): boolean | undefined {
    if (resource) {
      const map = this.resourceAbilities.get(resourceKey(resource));
      return map?.[ability];
    }
    return this.classAbilities[ability];
  }

  /** Empty the store. */
  clear(): this {
    for (const k of Object.keys(this.classAbilities)) delete this.classAbilities[k];
    this.resourceAbilities.clear();
    return this;
  }
}

/**
 * Hydrate `store` from Inertia shared props. Reads `props.<propKey>.can` for the
 * class-level abilities. Per-resource maps are hydrated separately via
 * {@link hydrateResource} (a resource's `can` lives on the serialized resource,
 * whose `type`/`id` only the caller knows).
 */
export function hydrateFromInertiaProps(
  store: AbilityStore,
  props: HydratableProps | undefined | null,
  propKey = 'auth',
): AbilityStore {
  const bag = (props as Record<string, unknown> | null | undefined)?.[propKey] as
    | { can?: CanMap | null }
    | undefined;
  if (bag?.can) store.mergeClassAbilities(bag.can);
  return store;
}

/**
 * Hydrate a single resource's per-instance `can` map (e.g. from a serialized
 * `{ ...post, can }`). `ref` identifies the instance (`type#id`).
 */
export function hydrateResource(
  store: AbilityStore,
  ref: ResourceRef,
  can: CanMap | undefined | null,
): AbilityStore {
  if (can) store.setResourceAbilities(ref, can);
  return store;
}

/**
 * The resolver function returned by {@link createCan}. When the verdict is cached
 * it returns a `boolean` SYNCHRONOUSLY; only on a cache miss with `fallback: 'fetch'`
 * does it return a `Promise<boolean>`.
 */
export type CanResolver = (ability: string, resource?: ResourceRef) => boolean | Promise<boolean>;

/**
 * Build a `can(ability, resource?)` bound to `store`.
 *
 * - **Cache hit** → returns the cached `boolean` synchronously (NO request).
 * - **Cache miss, `fallback: 'deny'`** (default) → returns `false` synchronously.
 * - **Cache miss, `fallback: 'fetch'`** → POSTs `{ ability, resource }` to the
 *   endpoint and returns a `Promise<boolean>` from `{ allowed }`.
 *
 * **Resource-bound decisions and the fetch fallback:** prefer hydrating per-instance
 * decisions (`can(ability, { type, id })`) via shared props / `authorizeResource`
 * (tiers 1-2). The `POST /authz/can` fetch fallback sends a `{ type, id }` shim; the
 * server resolves it per-instance ONLY when the app registered a matching
 * `resourceLoaders` entry for that `type` (which rehydrates the real entity). Without
 * such hydration or loader the resource-bound ability DENIES — so on a resource-bound
 * cache miss under `fallback: 'fetch'` this logs a one-time `console.warn` so the
 * potential silent deny is debuggable.
 */
export function createCan(store: AbilityStore, options: AbilityStoreOptions = {}): CanResolver {
  const fallback = options.fallback ?? 'deny';
  const endpoint = options.endpoint ?? '/authz/can';
  let warnedResourceFetch = false;

  return (ability: string, resource?: ResourceRef): boolean | Promise<boolean> => {
    const cached = store.peek(ability, resource);
    if (cached !== undefined) return cached;

    if (fallback === 'deny') return false;

    // A resource-bound ability that misses the cache is resolved by the endpoint
    // fallback ONLY if the server registered a `resourceLoaders` entry for this
    // `type` (otherwise the {type,id} shim never matches a @Policy and DENIES). Warn once.
    if (resource && !warnedResourceFetch) {
      warnedResourceFetch = true;
      const id = JSON.stringify(resource.id ?? null);
      console.warn(
        `[nestjs-authz] can('${ability}', { type: '${resource.type}', id: ${id} }) missed the cache and fell through to the '${endpoint}' fetch fallback. The server resolves this per-instance only if it registered a resourceLoaders entry for '${resource.type}'; otherwise it will DENY. Hydrate resource decisions via shared props / authorizeResource (tiers 1-2), or register a resourceLoaders loader.`,
      );
    }

    const doFetch = options.fetchImpl ?? globalThis.fetch;
    if (typeof doFetch !== 'function') return false;

    return doFetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ability,
        resource: resource ? { type: resource.type, id: resource.id ?? null } : null,
      }),
    })
      .then((res: Response) => (res.ok ? (res.json() as Promise<{ allowed?: boolean }>) : null))
      .then((data) => data?.allowed === true)
      .catch(() => false);
  };
}
