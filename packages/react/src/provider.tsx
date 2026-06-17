import {
  AbilityStore,
  type AbilityStoreOptions,
  type CanMap,
  type CanResolver,
  createCan,
} from '@dudousxd/nestjs-authz-client';
import { type ReactNode, createContext, createElement, useContext, useMemo } from 'react';

/** Value held by the {@link AuthzContext}. */
export interface AuthzContextValue {
  /** The ability store the hooks/components read from. */
  store: AbilityStore;
  /** Resolver bound to {@link AuthzContextValue.store} (honors the configured fallback). */
  can: CanResolver;
}

const AuthzContext = createContext<AuthzContextValue | null>(null);

/** Props for {@link AuthzProvider}. */
export interface AuthzProviderProps {
  /**
   * A ready {@link AbilityStore}. Pass this when the app hydrates the store
   * itself (e.g. from Inertia props). When omitted, an empty store is created
   * and seeded from {@link AuthzProviderProps.abilities}.
   */
  store?: AbilityStore;
  /**
   * Initial class-level abilities to seed a fresh store with. Ignored when an
   * explicit `store` is provided.
   */
  abilities?: CanMap;
  /**
   * Resolver behavior on a cache miss (`fallback`, `endpoint`, `fetchImpl`).
   * Default is `'deny'` — `useCan` answers synchronously and never fetches.
   */
  options?: AbilityStoreOptions;
  children: ReactNode;
}

/**
 * Hold an {@link AbilityStore} (and a `can` resolver) for a subtree. The store is
 * usually hydrated by the app from Inertia shared props or any other source and
 * passed in; otherwise an empty store is created and seeded from `abilities`.
 *
 * ```tsx
 * const store = hydrateFromInertiaProps(new AbilityStore(), pageProps);
 * <AuthzProvider store={store}>
 *   <App />
 * </AuthzProvider>
 * ```
 *
 * Written with `createElement` (no JSX in the returned element) so it stays easy
 * to reason about, but the file is `.tsx` for the JSX-ready types.
 */
export function AuthzProvider({ store, abilities, options, children }: AuthzProviderProps) {
  // Memoize on STABLE primitives, not on the `options`/`abilities` object
  // identity — an inline `options={{...}}` or `abilities={{...}}` would otherwise
  // construct a fresh (empty) store on every render, dropping any hydration.
  // For a stable store, pass a hydrated `store` prop (recommended).
  const fallback = options?.fallback;
  const endpoint = options?.endpoint;
  const fetchImpl = options?.fetchImpl;
  const propKey = options?.propKey;
  // `options`/`abilities` are intentionally excluded from the deps: they're read
  // by-value via the stable primitives above (`options`) or only used to seed a
  // fresh store (`abilities`). Re-reading them on identity churn (inline
  // `options={{...}}` / `abilities={{...}}`) would rebuild the store every render
  // and drop hydration. Pass a hydrated `store` for stability when seeding.
  // biome-ignore lint/correctness/useExhaustiveDependencies: see comment above
  const value = useMemo<AuthzContextValue>(() => {
    const resolved = store ?? new AbilityStore();
    if (!store && abilities) resolved.mergeClassAbilities(abilities);
    return { store: resolved, can: createCan(resolved, options) };
  }, [store, fallback, endpoint, fetchImpl, propKey]);
  return createElement(AuthzContext.Provider, { value }, children);
}

/**
 * Read the nearest {@link AuthzProvider} value, or `null` when none is mounted.
 * `useCan` / `<Can>` use this to fall back to a deny-by-default verdict so an
 * un-provided tree fails closed rather than throwing.
 */
export function useAuthzContext(): AuthzContextValue | null {
  return useContext(AuthzContext);
}
