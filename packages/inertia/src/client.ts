/**
 * Re-export of the framework-neutral ability store, now canonicalized in
 * {@link @dudousxd/nestjs-authz-client}. Kept here so the long-standing
 * `@dudousxd/nestjs-authz-inertia/client` entry point continues to work.
 *
 * @module client
 */

export {
  AbilityStore,
  createCan,
  hydrateFromInertiaProps,
  hydrateResource,
} from '@dudousxd/nestjs-authz-client';
export type {
  CanMap,
  ResourceRef,
  HydratableProps,
  FallbackMode,
  AbilityStoreOptions,
  CanResolver,
} from '@dudousxd/nestjs-authz-client';
