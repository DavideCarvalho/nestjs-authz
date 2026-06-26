export const VERSION = '0.1.2';

// Re-export the framework-neutral store for convenience.
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

// Provider / context
export { AuthzProvider, useAuthzContext } from './provider.js';
export type { AuthzProviderProps, AuthzContextValue } from './provider.js';

// Hook
export { useCan } from './use-can.js';
export type { UseCanResult } from './use-can.js';

// Component
export { Can } from './can.js';
export type { CanProps } from './can.js';
