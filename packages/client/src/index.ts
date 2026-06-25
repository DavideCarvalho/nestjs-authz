export const VERSION = '0.2.0';

export {
  AbilityStore,
  createCan,
  createCanBatch,
  hydrateFromInertiaProps,
  hydrateResource,
} from './store.js';
export type {
  CanMap,
  ResourceRef,
  HydratableProps,
  FallbackMode,
  AbilityStoreOptions,
  CanResolver,
  BatchAbilityRequest,
  BatchAbilityResult,
  CanBatchResolver,
} from './store.js';
