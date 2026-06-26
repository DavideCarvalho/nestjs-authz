export const VERSION = '0.1.2';

export { AuthzInertiaModule } from './module.js';
export { AuthzInertiaInterceptor } from './authz-inertia.interceptor.js';
export {
  AuthzDenialFilter,
  DEFAULT_LOGIN_URL,
  DEFAULT_FORBIDDEN_URL,
} from './authz-denial.filter.js';
export { createAuthzShare, DEFAULT_PROP_KEY } from './share.js';
export type { CreateAuthzShareOptions } from './share.js';
export {
  resolveClassAbilities,
  defaultAbilityNamer,
} from './resolve-abilities.js';
export type {
  CanMap,
  AbilityNamer,
  ResolveAbilitiesOptions,
} from './resolve-abilities.js';
export { authorizeResource, authorizeResourceForUser } from './authorize-resource.js';
export { AUTHZ_INERTIA_OPTIONS } from './tokens.js';
export type {
  AuthzInertiaOptions,
  AuthzDenialOptions,
  SharedAuthProps,
  InertiaShareable,
  RequestWithInertia,
} from './types.js';
