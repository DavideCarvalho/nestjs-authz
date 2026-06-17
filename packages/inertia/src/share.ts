import type { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { type ResolveAbilitiesOptions, resolveClassAbilities } from './resolve-abilities.js';

/** Default prop namespace: `props.auth.can`. */
export const DEFAULT_PROP_KEY = 'auth';

export interface CreateAuthzShareOptions extends ResolveAbilitiesOptions {
  /** Prop key the `{ can }` object nests under. Default `'auth'`. */
  propKey?: string;
}

/**
 * Build an Inertia **share factory** that resolves the current user's class-level
 * abilities into `props.<propKey>.can` — with NO network request (direct in-process
 * `gate.allows` calls).
 *
 * Drop it into `InertiaModule.forRoot({ share })` (matching nestjs-inertia's
 * prop-sharing idiom):
 *
 * ```ts
 * InertiaModule.forRoot({
 *   share: createAuthzShare(gate, policyRegistry),
 * })
 * ```
 *
 * The returned factory is an async `(req) => Props`; nestjs-inertia awaits it per
 * render and merges the result into every page's shared props. The client store's
 * `hydrateFromInertiaProps` then reads `props.auth.can`.
 */
export function createAuthzShare(
  gate: Gate,
  policies: PolicyRegistry,
  options: CreateAuthzShareOptions = {},
): () => Promise<Record<string, unknown>> {
  const propKey = options.propKey ?? DEFAULT_PROP_KEY;
  return async () => {
    const can = await resolveClassAbilities(gate, policies, options);
    return { [propKey]: { can } };
  };
}
