import type { Gate, Resource } from '@dudousxd/nestjs-authz';
import type { CanMap } from './resolve-abilities.js';

/**
 * Resolve a per-INSTANCE `can` map for one resource, with NO HTTP round-trip:
 * each ability is a direct `gate.allows(ability, resource)` call against the
 * in-process Gate for the current (context) user.
 *
 * Use it controller-side to attach decisions to a serialized resource:
 *
 * ```ts
 * const post = await this.posts.find(id);
 * const can = await authorizeResource(this.gate, post, ['update', 'delete']);
 * return this.inertia.render('Post/Show', { post: { ...post, can } });
 * ```
 *
 * The client store keys these maps by `type#id`, so hydrating them lets
 * `can('update', post)` return the cached verdict synchronously on the front end.
 *
 * @returns e.g. `{ update: true, delete: false }`
 */
export async function authorizeResource(
  gate: Gate,
  resource: Resource,
  abilities: string[],
): Promise<CanMap> {
  const out: CanMap = {};
  for (const ability of abilities) {
    try {
      out[ability] = await gate.allows(ability, resource);
    } catch {
      out[ability] = false;
    }
  }
  return out;
}

/**
 * Like {@link authorizeResource}, but resolves for an explicit user via
 * `gate.forUser(user)` instead of the current context user. Useful outside a
 * request, or to serialize decisions for a user other than the caller.
 */
export async function authorizeResourceForUser(
  gate: Gate,
  user: unknown,
  resource: Resource,
  abilities: string[],
): Promise<CanMap> {
  const bound = gate.forUser(user);
  const out: CanMap = {};
  for (const ability of abilities) {
    try {
      out[ability] = await bound.allows(ability, resource);
    } catch {
      out[ability] = false;
    }
  }
  return out;
}
