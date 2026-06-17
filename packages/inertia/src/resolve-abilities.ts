import type { Gate, PolicyRegistry, Resource } from '@dudousxd/nestjs-authz';
import type { CanMap } from '@dudousxd/nestjs-authz-client';

/**
 * A flat record of `ability -> verdict`, e.g. `{ 'posts.create': true }`.
 * Re-exported from `@dudousxd/nestjs-authz-client` so there is a single source
 * of truth shared with the client store.
 */
export type { CanMap };

/**
 * How an ability name is built from a policy's resource class + method name when
 * enumerating class-level policy abilities. Default: `"<ResourceName>.<method>"`
 * lower-cased on the resource (e.g. `Post` + `create` → `posts.create`... no — see
 * below). Kept overridable so an app can match the naming its `@Can` decorators use.
 */
export type AbilityNamer = (resourceName: string, method: string) => string;

/**
 * Default namer: `"<resourceNameLower>.<method>"` (e.g. `Post`,`create` →
 * `post.create`). Apps whose `@Can` abilities are bare method names
 * (`create`, `viewAny`) can pass `(_, m) => m`.
 */
export const defaultAbilityNamer: AbilityNamer = (resourceName, method) =>
  `${resourceName.toLowerCase()}.${method}`;

export interface ResolveAbilitiesOptions {
  /**
   * Extra ad-hoc gate / explicit ability names to resolve in addition to the
   * gates auto-discovered via {@link Gate.gateNames}. Useful for gates registered
   * lazily or abilities you always want present in props.
   */
  abilities?: string[];
  /**
   * Build the ability name from a policy's `(resourceClassName, method)`. Defaults
   * to {@link defaultAbilityNamer}. Use `(_, m) => m` for bare method-name abilities.
   */
  abilityNamer?: AbilityNamer;
  /**
   * Include the bare policy method name as an additional key alongside the
   * namespaced one (so both `post.create` and `create` resolve). Default `false`.
   */
  includeBareMethodNames?: boolean;
}

/**
 * Resolve the current user's CLASS-LEVEL abilities into a flat `{ ability: boolean }`
 * map, with NO per-request HTTP round-trip — each entry is a direct `gate.allows`
 * call against the in-process Gate.
 *
 * Sources, in order:
 *  1. Ad-hoc gates registered via `gate.define(...)` (model-less, e.g. `access-admin`).
 *  2. Class-level `@Policy` methods (those taking no resource instance — heuristically
 *     arity `<= 1`, e.g. `create(user)`/`viewAny(user)`), dispatched against the resource
 *     CLASS so no instance is loaded. Instance methods like `update(user, post)` are NOT
 *     enumerated (see {@link PolicyRegistry.classAbilities}) — dispatching them against the
 *     class would write a bogus class-level verdict.
 *  3. Any extra `options.abilities` names.
 *
 * Gates are checked by name; policy methods are checked by passing the resource
 * class as the dispatch target (Gate resolves the class-level policy method).
 */
export async function resolveClassAbilities(
  gate: Gate,
  policies: PolicyRegistry,
  options: ResolveAbilitiesOptions = {},
): Promise<CanMap> {
  const namer = options.abilityNamer ?? defaultAbilityNamer;
  const out: CanMap = {};

  // 1. Ad-hoc gates (model-less). Resolve by ability name only.
  const gateNames = new Set<string>([...gate.gateNames(), ...(options.abilities ?? [])]);
  for (const ability of gateNames) {
    out[ability] = await safeAllows(gate, ability);
  }

  // 2. Class-level policy methods, dispatched against the resource CLASS.
  for (const { resource, abilities } of policies.classAbilities()) {
    const resourceName = (resource as { name?: string }).name ?? 'Resource';
    for (const method of abilities) {
      const key = namer(resourceName, method);
      // Gate.allows accepts a Type (class) as the resource for class-level abilities.
      out[key] = await safeAllows(gate, method, resource as unknown as Resource);
      if (options.includeBareMethodNames && out[method] === undefined) {
        out[method] = out[key];
      }
    }
  }

  return out;
}

/**
 * `gate.allows` may throw (unresolved/ambiguous ability). For prop sharing we
 * fail closed (deny) rather than crash the render.
 */
async function safeAllows(gate: Gate, ability: string, resource?: Resource): Promise<boolean> {
  try {
    return await gate.allows(ability, resource);
  } catch {
    return false;
  }
}
