import type { BoundGate, Gate, PolicyIndex } from '@dudousxd/nestjs-authz';
import type { CanMap } from '@dudousxd/nestjs-authz-client';
import type { Type } from '@nestjs/common';

/**
 * A flat record of `ability -> verdict`, e.g. `{ 'posts.create': true }`.
 * Re-exported from `@dudousxd/nestjs-authz-client` so there is a single source
 * of truth shared with the client store.
 */
export type { CanMap };

/**
 * How an ability key is built from a policy's resource name and method name when
 * listing class-level abilities. The resource name is the class linked with
 * `@PolicyFor(Resource)`, else the policy class name without `Policy` (`PostPolicy` →
 * `Post`).
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
 * Resolve a user's CLASS-LEVEL abilities into a flat `{ ability: boolean }` map, with no
 * HTTP round-trip. Pass `gate.forUser(user)`; a bare `Gate` checks its ambient user.
 *
 * Sources, in order:
 *  1. Ad-hoc gates registered with `gate.define(...)`.
 *  2. The abilities of every official `@Policy()` that take no argument after the user
 *     (`create(user)`, `viewAny(user)`), checked through the official
 *     `AuthorizationService` (so each policy's `before()` applies). Abilities that take a
 *     record (`update(user, post)`) are per-instance: share them with `authorizeResource`.
 *  3. Any extra `options.abilities` names.
 */
export async function resolveClassAbilities(
  gate: Gate | BoundGate,
  policies: PolicyIndex,
  options: ResolveAbilitiesOptions = {},
): Promise<CanMap> {
  const namer = options.abilityNamer ?? defaultAbilityNamer;
  const out: CanMap = {};
  const names = new Set<string>([...gateNamesOf(gate), ...(options.abilities ?? [])]);
  for (const ability of names) {
    out[ability] = await safely(() => gate.allows(ability));
  }

  for (const { policy, resource, abilities } of policies.classAbilities()) {
    const resourceName = resource?.name ?? policy.name.replace(/Policy$/, '');
    for (const method of abilities) {
      const key = namer(resourceName, method);
      out[key] = await safely(() =>
        (gate.allows as (p: Type<unknown>, a: string) => Promise<boolean>).call(
          gate,
          policy,
          method,
        ),
      );
      if (options.includeBareMethodNames && out[method] === undefined) {
        out[method] = out[key];
      }
    }
  }

  return out;
}

/** The ad-hoc gate names, from a `Gate` or the `Gate` behind a `BoundGate`. */
function gateNamesOf(gate: Gate | BoundGate): string[] {
  const owner = (gate as unknown as { gate?: Gate }).gate ?? (gate as Gate);
  return typeof owner.gateNames === 'function' ? owner.gateNames() : [];
}

/** A check that throws (unresolved ability, unregistered policy) shares `false`. */
async function safely(check: () => Promise<boolean>): Promise<boolean> {
  try {
    return await check();
  } catch {
    return false;
  }
}
