import { Injectable, type Type } from '@nestjs/common';
import { getPolicyResource } from './decorator/policy.decorator.js';
import { PolicyNotDecoratedException } from './errors/exceptions.js';
import type { PolicyInstance } from './types.js';

/**
 * Maps a resource class → its policy instance. Populated at module init from
 * explicit `policies: []` and/or auto-discovered `@Policy` providers.
 */
@Injectable()
export class PolicyRegistry {
  private readonly byResource = new Map<Type<unknown>, PolicyInstance>();

  // Cache for classAbilities(): the result is static after registration, so it
  // is computed lazily once and invalidated whenever a policy is registered.
  private classAbilitiesCache: Array<{ resource: Type<unknown>; abilities: string[] }> | undefined;

  /**
   * Register a policy instance. Throws if the instance's class was not decorated
   * with `@Policy(Resource)`.
   */
  register(policy: PolicyInstance): void {
    const resource = getPolicyResource(policy);
    if (!resource) {
      const name = policy.constructor?.name ?? 'Policy';
      throw new PolicyNotDecoratedException(name);
    }
    this.byResource.set(resource, policy);
    this.classAbilitiesCache = undefined;
  }

  /** Resolve the policy instance for a resource class, or `undefined`. */
  forResource(resource: Type<unknown>): PolicyInstance | undefined {
    return this.byResource.get(resource);
  }

  /** Resolve the policy for the class of a resource instance, or `undefined`. */
  forInstance(instance: object): PolicyInstance | undefined {
    return this.byResource.get(instance.constructor as Type<unknown>);
  }

  /** True when a policy is registered for the resource class. */
  has(resource: Type<unknown>): boolean {
    return this.byResource.has(resource);
  }

  /** All registered policies (for introspection/testing). */
  all(): PolicyInstance[] {
    return [...this.byResource.values()];
  }

  /** All registered resource classes (insertion order). */
  resources(): Type<unknown>[] {
    return [...this.byResource.keys()];
  }

  /**
   * Enumerate the CLASS-LEVEL ability method names declared on each registered
   * policy, keyed by resource class. Used by integrations that pre-resolve a
   * user's class-level abilities (e.g. to share them as Inertia props).
   *
   * Walks the policy prototype chain and collects own function-valued members,
   * excluding `constructor` and the reserved `before` hook. Inherited Object
   * members are skipped.
   *
   * Only methods that take NO resource instance are included — heuristically,
   * arity `<= 1` (just `user`, e.g. `create(user)` / `viewAny(user)`). An
   * instance method like `update(user, post)` is excluded: dispatching it
   * against the resource CLASS would call it with the class constructor as
   * `post` and write a bogus class-level verdict.
   */
  classAbilities(): Array<{ resource: Type<unknown>; abilities: string[] }> {
    return (this.classAbilitiesCache ??= this.computeClassAbilities());
  }

  private computeClassAbilities(): Array<{ resource: Type<unknown>; abilities: string[] }> {
    const out: Array<{ resource: Type<unknown>; abilities: string[] }> = [];
    for (const [resource, policy] of this.byResource) {
      const abilities = new Set<string>();
      let proto: object | null = Object.getPrototypeOf(policy);
      while (proto && proto !== Object.prototype) {
        for (const name of Object.getOwnPropertyNames(proto)) {
          if (name === 'constructor' || name === 'before') continue;
          const member = (policy as Record<string, unknown>)[name];
          // Class-level abilities take only `user` (arity <= 1). A method that
          // also declares a resource param (arity >= 2) is instance-scoped and
          // must not be dispatched against the class.
          if (typeof member === 'function' && member.length <= 1) {
            abilities.add(name);
          }
        }
        proto = Object.getPrototypeOf(proto);
      }
      out.push({ resource, abilities: [...abilities] });
    }
    return out;
  }
}
