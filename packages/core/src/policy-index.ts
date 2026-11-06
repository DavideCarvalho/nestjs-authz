import { Injectable, type Type } from '@nestjs/common';
import { DiscoveryService, ModuleRef } from '@nestjs/core';
import { getPolicyResource, policyForResource, policyLinks } from './links.js';
import { isOfficialPolicy } from './official.js';

/** Built-in policies that are not about a resource; left out of ability listings. */
const BUILT_IN = new Set(['RolePolicy', 'PermissionPolicy', 'GatePolicy']);

/** One official policy of the application, as the extras see it. */
export interface IndexedPolicy {
  policy: Type<unknown>;
  /** The instance the official registry uses (an `overrideProvider` replacement in tests). */
  instance: object;
  /** The resource linked with `@PolicyFor`, if any. */
  resource: Type<unknown> | undefined;
}

/**
 * The application's official `@Policy()` providers and their resource links. Read-only:
 * the official `PolicyRegistry` owns registration; this only looks them up for the
 * extras (resource → policy, `scope()`, ability listings).
 */
@Injectable()
export class PolicyIndex {
  private cache: IndexedPolicy[] | undefined;

  constructor(
    private readonly discovery: DiscoveryService,
    private readonly moduleRef: ModuleRef,
  ) {}

  /** Every official policy registered as a provider, built-ins included. */
  all(): IndexedPolicy[] {
    if (this.cache) return this.cache;
    const seen = new Set<unknown>();
    const out: IndexedPolicy[] = [];
    for (const wrapper of this.discovery.getProviders()) {
      const token = wrapper.token;
      const key = isOfficialPolicy(token)
        ? token
        : !wrapper.isFactory && isOfficialPolicy(wrapper.metatype)
          ? (wrapper.metatype as Type<unknown>)
          : undefined;
      if (!key || seen.has(key) || !wrapper.instance || typeof wrapper.instance !== 'object') {
        continue;
      }
      seen.add(key);
      out.push({
        policy: key,
        instance: wrapper.instance as object,
        resource: getPolicyResource(key),
      });
    }
    if (out.length > 0) this.cache = out;
    return out;
  }

  /** Official policies about a resource (built-ins left out). */
  resourcePolicies(): IndexedPolicy[] {
    return this.all().filter((p) => !BUILT_IN.has(p.policy.name));
  }

  /** The policy class linked to a resource class. */
  policyFor(resource: Type<unknown>): Type<unknown> | undefined {
    return policyForResource(resource);
  }

  /** The policy class for a resource instance (by its constructor), or for a class. */
  policyOf(resource: object): Type<unknown> | undefined {
    if (typeof resource === 'function') return policyForResource(resource as Type<unknown>);
    return policyForResource((resource as { constructor: Type<unknown> }).constructor);
  }

  /** Linked policy classes defining `ability`, for a check that names no resource. */
  linkedPoliciesWith(ability: string): Type<unknown>[] {
    return policyLinks()
      .map((l) => l.policy)
      .filter((p) => typeof (p.prototype as Record<string, unknown>)[ability] === 'function');
  }

  /** The policy instance the app uses for `policy`, or `undefined` when it is not registered. */
  instanceOf(policy: Type<unknown>): object | undefined {
    const indexed = this.all().find((p) => p.policy === policy);
    if (indexed) return indexed.instance;
    try {
      return this.moduleRef.get(policy, { strict: false }) as object;
    } catch {
      return undefined;
    }
  }

  /**
   * Abilities of each resource policy that take no argument after the user (arity
   * `<= 1`, e.g. `create(user)`), safe to check without a record. `before`, `scope` and
   * the constructor are not abilities.
   */
  classAbilities(): Array<{
    policy: Type<unknown>;
    resource: Type<unknown> | undefined;
    abilities: string[];
  }> {
    return this.resourcePolicies().map(({ policy, instance, resource }) => {
      const abilities = new Set<string>();
      let proto: object | null = Object.getPrototypeOf(instance);
      while (proto && proto !== Object.prototype) {
        for (const name of Object.getOwnPropertyNames(proto)) {
          if (name === 'constructor' || name === 'before' || name === 'scope') continue;
          const member = (instance as Record<string, unknown>)[name];
          if (typeof member === 'function' && member.length <= 1) abilities.add(name);
        }
        proto = Object.getPrototypeOf(proto);
      }
      return { policy, resource, abilities: [...abilities] };
    });
  }
}
