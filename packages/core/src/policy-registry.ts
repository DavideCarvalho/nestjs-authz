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
}
