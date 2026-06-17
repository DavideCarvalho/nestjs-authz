import 'reflect-metadata';
import { Injectable, type Type } from '@nestjs/common';
import { POLICY_RESOURCE_METADATA } from '../tokens.js';
import type { PolicyInstance } from '../types.js';

/**
 * Marks a class as the policy for `resource`. The class methods become abilities
 * dispatched by name (e.g. `update(user, post)` answers `gate.authorize('update', post)`).
 *
 * Applying `@Policy` also makes the class an `@Injectable()` provider so it can
 * be auto-discovered and resolved from the Nest container.
 */
export function Policy(resource: Type<unknown>): ClassDecorator {
  return (target) => {
    Reflect.defineMetadata(POLICY_RESOURCE_METADATA, resource, target);
    // Make the policy a provider without forcing the app to add @Injectable().
    Injectable()(target);
  };
}

/**
 * Returns the resource class a policy was declared for, or `undefined`.
 *
 * Uses `getMetadata` (not `getOwnMetadata`) so a subclass of a `@Policy`-decorated
 * class still resolves the inherited resource via the prototype chain.
 */
export function getPolicyResource(policy: Type<unknown> | object): Type<unknown> | undefined {
  const ctor = typeof policy === 'function' ? policy : (policy as PolicyInstance).constructor;
  return Reflect.getMetadata(POLICY_RESOURCE_METADATA, ctor) as Type<unknown> | undefined;
}
