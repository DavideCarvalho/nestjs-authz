import 'reflect-metadata';
import { Policy as OfficialPolicy } from '@nestjs/authorization';
import type { Type } from '@nestjs/common';

/** Metadata key on a policy class: the resource class it is linked to. */
export const POLICY_RESOURCE_METADATA = 'nestjs-authz:policy-resource';

const policyByResource = new Map<Type<unknown>, Type<unknown>>();

/**
 * Links an official policy to the resource class it authorizes, and marks it as an
 * official `@Policy()`. The link is what lets the extras find the policy from a
 * resource: `gate.allows('update', post)`, `gate.scope(Post)`, the client ability map.
 * The official API itself never needs it: `@Can(PostPolicy, 'update', byId(Post))`
 * names the policy.
 *
 * @example
 * ```ts
 * import { Policy } from '@nestjs/authorization';
 *
 * @Policy()
 * @PolicyFor(Post)
 * export class PostPolicy {
 *   update(user: User | null, post: Post) { return post.authorId === user?.id; }
 * }
 * ```
 *
 * `@PolicyFor(Post)` alone also works: it applies the official `@Policy()` itself.
 */
export function PolicyFor(resource: Type<unknown>): ClassDecorator {
  return (target) => {
    Reflect.defineMetadata(POLICY_RESOURCE_METADATA, resource, target);
    policyByResource.set(resource, target as unknown as Type<unknown>);
    (OfficialPolicy() as (t: unknown) => void)(target);
  };
}

/** The policy class linked to `resource` with {@link PolicyFor}, if any. */
export function policyForResource(resource: Type<unknown>): Type<unknown> | undefined {
  return policyByResource.get(resource);
}

/** The resource class a policy is linked to with {@link PolicyFor}, if any. Inherited by subclasses. */
export function getPolicyResource(policy: Type<unknown> | object): Type<unknown> | undefined {
  const ctor = typeof policy === 'function' ? policy : (policy as object).constructor;
  return Reflect.getMetadata(POLICY_RESOURCE_METADATA, ctor) as Type<unknown> | undefined;
}

/** Every resource → policy link declared so far, in declaration order. */
export function policyLinks(): Array<{ resource: Type<unknown>; policy: Type<unknown> }> {
  return [...policyByResource].map(([resource, policy]) => ({ resource, policy }));
}
