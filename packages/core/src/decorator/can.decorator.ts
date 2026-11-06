import 'reflect-metadata';
import type { Type } from '@nestjs/common';
import { byId, staticCanArgs } from '../helpers.js';
import { policyForResource } from '../links.js';
import { OFFICIAL_CAN_METADATA, type OfficialCanRequirement } from '../official.js';
import { GatePolicy } from '../policies/gate.policy.js';

/** @deprecated Options of the deprecated string {@link Can}. */
export interface CanOptions {
  /** The ability takes no record: the policy method runs with the user only. */
  classLevel?: boolean;
}

/**
 * @deprecated Use the official `@Can()` from `@nestjs/authorization`, which names the
 * policy. This string form is kept for one major version and only writes the official
 * metadata, which the official `AuthorizationGuard` enforces:
 *
 * | Deprecated | Official equivalent |
 * | --- | --- |
 * | `@Can('update', Post)` | `@Can(PostPolicy, 'update', byId(Post))` |
 * | `@Can('create', Post, { classLevel: true })` | `@Can(PostPolicy, 'create')` |
 * | `@Can('access-admin')` | `@Can(GatePolicy, 'allows', ability('access-admin'))` |
 *
 * `PostPolicy` is the policy linked to `Post` with `@PolicyFor(Post)` (or the deprecated
 * `@Policy(Post)`), looked up when the application starts.
 */
export function Can(
  ability: string,
  resource?: Type<unknown>,
  options?: CanOptions,
): MethodDecorator & ClassDecorator {
  const requirement = (
    resource === undefined
      ? { policy: GatePolicy, ability: 'allows', args: staticCanArgs(ability) }
      : linkedRequirement(ability, resource, options?.classLevel === true)
  ) as OfficialCanRequirement;
  return (target: object, _key?: string | symbol, descriptor?: PropertyDescriptor) => {
    const host = descriptor ? (descriptor.value as object) : target;
    const existing = (Reflect.getMetadata(OFFICIAL_CAN_METADATA, host) as unknown[]) ?? [];
    Reflect.defineMetadata(OFFICIAL_CAN_METADATA, [requirement, ...existing], host);
  };
}

/**
 * A requirement whose `policy` is looked up when first read (at startup, by the
 * official registry's check), so `@Can('update', Post)` works whatever order the
 * policy and the controller are imported in.
 */
function linkedRequirement(
  ability: string,
  resource: Type<unknown>,
  classLevel: boolean,
): OfficialCanRequirement {
  const requirement = { ability } as OfficialCanRequirement;
  Object.defineProperty(requirement, 'policy', {
    enumerable: true,
    get(): Type<unknown> {
      const policy = policyForResource(resource);
      if (!policy) {
        throw new Error(
          `@Can('${ability}', ${resource.name}): no policy is linked to ${resource.name}. ` +
            `Decorate its policy with @PolicyFor(${resource.name}).`,
        );
      }
      return policy;
    },
  });
  if (!classLevel) requirement.args = byId(resource);
  return requirement;
}
