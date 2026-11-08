import { Can } from '@nestjs/authorization';
import { permission, roles } from '../helpers.js';
import { PermissionPolicy } from '../policies/permission.policy.js';
import { RolePolicy } from '../policies/role.policy.js';

/**
 * Sugar for the official `@Can(RolePolicy, 'has', roles(...names))`: the user holds any
 * of the roles. Stacks with other `@Can()`s (all must pass); a class-level `@Roles`
 * applies to every handler, together with the method's.
 */
export function Roles(...names: string[]): MethodDecorator & ClassDecorator {
  return Can(RolePolicy, 'has', roles(...names));
}

/** Sugar for the official `@Can(PermissionPolicy, 'has', permission(...names))`: any of the permissions. */
export function Permission(...names: string[]): MethodDecorator & ClassDecorator {
  return Can(PermissionPolicy, 'has', permission(...names));
}
