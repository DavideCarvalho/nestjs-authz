import { Policy } from '@nestjs/authorization';
import { AuthzRbac } from '../rbac.js';
import { AuthzPolicy, superAdminBefore } from './authz-policy.js';

/**
 * Persisted (and user-object) roles as an official policy.
 *
 * ```ts
 * @Can(RolePolicy, 'has', roles('admin', 'editor'))   // any of
 * @Can(RolePolicy, 'hasAll', roles('admin', 'editor')) // all of
 * ```
 *
 * Roles come from `user.roles` / `user.role` (or `resolveRoles`) and from the RBAC
 * adapter's role store, scoped to the current tenant. Honors `superAdmin`.
 */
@Policy()
export class RolePolicy extends AuthzPolicy {
  constructor(private readonly rbac: AuthzRbac) {
    super();
  }

  /**
   * Asks only `superAdmin`: the abilities here name roles, not a resource, so the
   * external decision point is not consulted.
   */
  override before(user: unknown, ability: string): Promise<true | undefined> {
    return superAdminBefore(user, ability);
  }

  /** The user holds any of `roles`. */
  has(user: unknown, ...roles: string[]): Promise<boolean> {
    return this.rbac.hasAnyRole(user, roles);
  }

  /** The user holds every one of `roles`. */
  hasAll(user: unknown, ...roles: string[]): Promise<boolean> {
    return this.rbac.hasAllRoles(user, roles);
  }
}
