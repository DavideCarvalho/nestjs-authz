import { Policy } from '@nestjs/authorization';
import { AuthzRbac } from '../rbac.js';
import { AuthzPolicy, superAdminBefore } from './authz-policy.js';

/**
 * Persisted permissions (through roles, tenant-scoped roles, or granted directly) as an
 * official policy. Wildcard grants apply: `posts.*` satisfies `posts.update`.
 *
 * ```ts
 * @Can(PermissionPolicy, 'has', permission('posts.update'))
 * @Can(PermissionPolicy, 'hasAll', permission('posts.update', 'posts.publish'))
 * ```
 *
 * Honors `superAdmin`.
 */
@Policy()
export class PermissionPolicy extends AuthzPolicy {
  constructor(private readonly rbac: AuthzRbac) {
    super();
  }

  /**
   * Asks only `superAdmin`: the abilities here name permissions, not a resource, so the
   * external decision point is not consulted.
   */
  override before(user: unknown, ability: string): Promise<true | undefined> {
    return superAdminBefore(user, ability);
  }

  /** The user holds any of `permissions`. */
  async has(user: unknown, ...permissions: string[]): Promise<boolean> {
    for (const permission of permissions) {
      if (await this.rbac.grants(user, permission)) return true;
    }
    return false;
  }

  /** The user holds every one of `permissions`. */
  async hasAll(user: unknown, ...permissions: string[]): Promise<boolean> {
    if (permissions.length === 0) return false;
    for (const permission of permissions) {
      if (!(await this.rbac.grants(user, permission))) return false;
    }
    return true;
  }
}
