import type { User } from './types.js';

/**
 * Optional seam that lets a persisted RBAC layer supply a user's roles.
 *
 * This mirrors {@link PermissionProvider} but for COARSE, role-based checks
 * (`gate.hasRole('teacher')`, `@Roles('admin')`). The core does NOT implement
 * this — `@dudousxd/nestjs-authz-typeorm` (and the other RBAC adapters) provide an
 * implementation and register it under the shared {@link ROLE_PROVIDER} token.
 * When no provider is registered the default {@link RoleResolver} (reading roles
 * off the user object) is the only source.
 *
 * `user` is the current user (whatever the app's auth layer produced; `undefined`
 * when anonymous). Return the role names the user holds — an empty array (or
 * nullish) contributes no roles. When both this provider and the default resolver
 * yield roles, the Gate takes their UNION.
 */
export interface RoleProvider {
  getRoles(user: User): string[] | undefined | Promise<string[] | undefined>;
  /**
   * Optional: where the user's roles and permissions come from, for the dev tools
   * (`authz_explain_check`). The RBAC adapters implement it; `undefined` for a user they
   * cannot map.
   */
  describeRbac?(user: User): Promise<RbacDescription | undefined>;
}

/** What {@link RoleProvider.describeRbac} answers: the RBAC store's view of one user. */
export interface RbacDescription {
  /** The tenant scope the lookups ran in; `null` = the global scope. */
  tenantId: string | null;
  /**
   * Every tenant whose roles and grants applied, root first: the levels of a nested tenant
   * the module honours (the last is `tenantId`). Empty for the global scope.
   */
  tenantChain?: string[];
  /** Role names by where they come from: assigned in the store, or mapped by `tenancy.roles`. */
  roles: { store: string[]; tenant: string[] };
  /** Permissions of each of those roles in the store. */
  rolePermissions: Record<string, string[]>;
  /** Every permission granted in that scope: role-derived plus direct grants. */
  permissions: string[];
}

/**
 * Strategy that derives a user's roles from the user object itself, with ZERO RBAC
 * tables. The {@link defaultRoleResolver} reads `user.roles` (`string[]`) OR
 * `user.role` (`string | string[]`) and normalizes both to a `string[]`. Apps that
 * already carry a role on the user thus get role-checks for free; an app that needs
 * a different shape overrides it via `AuthzModule.forRoot({ resolveRoles })`.
 */
export type RoleResolver = (user: User) => string[] | undefined | Promise<string[] | undefined>;

/**
 * Default {@link RoleResolver}: read roles directly off the user object.
 *
 * - `user.roles` is a `string[]` → used as-is.
 * - `user.role` is a `string` → wrapped to `[role]`.
 * - `user.role` is a `string[]` → used as-is.
 * - neither present (or anonymous) → `[]` (no roles).
 *
 * Non-string entries are filtered out so a malformed field can never leak a
 * truthy match.
 */
export function defaultRoleResolver(user: User): string[] {
  if (user == null || typeof user !== 'object') return [];
  const u = user as { roles?: unknown; role?: unknown };
  const out: string[] = [];
  if (Array.isArray(u.roles)) {
    for (const r of u.roles) if (typeof r === 'string') out.push(r);
  }
  if (typeof u.role === 'string') {
    out.push(u.role);
  } else if (Array.isArray(u.role)) {
    for (const r of u.role) if (typeof r === 'string') out.push(r);
  }
  return out;
}
