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
