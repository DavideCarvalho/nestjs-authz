// packages/core/src/store-kit.ts
//
// The shared persistence contract for ORM-backed RBAC stores (typeorm/prisma/
// mikro-orm adapters). Exposed via the `@dudousxd/nestjs-authz/store-kit` subpath
// rather than the main barrel, because the barrel already exports a different
// `UserRef` (nestjs-context's `{ type, id }` shape). The adapters re-export these
// under their own public names so a single definition can't drift across them.

/**
 * A reference to a user. Matches nestjs-context's `UserRef` shape (`{ type, id }`),
 * but the store accepts either a full ref or a bare id (defaulting `type` to `'user'`).
 */
export interface UserRefInput {
  type?: string;
  id: string | number;
}

/** A user reference, or just its id (treated as `{ type: 'user', id }`). */
export type UserRef = UserRefInput | string | number;

/**
 * A user's effective permissions: the role names they hold and the flattened set of
 * permission names granted by those roles.
 */
export interface UserAuthz {
  roles: string[];
  permissions: string[];
}

/** Normalize a {@link UserRef} to `{ type, id }` with `id` stringified. */
export function normalizeUserRef(ref: UserRef): { type: string; id: string } {
  if (typeof ref === 'string' || typeof ref === 'number') {
    return { type: 'user', id: String(ref) };
  }
  return { type: ref.type ?? 'user', id: String(ref.id) };
}

/**
 * The source recorded on a role assignment when none is given — assignments made by hand
 * (`assignRole`) and every row that predates per-source assignments.
 */
export const DEFAULT_ROLE_SOURCE = 'manual';

/** One persisted role assignment, as returned by the adapters' `getRoleAssignments`. */
export interface RoleAssignment {
  /** Role name. */
  role: string;
  /**
   * Where the assignment came from (`'manual'`, `'sso'`, `'scim'`, …). A role held through two
   * sources is two assignments — removing one source keeps the role.
   */
  source: string;
  /** Tenant the assignment is scoped to, or `null` for a global one (tenant-aware adapters). */
  tenantId: string | null;
}

/**
 * One persisted role assignment together with the user holding it — a raw row of the
 * user↔role pivot, as returned by the adapters' `listRoleAssignments` (admin listings such as
 * "every member's roles in tenant T" or "who holds role R").
 */
export interface UserRoleAssignment extends RoleAssignment {
  /** The user's type (`'user'` unless the assignment was made with a typed {@link UserRef}). */
  userType: string;
  /** The user's id, stringified. */
  userId: string;
}

/** Filter for the adapters' `listRoleAssignments`. Every field is optional; they AND together. */
export interface RoleAssignmentFilter {
  /**
   * Tenant filter:
   * - `undefined` (omitted): no tenant filter — global AND every tenant's assignments;
   * - `null`: GLOBAL assignments only;
   * - a string: exactly that tenant's scoped assignments. Global assignments are NOT included
   *   (unlike the permission checks, where a global assignment applies in every tenant) — pass
   *   `null` in a second call when you need them too.
   *
   * Adapters without tenant support store every assignment as global, so a string matches nothing.
   */
  tenantId?: string | null;
  /** Only assignments of this role, or of any of these roles (an empty list matches nothing). */
  role?: string | readonly string[];
  /** Only this user's assignments. */
  user?: UserRef;
  /** Only assignments from this source (`'manual'`, `'sso'`, …). */
  source?: string;
}

/** Normalize {@link RoleAssignmentFilter.role} to a list (`undefined` = no role filter). */
export function roleFilterNames(role: RoleAssignmentFilter['role']): string[] | undefined {
  if (role === undefined) return undefined;
  return typeof role === 'string' ? [role] : [...new Set(role)];
}

/**
 * Deterministic order for `listRoleAssignments` rows: `(userType, userId, role, source, tenantId)`,
 * by code unit (not locale), so every adapter returns the same order for the same data.
 */
export function compareUserRoleAssignments(a: UserRoleAssignment, b: UserRoleAssignment): number {
  const keys = (x: UserRoleAssignment) => [
    x.userType,
    x.userId,
    x.role,
    x.source,
    x.tenantId ?? '',
  ];
  const ka = keys(a);
  const kb = keys(b);
  for (let i = 0; i < ka.length; i++) {
    const l = ka[i] as string;
    const r = kb[i] as string;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}
