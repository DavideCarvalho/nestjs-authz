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
