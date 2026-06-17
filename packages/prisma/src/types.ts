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
