import 'reflect-metadata';
import { SetMetadata } from '@nestjs/common';
import { ROLES_METADATA } from '../tokens.js';

/**
 * Guard a route by COARSE role membership: the request is allowed when the current
 * user holds ANY of the listed roles. This is the broad "is teacher?" check, as
 * opposed to the granular ability check of `@Can`.
 *
 * Roles come from the user object (`user.roles` / `user.role`) by default, plus the
 * optional `ROLE_PROVIDER` seam (a persisted RBAC store) when registered — see
 * {@link RolesGuard}.
 *
 * @example
 *   `@Roles('admin', 'teacher')`  // allow if the user is an admin OR a teacher
 */
export function Roles(...roles: string[]): MethodDecorator & ClassDecorator {
  return SetMetadata(ROLES_METADATA, roles);
}
