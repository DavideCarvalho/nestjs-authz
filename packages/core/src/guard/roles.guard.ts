import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Gate } from '../gate.js';
import { ROLES_METADATA } from '../tokens.js';

/**
 * Enforces `@Roles(...roles)` on routes.
 *
 * - No `@Roles` metadata → allow (the guard is inert on un-annotated routes).
 * - Otherwise allow when the current user holds ANY of the listed roles.
 *
 * The current user is resolved EXACTLY as the {@link Gate} does — from the optional
 * context accessor (nestjs-context) — and an unauthenticated request is denied by
 * default (`gate.hasAnyRole` returns `false` for a NO_USER caller). The verdict is
 * delegated to {@link Gate.hasAnyRole}; a denial throws `ForbiddenException`.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly gate: Gate,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.getAllAndOverride<string[] | undefined>(ROLES_METADATA, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (!roles || roles.length === 0) return true;
    if (await this.gate.hasAnyRole(roles)) return true;
    throw new ForbiddenException(`Unauthorized: requires one of [${roles.join(', ')}]`);
  }
}
