import { AuthorizationGuard } from '@nestjs/authorization';
import {
  type CanActivate,
  type ExecutionContext,
  Inject,
  Injectable,
  type OnModuleInit,
} from '@nestjs/common';
import { DiscoveryService } from '@nestjs/core';
import { routeRequirements } from './official.js';

/** The static brand `@nestjs/authorization` puts on `AuthorizationGuard` (and its subclasses). */
const OFFICIAL_GUARD_BRAND = Symbol.for('@nestjs/authorization:guard');

/**
 * The migration guard `AuthzModule.forRoot({ unannotated: 'allow' })` registers globally.
 *
 * A route with official `@Can()` requirements (on the class or the method, including
 * `@Roles` and `@Permission`, which write the same metadata) is
 * handed to the official `AuthorizationGuard` as is: the same evaluator, the same `getUser`,
 * the same 401/403, the same denied event. A route that declares no requirement is let
 * through, where the official guard would deny it. That lets an app turn authorization on
 * one controller at a time.
 *
 * It needs `AuthorizationModule.forRoot({ globalGuard: false })`: the official global guard
 * would still deny the unannotated routes. The application fails to start when both run.
 */
@Injectable()
export class AuthzGuard implements CanActivate {
  constructor(@Inject(AuthorizationGuard) private readonly official: AuthorizationGuard) {}

  canActivate(context: ExecutionContext): Promise<boolean> | boolean {
    if (routeRequirements(context.getClass(), context.getHandler()).length === 0) return true;
    return this.official.canActivate(context);
  }
}

/** True when `value` is the official `AuthorizationGuard` (or a subclass of it). */
function isOfficialGuard(value: unknown): boolean {
  const type = (value as { constructor?: Record<symbol, unknown> } | null)?.constructor;
  return typeof type === 'function' && type[OFFICIAL_GUARD_BRAND] === true;
}

/**
 * Fails the startup when `unannotated: 'allow'` is on and the official module still registers
 * its own global guard: that guard runs too, and denies every unannotated route, so the option
 * would do nothing.
 */
@Injectable()
export class AuthzGuardStartupCheck implements OnModuleInit {
  constructor(private readonly discovery: DiscoveryService) {}

  onModuleInit(): void {
    const officialGlobal = this.discovery
      .getProviders()
      .some(
        (wrapper) =>
          typeof wrapper.token === 'string' &&
          wrapper.token.startsWith('APP_GUARD') &&
          isOfficialGuard(wrapper.instance),
      );
    if (officialGlobal) {
      throw new Error(
        "AuthzModule: `unannotated: 'allow'` needs AuthorizationModule.forRoot({ globalGuard: false }). " +
          "The official global guard is registered too, and it denies every route that declares no @Can(), so 'allow' would have no effect.",
      );
    }
  }
}
