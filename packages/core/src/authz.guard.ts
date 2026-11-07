import { AuthorizationGuard } from '@nestjs/authorization';
import {
  type CanActivate,
  type ExecutionContext,
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleInit,
  type Type,
} from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants.js';
import { DiscoveryService, MetadataScanner } from '@nestjs/core';
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
 *
 * It deliberately does not carry the official guard's brand. `@nestjs/authorization` 0.1.3
 * recognizes a guard that enforces `@Can()` only by that brand, and with it every route this
 * guard lets through would be logged as "AuthorizationGuard denies every call to …". Without it,
 * the official module logs "@Can() is not enforced on …" for the routes this guard does enforce;
 * {@link AuthzGuardStartupCheck} explains that line right after it.
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

/** True when `guard` (a class from `@UseGuards()`, or an instance) carries the official brand. */
function isBrandedGuard(guard: unknown): boolean {
  const type =
    typeof guard === 'function' ? guard : (guard as { constructor?: unknown } | null)?.constructor;
  return (
    typeof type === 'function' &&
    Boolean((type as unknown as Record<symbol, unknown>)[OFFICIAL_GUARD_BRAND])
  );
}

const list = (wheres: string[]): string =>
  wheres.length > 3
    ? `${wheres.slice(0, 3).join(', ')} and ${wheres.length - 3} more`
    : wheres.join(', ');

/**
 * With `unannotated: 'allow'`:
 *
 * - fails the startup when the official module still registers its own global guard: that guard
 *   runs too, and denies every unannotated route, so the option would do nothing;
 * - after the official module's startup check, explains its "@Can() is not enforced on …" error.
 *   That check sees only `AuthorizationGuard` (by its brand), not the global `AuthzGuard` that
 *   enforces those routes, so it reports them at every boot in this mode.
 */
@Injectable()
export class AuthzGuardStartupCheck implements OnModuleInit, OnApplicationBootstrap {
  private readonly logger = new Logger('AuthzModule');

  constructor(
    private readonly discovery: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
  ) {}

  /** Runs after every `onModuleInit()`, so after the official error it explains. */
  onApplicationBootstrap(): void {
    const enforced = this.routesOnlyAuthzGuardEnforces();
    if (enforced.length === 0) return;
    const official = '"@Can() is not enforced on …"';
    this.logger.log(
      [
        `unannotated: 'allow': the global AuthzGuard enforces @Can() on ${list(enforced)}.`,
        `@nestjs/authorization logs ${official} for these handlers because it only recognizes`,
        'its own AuthorizationGuard; in this mode that error is expected. It goes away when you',
        "remove `unannotated: 'allow'` and turn the official global guard back on.",
      ].join(' '),
    );
  }

  /** Handlers with a `@Can()` requirement and no official guard of their own: AuthzGuard's alone. */
  private routesOnlyAuthzGuardEnforces(): string[] {
    const wheres: string[] = [];
    const seen = new Set<Type<unknown>>();
    for (const wrapper of [...this.discovery.getControllers(), ...this.discovery.getProviders()]) {
      const type = wrapper.metatype as Type<unknown> | undefined;
      if (typeof type !== 'function' || wrapper.isFactory || !type.prototype || seen.has(type)) {
        continue;
      }
      seen.add(type);
      const classGuards: unknown[] = Reflect.getMetadata(GUARDS_METADATA, type) ?? [];
      for (const key of this.metadataScanner.getAllMethodNames(type.prototype)) {
        const method = (type.prototype as Record<string, unknown>)[key];
        // An undecorated method under a class-level @Can() is a helper, not a handler.
        if (typeof method !== 'function' || Reflect.getOwnMetadataKeys(method).length === 0)
          continue;
        if (routeRequirements(type, method).length === 0) continue;
        const guards = [...classGuards, ...(Reflect.getMetadata(GUARDS_METADATA, method) ?? [])];
        if (!guards.some(isBrandedGuard)) wheres.push(`${type.name}.${key}`);
      }
    }
    return wheres;
  }

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
