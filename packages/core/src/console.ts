import { createHash, timingSafeEqual } from 'node:crypto';
import {
  AUTHORIZATION_MODULE_OPTIONS,
  type AuthorizationModuleOptions,
  defaultGetUser,
} from '@nestjs/authorization';
import {
  type ExecutionContext,
  Inject,
  Injectable,
  Logger,
  Optional,
  type Type,
} from '@nestjs/common';
import { AbilityNotResolvedException } from './errors/exceptions.js';
import { Gate } from './gate.js';
import { PermissionPolicy } from './policies/permission.policy.js';
import { RolePolicy } from './policies/role.policy.js';
import { AuthzRbac } from './rbac.js';
import { runWithoutRequiredTenant } from './tenant-override.js';
import type { User } from './types.js';

// --- The Aviary console access contract (each console lib declares the same shapes) ---

/** What a console `authorize` check answers. */
export type ConsoleAuthorizeResult =
  | boolean
  | { allowed: true }
  | { allowed: false; reason?: 'unauthenticated' | 'forbidden' }
  | { redirectTo: string };

/** Class form: an `@Injectable()` provider (constructor injection works). */
export interface ConsoleAuthorizer {
  authorize(context: ExecutionContext): ConsoleAuthorizeResult | Promise<ConsoleAuthorizeResult>;
}
export type ConsoleAuthorizerClass = Type<ConsoleAuthorizer>;

/** `@nestjs/authorization` policy check: `policy[ability](user)`. */
export interface ConsolePolicyCheck {
  policy: Type<unknown>;
  ability: string;
}

/** The `authorize` option of every Aviary console. */
export type ConsoleAuthorize =
  | ((context: ExecutionContext) => ConsoleAuthorizeResult | Promise<ConsoleAuthorizeResult>)
  | ConsoleAuthorizerClass
  | (() => Promise<{ default: ConsoleAuthorizerClass }>)
  | ConsolePolicyCheck
  | string;

/**
 * The token Aviary consoles resolve `authorize: '<gate name>'` through. `AuthzModule`
 * provides it globally.
 */
export const CONSOLE_GATE = Symbol.for('@dudousxd/aviary:console-gate');

/** A fresh denial per call, so no caller can mutate a shared result. */
const unauthenticated = (): ConsoleAuthorizeResult => ({
  allowed: false,
  reason: 'unauthenticated',
});

/**
 * Answers console checks with the `Gate`, for the user the authorization guard sees:
 * the official `getUser` (by default `request.user`), else the `Gate`'s ambient user
 * (`@nestjs/authentication`'s `AuthenticationContext`, else nestjs-context's user ref).
 */
@Injectable()
export class AuthzConsoleGate {
  private readonly logger = new Logger('AuthzConsoleGate');

  constructor(
    private readonly gate: Gate,
    private readonly rbac: AuthzRbac,
    @Optional()
    @Inject(AUTHORIZATION_MODULE_OPTIONS)
    private readonly official?: AuthorizationModuleOptions,
  ) {}

  /** The user of this call, or `null` for a guest. */
  async userOf(context: ExecutionContext): Promise<User> {
    const getUser = this.official?.getUser ?? defaultGetUser;
    const user = await getUser(context);
    // The official contract: only `undefined` means "not answered here, look further".
    // `null` (and Passport's `false`) is an answer: a guest, never promoted to the ambient user.
    if (user === null || user === false) return null;
    if (user !== undefined) return user;
    return (await this.rbac.currentUser()) ?? null;
  }

  /**
   * `gate.forUser(user).allows(name)`; a denied guest is `unauthenticated`. A name the `Gate`
   * cannot resolve denies (fail-closed) and logs a warning, so a typo'd gate name shows up in
   * the logs instead of becoming a 500.
   */
  async allows(name: string, context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
    return this.check(context, async (user) => {
      try {
        return await this.gate.forUser(user).allows(name);
      } catch (error) {
        if (!(error instanceof AbilityNotResolvedException)) throw error;
        this.logger.warn(
          `console authorize: gate "${name}" resolves to nothing (no \`gate.define('${name}', …)\`, policy or permission); denying.`,
        );
        return false;
      }
    });
  }

  /** @internal Runs `test` for the call's user and turns the answer into a console result. */
  async check(
    context: ExecutionContext,
    test: (user: User) => Promise<boolean>,
  ): Promise<ConsoleAuthorizeResult> {
    const user = await this.userOf(context);
    // Console access is not a tenant-scoped read: `tenancy.required` never denies it.
    if (await runWithoutRequiredTenant(() => test(user))) return true;
    return user === null ? unauthenticated() : false;
  }
}

/**
 * Allows a console to a user holding any of `roles` (persisted or on the user object, the
 * same check as `@Roles()`; `superAdmin` applies). A guest is `unauthenticated`, a user
 * without the role `forbidden`.
 *
 * ```ts
 * DurableModule.forRoot({ authorize: authorizeByRoles({ roles: ['admin'] }) })
 * ```
 */
export function authorizeByRoles(options: { roles: readonly string[] }): ConsoleAuthorizerClass {
  const roles = [...(options?.roles ?? [])];
  if (roles.length === 0) {
    throw new Error('authorizeByRoles: `roles` must name at least one role.');
  }

  @Injectable()
  class AuthorizeByRoles implements ConsoleAuthorizer {
    constructor(
      @Inject(Gate) private readonly gate: Gate,
      @Inject(AuthzConsoleGate) private readonly consoleGate: AuthzConsoleGate,
    ) {}

    authorize(context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
      return this.consoleGate.check(context, (user) =>
        this.gate.forUser(user).allows(RolePolicy, 'has', ...roles),
      );
    }
  }
  return AuthorizeByRoles;
}

/**
 * Allows a console to a user granted `permission` (persisted, through roles or directly,
 * wildcards apply; the same check as `@Permission()`; `superAdmin` applies).
 * A guest is `unauthenticated`, a user without it `forbidden`.
 *
 * ```ts
 * TelescopeModule.forRoot({ authorize: authorizeByPermission('telescope.view') })
 * ```
 */
export function authorizeByPermission(permission: string): ConsoleAuthorizerClass {
  if (typeof permission !== 'string' || permission === '') {
    throw new Error('authorizeByPermission: `permission` must be a non-empty string.');
  }

  @Injectable()
  class AuthorizeByPermission implements ConsoleAuthorizer {
    constructor(
      @Inject(Gate) private readonly gate: Gate,
      @Inject(AuthzConsoleGate) private readonly consoleGate: AuthzConsoleGate,
    ) {}

    authorize(context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
      return this.consoleGate.check(context, (user) =>
        this.gate.forUser(user).allows(PermissionPolicy, 'has', permission),
      );
    }
  }
  return AuthorizeByPermission;
}

const sha256 = (value: string): Buffer => createHash('sha256').update(value).digest();

/**
 * Allows a console to calls sending `Authorization: Bearer <token>` (compared in constant
 * time). Anything else is `unauthenticated`. Throws when `token` is empty.
 *
 * ```ts
 * authorize: authorizeByToken({ token: process.env.CONSOLE_TOKEN })
 * ```
 */
export function authorizeByToken(options: {
  token: string | undefined;
}): (context: ExecutionContext) => ConsoleAuthorizeResult {
  const token = options?.token;
  if (typeof token !== 'string' || token === '') {
    throw new Error('authorizeByToken: `token` is empty. Set it (for example from an env var).');
  }
  const expected = sha256(token);
  return (context) => {
    const header = context.switchToHttp().getRequest<{
      headers?: Record<string, string | string[] | undefined>;
    }>()?.headers?.authorization;
    const value = Array.isArray(header) ? header[0] : header;
    const match = typeof value === 'string' ? /^Bearer\s+(.+)$/i.exec(value.trim()) : null;
    if (!match?.[1]) return unauthenticated();
    return timingSafeEqual(sha256(match[1]), expected) ? true : unauthenticated();
  };
}
