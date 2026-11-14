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

/** Sends a guest to the app's sign-in page instead of the console's bare 401. */
export interface ConsoleLoginOptions {
  /**
   * The app's sign-in path, for example `'/auth/login'`. When set, a guest (no user) gets
   * `{ redirectTo: '/auth/login?redirect=%2Fdurable' }`: a console page redirects there, and
   * a console API call answers 401 with that `redirectTo`, which the console follows. A
   * signed-in user without access still gets 403 (redirecting would loop). Must be a
   * same-origin path.
   */
  loginPath?: string;
  /** The query parameter carrying the way back. Default `'redirect'`. */
  redirectParam?: string;
}

function checkLoginPath(name: string, options: ConsoleLoginOptions | undefined): void {
  const path = options?.loginPath;
  if (path === undefined) return;
  if (
    typeof path !== 'string' ||
    !path.startsWith('/') ||
    path.startsWith('//') ||
    path.includes('\\') ||
    path.includes('#')
  ) {
    throw new Error(
      `${name}: \`loginPath\` must be a same-origin path without a fragment, such as '/auth/login'.`,
    );
  }
  const param = options?.redirectParam;
  if (param !== undefined && (typeof param !== 'string' || param.trim() === '')) {
    throw new Error(`${name}: \`redirectParam\` must be a non-empty string.`);
  }
}

/** The path (with query) of a same-origin URL, or `undefined`. */
function sameOriginPath(url: string, host: string | undefined): string | undefined {
  if (url.startsWith('/') && !url.startsWith('//')) return url;
  try {
    const parsed = new URL(url);
    return host !== undefined && parsed.host === host
      ? `${parsed.pathname}${parsed.search}`
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Where a guest goes back to after signing in: the page itself on a page load, the page that
 * made the call (`Referer`, same host only) on a console API call.
 */
function returnPath(context: ExecutionContext): string | undefined {
  const request = context.switchToHttp().getRequest<{
    headers?: Record<string, string | string[] | undefined>;
    originalUrl?: string;
    url?: string;
  }>();
  const header = (name: string): string | undefined => {
    const value = request?.headers?.[name];
    return Array.isArray(value) ? value[0] : value;
  };
  const host = header('host');
  if (header('accept')?.includes('text/html')) {
    const url = request?.originalUrl ?? request?.url;
    return typeof url === 'string' ? sameOriginPath(url, host) : undefined;
  }
  const referer = header('referer');
  return referer ? sameOriginPath(referer, host) : undefined;
}

function toLogin(
  result: ConsoleAuthorizeResult,
  context: ExecutionContext,
  options: ConsoleLoginOptions | undefined,
): ConsoleAuthorizeResult {
  const loginPath = options?.loginPath;
  if (
    loginPath === undefined ||
    typeof result !== 'object' ||
    !('reason' in result) ||
    result.reason !== 'unauthenticated'
  ) {
    return result;
  }
  const back = returnPath(context);
  if (back === undefined) return { redirectTo: loginPath };
  const separator = loginPath.includes('?') ? '&' : '?';
  const param = encodeURIComponent(options?.redirectParam ?? 'redirect');
  return { redirectTo: `${loginPath}${separator}${param}=${encodeURIComponent(back)}` };
}

/**
 * Allows a console to a user holding any of `roles` (persisted or on the user object, the
 * same check as `@Roles()`; `superAdmin` applies). A guest is `unauthenticated` (or sent to
 * `loginPath`), a user without the role `forbidden`.
 *
 * ```ts
 * DurableModule.forRoot({
 *   authorize: authorizeByRoles({ roles: ['admin'], loginPath: '/auth/login' }),
 * })
 * ```
 */
export function authorizeByRoles(
  options: { roles: readonly string[] } & ConsoleLoginOptions,
): ConsoleAuthorizerClass {
  const roles = [...(options?.roles ?? [])];
  if (roles.length === 0) {
    throw new Error('authorizeByRoles: `roles` must name at least one role.');
  }
  checkLoginPath('authorizeByRoles', options);

  @Injectable()
  class AuthorizeByRoles implements ConsoleAuthorizer {
    constructor(
      @Inject(Gate) private readonly gate: Gate,
      @Inject(AuthzConsoleGate) private readonly consoleGate: AuthzConsoleGate,
    ) {}

    async authorize(context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
      const result = await this.consoleGate.check(context, (user) =>
        this.gate.forUser(user).allows(RolePolicy, 'has', ...roles),
      );
      return toLogin(result, context, options);
    }
  }
  return AuthorizeByRoles;
}

/**
 * Allows a console to a user granted `permission` (persisted, through roles or directly,
 * wildcards apply; the same check as `@Permission()`; `superAdmin` applies).
 * A guest is `unauthenticated` (or sent to `loginPath`), a user without it `forbidden`.
 *
 * ```ts
 * TelescopeModule.forRoot({
 *   authorize: authorizeByPermission('telescope.view', { loginPath: '/auth/login' }),
 * })
 * ```
 */
export function authorizeByPermission(
  permission: string,
  options?: ConsoleLoginOptions,
): ConsoleAuthorizerClass {
  if (typeof permission !== 'string' || permission === '') {
    throw new Error('authorizeByPermission: `permission` must be a non-empty string.');
  }
  checkLoginPath('authorizeByPermission', options);

  @Injectable()
  class AuthorizeByPermission implements ConsoleAuthorizer {
    constructor(
      @Inject(Gate) private readonly gate: Gate,
      @Inject(AuthzConsoleGate) private readonly consoleGate: AuthzConsoleGate,
    ) {}

    async authorize(context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
      const result = await this.consoleGate.check(context, (user) =>
        this.gate.forUser(user).allows(PermissionPolicy, 'has', permission),
      );
      return toLogin(result, context, options);
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
