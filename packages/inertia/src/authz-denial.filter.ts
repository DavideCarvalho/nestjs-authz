import { CONTEXT_ACCESSOR, type ContextAccessor } from '@dudousxd/nestjs-authz';
import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  ForbiddenException,
  Inject,
  Optional,
} from '@nestjs/common';
import { AUTHZ_INERTIA_OPTIONS } from './tokens.js';
import type { AuthzDenialOptions, AuthzInertiaOptions } from './types.js';

/**
 * Default redirect target for an UNAUTHENTICATED Inertia denial.
 */
export const DEFAULT_LOGIN_URL = '/login';

/**
 * Default redirect target for an AUTHENTICATED-but-FORBIDDEN Inertia denial.
 */
export const DEFAULT_FORBIDDEN_URL = '/403';

/**
 * Catches authorization denials (`@Roles`/`@Can` → `ForbiddenException`) and, on
 * an Inertia request (`X-Inertia` header), 303-redirects to a friendly page
 * instead of bubbling a raw 403. Mirrors the structure of nestjs-inertia's
 * `InertiaValidationFilter`: detect the Inertia request via the `X-Inertia`
 * header, issue a safe same-origin redirect (303 + `Location`), and rethrow
 * everything else so normal Nest handling (JSON 403) applies — preserving REST
 * clients.
 *
 * Redirect targets are decided by auth-state, read from the OPTIONAL
 * `CONTEXT_ACCESSOR` (`userRef()` undefined → unauthenticated):
 * - unauthenticated → `loginUrl` (default `/login`)
 * - authenticated but forbidden → `forbiddenUrl` (default `/403`)
 *
 * Registered unconditionally as an `APP_FILTER` by
 * `AuthzInertiaModule.forRoot`; on by default and disabled via
 * `forRoot({ denial: { enabled: false } })`. A `handler(exception, host)`
 * escape hatch fully overrides the behavior on Inertia requests.
 */
@Catch(ForbiddenException)
export class AuthzDenialFilter implements ExceptionFilter {
  constructor(
    @Optional()
    @Inject(AUTHZ_INERTIA_OPTIONS)
    private readonly options: AuthzInertiaOptions = {},
    @Optional()
    @Inject(CONTEXT_ACCESSOR)
    private readonly context?: ContextAccessor,
  ) {}

  catch(exception: ForbiddenException, host: ArgumentsHost): void {
    const denial: AuthzDenialOptions = this.options.denial ?? {};

    // Disabled, or non-HTTP context: rethrow so normal Nest handling applies.
    if (denial.enabled === false || host.getType() !== 'http') {
      throw exception;
    }

    const http = host.switchToHttp();
    const req = http.getRequest<unknown>();
    const res = http.getResponse<unknown>();

    // Gate: only Inertia requests. Else rethrow → normal 403 JSON for REST.
    if (!getHeader(req, 'X-Inertia')) {
      throw exception;
    }

    // Escape hatch: a custom handler takes full control on Inertia requests.
    if (denial.handler) {
      denial.handler(exception, host);
      return;
    }

    const target = this.resolveRedirectTarget(denial);
    sendRedirect(res, 303, target);
  }

  /**
   * Pick the redirect target from auth-state. An undefined `userRef()` (or no
   * context accessor at all) is treated as unauthenticated.
   */
  private resolveRedirectTarget(denial: AuthzDenialOptions): string {
    const loginUrl = denial.loginUrl ?? DEFAULT_LOGIN_URL;
    const forbiddenUrl = denial.forbiddenUrl ?? DEFAULT_FORBIDDEN_URL;
    const authenticated = this.context?.userRef() !== undefined;
    const target = authenticated ? forbiddenUrl : loginUrl;
    return toSafePath(target, authenticated ? DEFAULT_FORBIDDEN_URL : DEFAULT_LOGIN_URL);
  }
}

/**
 * Reduce a configured target to a safe same-origin path via the same
 * open-redirect guard nestjs-inertia uses (`validateLocationUrl`), falling back
 * to a known-safe default if the target is rejected.
 */
function toSafePath(target: string, fallback: string): string {
  try {
    return validateLocationUrl(target);
  } catch {
    return fallback;
  }
}

/**
 * Local mirror of nestjs-inertia's `getHeader`. Reads a request header in a
 * cross-runtime way (Express `req.header(name)` / raw Fastify `req.headers`).
 * The package couples to nestjs-inertia STRUCTURALLY (request/response shape),
 * so this is replicated rather than imported.
 */
function getHeader(req: unknown, name: string): string | undefined {
  const r = req as {
    header?: (n: string) => string | undefined;
    headers?: Record<string, string | string[] | undefined>;
  };
  if (typeof r.header === 'function') return r.header(name);
  const v = r.headers?.[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Local mirror of nestjs-inertia's `validateLocationUrl` open-redirect guard.
 * Only relative URLs (single leading `/`) or recognizable relative paths are
 * permitted; absolute/protocol-relative/unsafe-scheme URLs throw.
 */
function validateLocationUrl(url: string): string {
  if (url.startsWith('/') && !url.startsWith('//')) return url;
  if (url.startsWith('//')) {
    throw new Error(
      `[nestjs-authz-inertia] denial redirect rejected protocol-relative URL: ${url}`,
    );
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`[nestjs-authz-inertia] denial redirect rejected unsafe URL scheme: ${url}`);
    }
    throw new Error(
      `[nestjs-authz-inertia] denial redirect rejected absolute URL to external host: ${url}.`,
    );
  } catch (err) {
    if (err instanceof TypeError) {
      if (/^[a-zA-Z0-9]/.test(url) || url.startsWith('.')) {
        return url;
      }
      throw new Error(`[nestjs-authz-inertia] denial redirect rejected unrecognized URL: ${url}`);
    }
    throw err;
  }
}

/**
 * Local mirror of nestjs-inertia's cross-runtime redirect emit. Sets the status
 * code + `Location` header and ends the response, duck-typing Express
 * (`status`/`setHeader`/`end`) vs raw Fastify (`code`/`header`/`send`).
 */
function sendRedirect(res: unknown, status: number, url: string): void {
  const r = res as {
    status?: (code: number) => unknown;
    code?: (code: number) => unknown;
    setHeader?: (name: string, value: string) => unknown;
    header?: (name: string, value: string) => unknown;
    end?: () => unknown;
    send?: (body?: unknown) => unknown;
  };

  if (typeof r.status === 'function') {
    r.status(status);
  } else if (typeof r.code === 'function') {
    r.code(status);
  }

  if (typeof r.setHeader === 'function') {
    r.setHeader('Location', url);
  } else if (typeof r.header === 'function') {
    r.header('Location', url);
  }

  if (typeof r.end === 'function') {
    r.end();
  } else if (typeof r.send === 'function') {
    r.send();
  }
}
