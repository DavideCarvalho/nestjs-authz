import { type DynamicModule, Module, type Provider } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { AuthzDenialFilter } from './authz-denial.filter.js';
import { AuthzInertiaInterceptor } from './authz-inertia.interceptor.js';
import { AUTHZ_INERTIA_OPTIONS } from './tokens.js';
import type { AuthzInertiaOptions } from './types.js';

/**
 * Wires the {@link AuthzInertiaInterceptor} as a global `APP_INTERCEPTOR` so every
 * Inertia render automatically carries `props.<propKey>.can` — the current user's
 * class-level abilities, resolved in-process (no network request).
 *
 * Requires `@dudousxd/nestjs-authz`'s `AuthzModule` (for `Gate`/`PolicyRegistry`)
 * and `@dudousxd/nestjs-inertia`'s `InertiaModule` (for `req.inertia`) to be
 * imported. Order does not matter; the interceptor no-ops when `req.inertia` is
 * absent.
 *
 * Alternatively, skip this module and pass `createAuthzShare(gate, policies)` to
 * `InertiaModule.forRoot({ share })` for the same result via inertia's own
 * prop-sharing seam.
 *
 * It also registers the {@link AuthzDenialFilter} as a global `APP_FILTER`, so
 * `@Roles`/`@Can` denials (`ForbiddenException`) redirect nicely on Inertia
 * requests (`/login` when unauthenticated, `/403` when forbidden) while staying
 * a normal 403 JSON for REST. Opt out via `forRoot({ denial: { enabled: false } })`.
 */
@Module({})
export class AuthzInertiaModule {
  static forRoot(options: AuthzInertiaOptions = {}): DynamicModule {
    const providers: Provider[] = [
      { provide: AUTHZ_INERTIA_OPTIONS, useValue: options },
      AuthzInertiaInterceptor,
      { provide: APP_INTERCEPTOR, useClass: AuthzInertiaInterceptor },
      AuthzDenialFilter,
      { provide: APP_FILTER, useClass: AuthzDenialFilter },
    ];
    return {
      module: AuthzInertiaModule,
      global: true,
      providers,
      exports: [AUTHZ_INERTIA_OPTIONS, AuthzInertiaInterceptor, AuthzDenialFilter],
    };
  }
}
