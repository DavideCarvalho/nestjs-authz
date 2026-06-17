import 'reflect-metadata';
import type { ContextAccessor } from '@dudousxd/nestjs-authz';
import { type ArgumentsHost, ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { AuthzDenialFilter } from '../src/authz-denial.filter.js';
import type { AuthzInertiaOptions } from '../src/types.js';

/** Captures status/Location/end from an Express-shaped response. */
function fakeRes() {
  return {
    statusCode: undefined as number | undefined,
    location: undefined as string | undefined,
    ended: false,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    setHeader(name: string, value: string) {
      if (name === 'Location') this.location = value;
    },
    end() {
      this.ended = true;
    },
  };
}

/** Builds a minimal HTTP `ArgumentsHost` over a header bag + response. */
function httpHost(headers: Record<string, string>, res: unknown): ArgumentsHost {
  const req = { headers };
  return {
    getType: () => 'http',
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => res,
    }),
  } as unknown as ArgumentsHost;
}

const accessorWithUser: ContextAccessor = {
  traceId: () => undefined,
  tenantId: () => undefined,
  userRef: () => ({ type: 'User', id: 1 }),
  get: () => undefined,
};

const accessorNoUser: ContextAccessor = {
  traceId: () => undefined,
  tenantId: () => undefined,
  userRef: () => undefined,
  get: () => undefined,
};

const denial = new ForbiddenException('Unauthorized: requires one of [admin]');

describe('AuthzDenialFilter', () => {
  it('Inertia request + denied + no user → 303 redirect to /login', () => {
    const res = fakeRes();
    const filter = new AuthzDenialFilter({}, accessorNoUser);

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.statusCode).toBe(303);
    expect(res.location).toBe('/login');
    expect(res.ended).toBe(true);
  });

  it('Inertia request + denied + user present → 303 redirect to /403', () => {
    const res = fakeRes();
    const filter = new AuthzDenialFilter({}, accessorWithUser);

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.statusCode).toBe(303);
    expect(res.location).toBe('/403');
    expect(res.ended).toBe(true);
  });

  it('non-Inertia request + denied → ForbiddenException passes through (no redirect)', () => {
    const res = fakeRes();
    const filter = new AuthzDenialFilter({}, accessorNoUser);

    expect(() => filter.catch(denial, httpHost({}, res))).toThrow(denial);
    expect(res.statusCode).toBeUndefined();
    expect(res.location).toBeUndefined();
    expect(res.ended).toBe(false);
  });

  it('honors a custom forbiddenUrl', () => {
    const res = fakeRes();
    const options: AuthzInertiaOptions = { denial: { forbiddenUrl: '/no-access' } };
    const filter = new AuthzDenialFilter(options, accessorWithUser);

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.statusCode).toBe(303);
    expect(res.location).toBe('/no-access');
  });

  it('honors a custom loginUrl', () => {
    const res = fakeRes();
    const options: AuthzInertiaOptions = { denial: { loginUrl: '/auth/sign-in' } };
    const filter = new AuthzDenialFilter(options, accessorNoUser);

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.location).toBe('/auth/sign-in');
  });

  it('honors a custom handler escape hatch (no redirect emitted)', () => {
    const res = fakeRes();
    const handler = vi.fn();
    const options: AuthzInertiaOptions = { denial: { handler } };
    const filter = new AuthzDenialFilter(options, accessorWithUser);

    const host = httpHost({ 'x-inertia': 'true' }, res);
    filter.catch(denial, host);

    expect(handler).toHaveBeenCalledWith(denial, host);
    expect(res.statusCode).toBeUndefined();
    expect(res.ended).toBe(false);
  });

  it('enabled: false rethrows even on an Inertia request', () => {
    const res = fakeRes();
    const options: AuthzInertiaOptions = { denial: { enabled: false } };
    const filter = new AuthzDenialFilter(options, accessorNoUser);

    expect(() => filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res))).toThrow(denial);
    expect(res.statusCode).toBeUndefined();
  });

  it('treats a missing context accessor as unauthenticated → /login', () => {
    const res = fakeRes();
    const filter = new AuthzDenialFilter({});

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.location).toBe('/login');
  });

  it('falls back to the safe default when a configured target is unsafe', () => {
    const res = fakeRes();
    const options: AuthzInertiaOptions = { denial: { forbiddenUrl: 'https://evil.com/phish' } };
    const filter = new AuthzDenialFilter(options, accessorWithUser);

    filter.catch(denial, httpHost({ 'x-inertia': 'true' }, res));

    expect(res.location).toBe('/403');
  });
});
