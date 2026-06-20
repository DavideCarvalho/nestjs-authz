import { assertCapabilityNaming, capability } from '@dudousxd/nestjs-diagnostics';
import { describe, expect, it } from 'vitest';
import {
  AUTHZ_MODULE_OPTIONS,
  PERMISSION_PROVIDER,
  RESOURCE_HYDRATOR,
  RESOURCE_RESOLVER,
  ROLE_PROVIDER,
} from '../src/tokens.js';

describe('nestjs-authz capability tokens', () => {
  it('all own tokens follow the canonical @dudousxd/nestjs-authz: naming', () => {
    expect(() =>
      assertCapabilityNaming('authz', {
        AUTHZ_MODULE_OPTIONS,
        RESOURCE_RESOLVER,
        RESOURCE_HYDRATOR,
        PERMISSION_PROVIDER,
        ROLE_PROVIDER,
      }),
    ).not.toThrow();
  });

  it('tokens resolve the exact pre-migration symbols (non-breaking)', () => {
    expect(AUTHZ_MODULE_OPTIONS).toBe(Symbol.for('@dudousxd/nestjs-authz:options'));
    expect(PERMISSION_PROVIDER).toBe(capability('authz', 'permission-provider'));
  });
});
