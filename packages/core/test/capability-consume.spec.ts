import { capability } from '@dudousxd/nestjs-diagnostics';
import { describe, expect, it } from 'vitest';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';

describe('nestjs-authz consumes context:accessor via the protocol', () => {
  it('CONTEXT_ACCESSOR resolves the identical cross-lib symbol', () => {
    expect(CONTEXT_ACCESSOR).toBe(capability('context', 'accessor'));
    expect(CONTEXT_ACCESSOR).toBe(Symbol.for('@dudousxd/nestjs-context:accessor'));
  });
});
