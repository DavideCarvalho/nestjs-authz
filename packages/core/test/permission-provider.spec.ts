import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { AbilityNotResolvedException } from '../src/errors/exceptions.js';
import { Gate } from '../src/gate.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';

/**
 * The RBAC seam: a PermissionProvider grants named, model-less abilities
 * (`gate.allows('posts.publish')`) when the current user holds that permission.
 * The provider is passed positionally as the 5th Gate ctor arg (after moduleRef).
 */
function gateWithProvider(provider: PermissionProvider): Gate {
  return new Gate(new PolicyRegistry(), {}, undefined, undefined, provider);
}

describe('PermissionProvider seam (RBAC ↔ Gate)', () => {
  const provider: PermissionProvider = {
    hasPermission(user, permission) {
      const perms = (user as { perms?: string[] }).perms ?? [];
      return perms.includes(permission);
    },
  };

  it('grants a model-less ability when the user holds the permission', async () => {
    const gate = gateWithProvider(provider);
    expect(await gate.forUser({ perms: ['posts.publish'] }).allows('posts.publish')).toBe(true);
  });

  it('falls through (throws unresolved) when the user lacks the permission', async () => {
    const gate = gateWithProvider(provider);
    await expect(gate.forUser({ perms: [] }).allows('posts.publish')).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });

  it('does not grant for an anonymous (NO_USER) caller', async () => {
    const gate = gateWithProvider(provider);
    // No forUser, no context accessor → NO_USER → provider is skipped → deny path.
    await expect(gate.allows('posts.publish')).rejects.toBeInstanceOf(AbilityNotResolvedException);
  });

  it('is grant-only: a false result never overrides an ad-hoc gate that allows', async () => {
    const gate = gateWithProvider({ hasPermission: () => false });
    gate.define('ping', () => true);
    expect(await gate.forUser({ id: 1 }).allows('ping')).toBe(true);
  });

  it('with no provider, behavior is unchanged (unknown ability throws)', async () => {
    const gate = new Gate(new PolicyRegistry(), {}, undefined);
    await expect(gate.forUser({}).allows('posts.publish')).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });
});

describe('PermissionProvider wildcard / hierarchical grants (getPermissions seam)', () => {
  // A provider that lists the user's granted permissions (each possibly a wildcard
  // pattern). The core applies segment-based matching against this set.
  const wildcardProvider: PermissionProvider = {
    hasPermission: () => false, // exact path defers entirely to getPermissions here
    getPermissions(user) {
      return (user as { perms?: string[] }).perms ?? [];
    },
  };

  it('exact match grant satisfies the check', async () => {
    const gate = gateWithProvider(wildcardProvider);
    expect(await gate.forUser({ perms: ['posts.update'] }).allows('posts.update')).toBe(true);
  });

  it('posts.* grant satisfies posts.update', async () => {
    const gate = gateWithProvider(wildcardProvider);
    expect(await gate.forUser({ perms: ['posts.*'] }).allows('posts.update')).toBe(true);
  });

  it('* grant satisfies anything', async () => {
    const gate = gateWithProvider(wildcardProvider);
    expect(await gate.forUser({ perms: ['*'] }).allows('comments.delete')).toBe(true);
  });

  it('posts.* grant does NOT satisfy comments.update (non-match → unresolved)', async () => {
    const gate = gateWithProvider(wildcardProvider);
    await expect(
      gate.forUser({ perms: ['posts.*'] }).allows('comments.update'),
    ).rejects.toBeInstanceOf(AbilityNotResolvedException);
  });

  it('falls back to hasPermission exact path when getPermissions yields no match', async () => {
    // getPermissions returns a non-matching set; hasPermission grants the exact name.
    const mixed: PermissionProvider = {
      hasPermission: (_u, permission) => permission === 'posts.publish',
      getPermissions: () => ['comments.*'],
    };
    const gate = gateWithProvider(mixed);
    expect(await gate.forUser({}).allows('posts.publish')).toBe(true);
  });

  it('still skipped for an anonymous (NO_USER) caller', async () => {
    const gate = gateWithProvider(wildcardProvider);
    await expect(gate.allows('posts.update')).rejects.toBeInstanceOf(AbilityNotResolvedException);
  });
});
