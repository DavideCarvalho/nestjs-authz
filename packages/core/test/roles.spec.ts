import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import type { RoleProvider } from '../src/role-provider.js';
import type { AuthzModuleOptions } from '../src/types.js';

function makeGate(options: AuthzModuleOptions = {}, roleProvider?: RoleProvider): Gate {
  // ctor: (policies, options, context, moduleRef, permissionProvider, roleProvider)
  return new Gate(new PolicyRegistry(), options, undefined, undefined, undefined, roleProvider);
}

describe('Gate role checks (default resolver)', () => {
  it('reads roles off user.roles (string[])', async () => {
    const gate = makeGate();
    expect(await gate.forUser({ roles: ['teacher', 'admin'] }).hasRole('teacher')).toBe(true);
    expect(await gate.forUser({ roles: ['teacher'] }).hasRole('admin')).toBe(false);
  });

  it('reads roles off user.role (string)', async () => {
    const gate = makeGate();
    expect(await gate.forUser({ role: 'admin' }).hasRole('admin')).toBe(true);
    expect(await gate.forUser({ role: 'student' }).hasRole('admin')).toBe(false);
  });

  it('reads roles off user.role (string[])', async () => {
    const gate = makeGate();
    expect(await gate.forUser({ role: ['a', 'b'] }).hasAnyRole(['b', 'c'])).toBe(true);
    expect(await gate.forUser({ role: ['a'] }).hasAnyRole(['b', 'c'])).toBe(false);
  });

  it('hasAnyRole allows when ANY listed role matches', async () => {
    const gate = makeGate();
    expect(await gate.forUser({ roles: ['teacher'] }).hasAnyRole(['admin', 'teacher'])).toBe(true);
  });

  it('a user with no roles is denied', async () => {
    const gate = makeGate();
    expect(await gate.forUser({ id: 1 }).hasRole('admin')).toBe(false);
    expect(await gate.forUser({ roles: [] }).hasRole('admin')).toBe(false);
  });

  it('an anonymous (NO_USER / context-less) caller is denied', async () => {
    const gate = makeGate();
    // No forUser, no context accessor → NO_USER → deny.
    expect(await gate.hasRole('admin')).toBe(false);
    expect(await gate.forUser(undefined).hasRole('admin')).toBe(false);
  });
});

describe('Gate role checks (resolveRoles override)', () => {
  it('uses the configured resolver instead of the default shape', async () => {
    const gate = makeGate({
      resolveRoles: (user) => (user as { groups?: string[] }).groups ?? [],
    });
    expect(await gate.forUser({ groups: ['staff'] }).hasRole('staff')).toBe(true);
    // The default `roles`/`role` fields are ignored when an override is set.
    expect(await gate.forUser({ roles: ['admin'], groups: [] }).hasRole('admin')).toBe(false);
  });
});

describe('Gate role checks (ROLE_PROVIDER seam)', () => {
  const provider: RoleProvider = {
    getRoles: (user) => ((user as { id?: number }).id === 1 ? ['teacher'] : []),
  };

  it('consults the provider when the user object carries no roles', async () => {
    const gate = makeGate({}, provider);
    expect(await gate.forUser({ id: 1 }).hasRole('teacher')).toBe(true);
    expect(await gate.forUser({ id: 2 }).hasRole('teacher')).toBe(false);
  });

  it('unions provider roles with default-resolver roles', async () => {
    const gate = makeGate({}, provider);
    // id===1 → provider gives ['teacher']; user.role gives ['admin'] → union.
    const bound = gate.forUser({ id: 1, role: 'admin' });
    expect(await bound.hasRole('teacher')).toBe(true);
    expect(await bound.hasRole('admin')).toBe(true);
  });

  it('still denies when neither source yields the role', async () => {
    const gate = makeGate({}, provider);
    expect(await gate.forUser({ id: 2, role: 'student' }).hasRole('admin')).toBe(false);
  });
});
