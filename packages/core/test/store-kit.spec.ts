import { describe, expect, it } from 'vitest';
import {
  type UserRoleAssignment,
  compareUserRoleAssignments,
  roleFilterNames,
} from '../src/store-kit.js';

describe('store-kit — listRoleAssignments helpers', () => {
  it('roleFilterNames normalizes one name or a list (deduped); undefined = no filter', () => {
    expect(roleFilterNames(undefined)).toBeUndefined();
    expect(roleFilterNames('admin')).toEqual(['admin']);
    expect(roleFilterNames(['a', 'b', 'a'])).toEqual(['a', 'b']);
    expect(roleFilterNames([])).toEqual([]);
  });

  it('compareUserRoleAssignments orders by (userType, userId, role, source, tenantId) by code unit', () => {
    const r = (
      userType: string,
      userId: string,
      role: string,
      source: string,
      tenantId: string | null,
    ): UserRoleAssignment => ({ userType, userId, role, source, tenantId });
    const rows = [
      r('user', '2', 'a', 'manual', null),
      r('user', '1', 'b', 'manual', null),
      r('user', '1', 'a', 'sso', null),
      r('user', '1', 'a', 'manual', 'acme'),
      r('user', '1', 'a', 'manual', null),
      r('bot', '9', 'z', 'manual', null),
      r('user', '1', 'Z', 'manual', null),
    ];
    expect([...rows].sort(compareUserRoleAssignments)).toEqual([
      r('bot', '9', 'z', 'manual', null),
      r('user', '1', 'Z', 'manual', null),
      r('user', '1', 'a', 'manual', null),
      r('user', '1', 'a', 'manual', 'acme'),
      r('user', '1', 'a', 'sso', null),
      r('user', '1', 'b', 'manual', null),
      r('user', '2', 'a', 'manual', null),
    ]);
  });
});
