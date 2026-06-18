import type { PermissionProvider, RoleProvider, User } from '@dudousxd/nestjs-authz';

/**
 * A grants table for {@link FakePermissionProvider} / {@link FakeRoleProvider},
 * keyed by a user identity. The default identity is the user's `id` (or the user
 * itself when it has none), so `{ '1': ['posts.*'] }` grants user #1.
 */
export type FakePermissionGrants = Record<string, string[]>;

/** Default identity: the user's `id` (stringified), else the value itself. */
function defaultIdentity(user: User): string {
  if (user == null) return '';
  if (typeof user === 'object') {
    const id = (user as { id?: unknown }).id;
    if (id != null) return String(id);
  }
  return String(user);
}

/**
 * An in-memory {@link PermissionProvider} for tests — no database. Grants are a
 * `{ userId: permissions[] }` table; the user's granted set is exposed via
 * `getPermissions`, so the core's wildcard matcher applies (`posts.*` satisfies
 * `posts.update`, `*` satisfies anything) exactly as with a real RBAC adapter.
 *
 * @example
 * const provider = new FakePermissionProvider({ '1': ['posts.*'], '2': ['posts.read'] });
 * const gate = buildGate({ permissionProvider: provider });
 * await expectCan(gate, { id: 1 }, 'posts.update'); // wildcard grant
 */
export class FakePermissionProvider implements PermissionProvider {
  private readonly grants: Map<string, Set<string>>;
  private readonly identity: (user: User) => string;

  constructor(
    grants: FakePermissionGrants = {},
    identity: (user: User) => string = defaultIdentity,
  ) {
    this.identity = identity;
    this.grants = new Map(Object.entries(grants).map(([key, perms]) => [key, new Set(perms)]));
  }

  /** Grant `permission` to a user (chainable). */
  grant(user: User, permission: string): this {
    const key = this.identity(user);
    const set = this.grants.get(key) ?? new Set<string>();
    set.add(permission);
    this.grants.set(key, set);
    return this;
  }

  hasPermission(user: User, permission: string): boolean {
    return this.grants.get(this.identity(user))?.has(permission) ?? false;
  }

  getPermissions(user: User): string[] | undefined {
    const set = this.grants.get(this.identity(user));
    return set ? [...set] : undefined;
  }
}

/**
 * An in-memory {@link RoleProvider} for tests — a `{ userId: roles[] }` table. Use
 * with `buildGate({ roleProvider })` to exercise coarse role checks (`gate.hasRole`)
 * without a database.
 */
export class FakeRoleProvider implements RoleProvider {
  private readonly roles: Map<string, Set<string>>;
  private readonly identity: (user: User) => string;

  constructor(
    roles: FakePermissionGrants = {},
    identity: (user: User) => string = defaultIdentity,
  ) {
    this.identity = identity;
    this.roles = new Map(Object.entries(roles).map(([key, names]) => [key, new Set(names)]));
  }

  /** Assign `role` to a user (chainable). */
  assign(user: User, role: string): this {
    const key = this.identity(user);
    const set = this.roles.get(key) ?? new Set<string>();
    set.add(role);
    this.roles.set(key, set);
    return this;
  }

  getRoles(user: User): string[] | undefined {
    const set = this.roles.get(this.identity(user));
    return set ? [...set] : undefined;
  }
}
