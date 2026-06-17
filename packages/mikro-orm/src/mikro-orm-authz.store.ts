import { randomUUID } from 'node:crypto';
import type { EntityManager, MikroORM } from '@mikro-orm/core';
import { PermissionEntity, RoleEntity, RolePermissionEntity, UserRoleEntity } from './entities.js';
import { ensureAuthzSchema } from './schema.js';
import type { UserRef } from './types.js';

/** Normalize a {@link UserRef} to `{ type, id }` with `id` stringified. */
function normalizeUserRef(ref: UserRef): { type: string; id: string } {
  if (typeof ref === 'string' || typeof ref === 'number') {
    return { type: 'user', id: String(ref) };
  }
  return { type: ref.type ?? 'user', id: String(ref.id) };
}

/**
 * A user's effective permissions: the role names they hold and the flattened set of
 * permission names granted by those roles.
 */
export interface UserAuthz {
  roles: string[];
  permissions: string[];
}

/**
 * MikroORM-backed RBAC store. A plain POJO that receives the `EntityManager` in its
 * constructor — NOT `@Injectable`, no internal connection token (the app owns the
 * connection and plugs it via DI; see the persistence contract).
 *
 * The store works purely through the EntityManager + the registered entities, so it never
 * assumes a literal table name — names are owned by the entity metadata. Every read forks
 * the EM (`this.em.fork()`) so it is request-safe under MikroORM's identity-map rules.
 */
export class MikroOrmAuthzStore {
  // `opts` is reserved for forward-compat (parity with the TypeORM adapter's options); it is
  // accepted but not yet consumed since MikroORM owns table names via entity metadata.
  constructor(
    private readonly em: EntityManager,
    _opts: Record<string, never> = {},
  ) {}

  /** Create/upgrade the RBAC tables (non-destructive, delegates to {@link ensureAuthzSchema}). */
  ensureSchema(): Promise<void> {
    return ensureAuthzSchema(this.em);
  }

  // --- roles & permissions (idempotent upserts by name) ---

  /**
   * Create the role if absent; returns its id. Idempotent and race-tolerant: it re-reads
   * by the unique `name` after a create so two concurrent creators converge on the same row.
   */
  async createRole(name: string): Promise<string> {
    const existing = await this.findRoleId(name);
    if (existing) return existing;
    const em = this.em.fork();
    const entity = em.create(RoleEntity, {
      id: randomUUID(),
      name,
      guard: null,
      createdAt: new Date(),
    });
    try {
      await em.persist(entity).flush();
    } catch {
      // A concurrent insert won the race on the unique `name`; fall through to re-read.
    }
    const id = await this.findRoleId(name);
    if (!id) throw new Error(`Failed to create or resolve role "${name}".`);
    return id;
  }

  /** Create the permission if absent; returns its id. Idempotent and race-tolerant. */
  async createPermission(name: string): Promise<string> {
    const existing = await this.findPermissionId(name);
    if (existing) return existing;
    const em = this.em.fork();
    const entity = em.create(PermissionEntity, {
      id: randomUUID(),
      name,
      guard: null,
      createdAt: new Date(),
    });
    try {
      await em.persist(entity).flush();
    } catch {
      // A concurrent insert won the race on the unique `name`; fall through to re-read.
    }
    const id = await this.findPermissionId(name);
    if (!id) throw new Error(`Failed to create or resolve permission "${name}".`);
    return id;
  }

  private async findRoleId(name: string): Promise<string | undefined> {
    const row = await this.em.fork().findOne(RoleEntity, { name });
    return row?.id;
  }

  private async findPermissionId(name: string): Promise<string | undefined> {
    const row = await this.em.fork().findOne(PermissionEntity, { name });
    return row?.id;
  }

  // --- role ↔ permission ---

  /** Grant a permission to a role (creating both by name if needed). Idempotent. */
  async givePermissionToRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionId = await this.createPermission(permissionName);
    const em = this.em.fork();
    const existing = await em.findOne(RolePermissionEntity, { roleId, permissionId });
    if (existing) return;
    em.create(RolePermissionEntity, { roleId, permissionId });
    await em.flush();
  }

  /** Revoke a permission from a role. No-op if either is absent or not linked. */
  async revokePermissionFromRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.findRoleId(roleName);
    const permissionId = await this.findPermissionId(permissionName);
    if (!roleId || !permissionId) return;
    await this.em.fork().nativeDelete(RolePermissionEntity, { roleId, permissionId });
  }

  // --- user ↔ role ---

  /** Assign a role to a user (creating the role by name if needed). Idempotent. */
  async assignRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    const em = this.em.fork();
    const existing = await em.findOne(UserRoleEntity, { userType: type, userId: id, roleId });
    if (existing) return;
    em.create(UserRoleEntity, { userType: type, userId: id, roleId });
    await em.flush();
  }

  /** Remove a role from a user. No-op if the role or assignment is absent. */
  async removeRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    await this.em.fork().nativeDelete(UserRoleEntity, { userType: type, userId: id, roleId });
  }

  // --- queries ---

  /** The role names a user holds. */
  async getRolesForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, { userType: type, userId: id });
    if (assignments.length === 0) return [];
    const roleIds = assignments.map((a) => a.roleId);
    const roles = await em.find(RoleEntity, { id: { $in: roleIds } });
    return roles.map((r) => r.name);
  }

  /** The flattened, distinct permission names a user has via their roles. */
  async getPermissionsForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, { userType: type, userId: id });
    if (assignments.length === 0) return [];
    const roleIds = assignments.map((a) => a.roleId);
    const links = await em.find(RolePermissionEntity, { roleId: { $in: roleIds } });
    if (links.length === 0) return [];
    const permissionIds = [...new Set(links.map((l) => l.permissionId))];
    const permissions = await em.find(PermissionEntity, { id: { $in: permissionIds } });
    return [...new Set(permissions.map((p) => p.name))];
  }

  /** A user's roles + effective permissions in one shot. */
  async getUserAuthz(user: UserRef): Promise<UserAuthz> {
    const [roles, permissions] = await Promise.all([
      this.getRolesForUser(user),
      this.getPermissionsForUser(user),
    ]);
    return { roles, permissions };
  }

  /** True when the user holds `permission` through any of their roles. */
  async userHasPermission(user: UserRef, permission: string): Promise<boolean> {
    const permissions = await this.getPermissionsForUser(user);
    return permissions.includes(permission);
  }
}
