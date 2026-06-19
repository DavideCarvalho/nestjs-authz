import { randomUUID } from 'node:crypto';
import { type UserAuthz, type UserRef, normalizeUserRef } from '@dudousxd/nestjs-authz/store-kit';
import { PRISMA_CLIENT, type PrismaAuthzClientLike } from './prisma-client.js';

// Re-exported so `@dudousxd/nestjs-authz-prisma`'s public `UserAuthz` keeps the
// same import path; canonical definition lives in core's store-kit.
export type { UserAuthz };

// Optional Nest DI decorators — declared structurally so this package does not need a
// hard runtime dependency on @nestjs/common for the POJO store (the module supplies the
// real Inject token). The store is usable as a plain POJO: `new PrismaAuthzStore(client)`.
import { Inject, Injectable } from '@nestjs/common';

/**
 * Prisma-backed RBAC store. Receives the app-owned Prisma client via the
 * {@link PRISMA_CLIENT} DI token — NO internal connection ownership, NO `@prisma/client`
 * import (it consumes the structural {@link PrismaAuthzClientLike}).
 *
 * Same method surface as the TypeORM/MikroORM adapters. The user is referenced BY ID ONLY
 * — this package never owns a users table.
 */
@Injectable()
export class PrismaAuthzStore {
  constructor(
    @Inject(PRISMA_CLIENT)
    private readonly client: PrismaAuthzClientLike,
  ) {}

  /**
   * No-op: Prisma is schema-first / consumer-managed. Declare the RBAC models in your
   * `schema.prisma` (see {@link PrismaAuthzClientLike}) and apply them with
   * `prisma migrate` / `prisma db push` — this adapter never runs DDL. Present for parity
   * with the other adapters' store surface.
   */
  async ensureSchema(): Promise<void> {
    // Intentionally empty — see the doc comment.
  }

  // --- roles & permissions (idempotent upserts by name) ---

  /** Create the role if absent; returns its id. Idempotent and race-tolerant. */
  async createRole(name: string): Promise<string> {
    const existing = await this.findRoleId(name);
    if (existing) return existing;
    try {
      const row = await this.client.role.create({
        data: { id: randomUUID(), name, guard: null, createdAt: new Date() },
      });
      return row.id as string;
    } catch {
      // A concurrent insert won the race on the unique `name`; re-read.
      const id = await this.findRoleId(name);
      if (!id) throw new Error(`Failed to create or resolve role "${name}".`);
      return id;
    }
  }

  /** Create the permission if absent; returns its id. Idempotent and race-tolerant. */
  async createPermission(name: string): Promise<string> {
    const existing = await this.findPermissionId(name);
    if (existing) return existing;
    try {
      const row = await this.client.permission.create({
        data: { id: randomUUID(), name, guard: null, createdAt: new Date() },
      });
      return row.id as string;
    } catch {
      const id = await this.findPermissionId(name);
      if (!id) throw new Error(`Failed to create or resolve permission "${name}".`);
      return id;
    }
  }

  private async findRoleId(name: string): Promise<string | undefined> {
    const row = await this.client.role.findFirst({ where: { name } });
    return row?.id as string | undefined;
  }

  private async findPermissionId(name: string): Promise<string | undefined> {
    const row = await this.client.permission.findFirst({ where: { name } });
    return row?.id as string | undefined;
  }

  // --- role ↔ permission ---

  /** Grant a permission to a role (creating both by name if needed). Idempotent. */
  async givePermissionToRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionId = await this.createPermission(permissionName);
    const existing = await this.client.rolePermission.findFirst({
      where: { roleId, permissionId },
    });
    if (existing) return;
    await this.client.rolePermission.create({ data: { roleId, permissionId } });
  }

  /** Revoke a permission from a role. No-op if either is absent or not linked. */
  async revokePermissionFromRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.findRoleId(roleName);
    const permissionId = await this.findPermissionId(permissionName);
    if (!roleId || !permissionId) return;
    await this.client.rolePermission.deleteMany({ where: { roleId, permissionId } });
  }

  // --- user ↔ role ---

  /** Assign a role to a user (creating the role by name if needed). Idempotent. */
  async assignRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    const existing = await this.client.userRole.findFirst({
      where: { userType: type, userId: id, roleId },
    });
    if (existing) return;
    await this.client.userRole.create({ data: { userType: type, userId: id, roleId } });
  }

  /** Remove a role from a user. No-op if the role or assignment is absent. */
  async removeRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    await this.client.userRole.deleteMany({ where: { userType: type, userId: id, roleId } });
  }

  // --- queries ---

  /** The role names a user holds. */
  async getRolesForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const assignments = await this.client.userRole.findMany({
      where: { userType: type, userId: id },
    });
    if (assignments.length === 0) return [];
    const roleIds = assignments.map((a) => a.roleId as string);
    const roles = await this.client.role.findMany({ where: { id: { in: roleIds } } });
    return roles.map((r) => r.name as string);
  }

  /** The flattened, distinct permission names a user has via their roles. */
  async getPermissionsForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const assignments = await this.client.userRole.findMany({
      where: { userType: type, userId: id },
    });
    if (assignments.length === 0) return [];
    const roleIds = assignments.map((a) => a.roleId as string);
    const links = await this.client.rolePermission.findMany({
      where: { roleId: { in: roleIds } },
    });
    if (links.length === 0) return [];
    const permissionIds = [...new Set(links.map((l) => l.permissionId as string))];
    const permissions = await this.client.permission.findMany({
      where: { id: { in: permissionIds } },
    });
    return [...new Set(permissions.map((p) => p.name as string))];
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
