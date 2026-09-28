import { randomUUID } from 'node:crypto';
import {
  DEFAULT_ROLE_SOURCE,
  type RoleAssignment,
  type UserAuthz,
  type UserRef,
  normalizeUserRef,
} from '@dudousxd/nestjs-authz/store-kit';
import {
  PRISMA_AUTHZ_STORE_OPTIONS,
  PRISMA_CLIENT,
  type PrismaAuthzClientLike,
  type PrismaAuthzStoreOptions,
} from './prisma-client.js';

// Re-exported so `@dudousxd/nestjs-authz-prisma`'s public `UserAuthz` keeps the
// same import path; canonical definition lives in core's store-kit.
export type { RoleAssignment, UserAuthz };

/** Assignment source for role mutations (default `'manual'`) — see `setUserRoles`. */
export interface RoleSourceOptions {
  source?: string;
}

// Optional Nest DI decorators — declared structurally so this package does not need a
// hard runtime dependency on @nestjs/common for the POJO store (the module supplies the
// real Inject token). The store is usable as a plain POJO: `new PrismaAuthzStore(client)`.
import { Inject, Injectable, Optional } from '@nestjs/common';

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
    @Optional()
    @Inject(PRISMA_AUTHZ_STORE_OPTIONS)
    private readonly options: PrismaAuthzStoreOptions = {},
  ) {}

  /**
   * The `source` filter/value for an assignment: `{ source }` when per-source assignments are on,
   * `{}` otherwise (legacy schema without the column) — where a non-default source is an error.
   */
  private sourceField(source: string | undefined): { source?: string } {
    if (this.options?.roleSources) return { source: source ?? DEFAULT_ROLE_SOURCE };
    if (source !== undefined && source !== DEFAULT_ROLE_SOURCE) {
      throw new Error(
        `PrismaAuthzStore: role source "${source}" needs per-source assignments — add \`source String @default("manual")\` to the UserRole model (in its @@id) and construct the store with { roleSources: true }.`,
      );
    }
    return {};
  }

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

  /**
   * Assign a role to a user (creating the role by name if needed). Idempotent. `{ source }`
   * (default `'manual'`) needs `roleSources: true`.
   */
  async assignRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const source = this.sourceField(opts?.source);
    const roleId = await this.createRole(roleName);
    const existing = await this.client.userRole.findFirst({
      where: { userType: type, userId: id, roleId, ...source },
    });
    if (existing) return;
    await this.client.userRole.create({ data: { userType: type, userId: id, roleId, ...source } });
  }

  /**
   * Remove a role from a user. No-op if the role or assignment is absent. With `{ source }` only
   * that source's assignment goes; without it, the role is removed from every source.
   */
  async removeRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const source = opts?.source === undefined ? {} : this.sourceField(opts.source);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    await this.client.userRole.deleteMany({
      where: { userType: type, userId: id, roleId, ...source },
    });
  }

  /**
   * REPLACE the user's role assignments of ONE source (default `'manual'`) with exactly
   * `roleNames` — e.g. an SSO/SCIM sync calls `setUserRoles(user, mappedRoles, { source: 'sso' })`
   * on every login; other sources' assignments are untouched. Roles are created by name when
   * missing. Atomic when the client has `$transaction`. Without `roleSources: true` there is only
   * one (implicit manual) source, so this replaces ALL of the user's roles.
   */
  async setUserRoles(
    user: UserRef,
    roleNames: readonly string[],
    opts?: RoleSourceOptions,
  ): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const source = this.sourceField(opts?.source);
    const roleIds: string[] = [];
    for (const name of new Set(roleNames)) roleIds.push(await this.createRole(name));
    const replace = async (client: PrismaAuthzClientLike) => {
      await client.userRole.deleteMany({ where: { userType: type, userId: id, ...source } });
      for (const roleId of roleIds) {
        await client.userRole.create({ data: { userType: type, userId: id, roleId, ...source } });
      }
    };
    if (typeof this.client.$transaction === 'function') {
      await this.client.$transaction((tx: PrismaAuthzClientLike) => replace(tx));
    } else {
      await replace(this.client);
    }
  }

  /** Every role assignment of a user, one entry per `(role, source)`. */
  async getRoleAssignments(user: UserRef): Promise<RoleAssignment[]> {
    const { type, id } = normalizeUserRef(user);
    const assignments = await this.client.userRole.findMany({
      where: { userType: type, userId: id },
    });
    if (assignments.length === 0) return [];
    const roles = await this.client.role.findMany({
      where: { id: { in: [...new Set(assignments.map((a) => a.roleId as string))] } },
    });
    const nameById = new Map(roles.map((r) => [r.id as string, r.name as string]));
    return assignments
      .filter((a) => nameById.has(a.roleId as string))
      .map((a) => ({
        role: nameById.get(a.roleId as string) as string,
        source: (a.source as string | undefined) ?? DEFAULT_ROLE_SOURCE,
        tenantId: null,
      }))
      .sort((a, b) => a.role.localeCompare(b.role) || a.source.localeCompare(b.source));
  }

  // --- queries ---

  /** The role names a user holds. */
  async getRolesForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const assignments = await this.client.userRole.findMany({
      where: { userType: type, userId: id },
    });
    if (assignments.length === 0) return [];
    const roleIds = [...new Set(assignments.map((a) => a.roleId as string))];
    const roles = await this.client.role.findMany({ where: { id: { in: roleIds } } });
    return roles.map((r) => r.name as string);
  }

  /**
   * The flattened, distinct permission names a user has via their roles.
   *
   * Contract: returns the FULL deduped set of granted permission NAMES — including
   * wildcard grants such as `posts.*`. This is NOT an existence check; callers
   * ({@link userHasPermission}, {@link getUserAuthz}) depend on the complete set.
   *
   * Fast path: when the injected client exposes `$queryRaw`, assemble the set in a
   * SINGLE database round-trip via one JOIN (3 round-trips → 1). On ANY failure
   * (missing `$queryRaw`, custom `@@map` table names, non-Postgres identifier
   * quoting, etc.) it degrades to {@link getPermissionsViaDelegates}, so correctness
   * is preserved everywhere and only the common (Postgres + documented schema) case
   * gets the speedup.
   */
  async getPermissionsForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);

    const queryRaw = this.client.$queryRaw;
    if (typeof queryRaw === 'function') {
      try {
        // Single JOIN across the three documented `@@map` tables. Identifiers are
        // literal + double-quoted (Postgres); the user `${type}`/`${id}` VALUES go
        // through the tagged template as BOUND params — never string-concatenated.
        const rows = await queryRaw<Array<{ name: string }>>`
          SELECT DISTINCT p."name" AS name
          FROM "authz_permissions" p
          JOIN "authz_role_permission" rp ON rp."permissionId" = p."id"
          JOIN "authz_user_role" ur ON ur."roleId" = rp."roleId"
          WHERE ur."userType" = ${type} AND ur."userId" = ${id}
        `;
        return [...new Set(rows.map((r) => r.name))];
      } catch {
        // Raw path unsupported for this client/schema/dialect — fall back below.
        return this.getPermissionsViaDelegates(type, id);
      }
    }

    return this.getPermissionsViaDelegates(type, id);
  }

  /**
   * The original three-query implementation (userRole → rolePermission → permission),
   * returning the same deduped permission-name set as {@link getPermissionsForUser}.
   * Used directly when `$queryRaw` is unavailable, and as the fallback when the raw
   * fast path throws.
   */
  private async getPermissionsViaDelegates(type: string, id: string): Promise<string[]> {
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
