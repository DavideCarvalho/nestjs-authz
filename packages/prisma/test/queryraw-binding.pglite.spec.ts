import 'reflect-metadata';
import { PGlite } from '@electric-sql/pglite';
import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import type { PrismaAuthzClientLike, PrismaModelDelegate } from '../src/prisma-client.js';
import { TABLE, makeDelegate } from './support/pg-client.js';

/**
 * `$queryRaw` fast path against real SQL (PGlite, in-process Postgres), with a client
 * whose `$queryRaw` is a prototype method that reads `this` — like the real
 * `PrismaClient`. A store that calls `$queryRaw` detached from the client throws inside
 * the fast path and silently falls back to the three delegate queries; these specs
 * assert the delegates are never touched, so that fallback cannot hide.
 */

/** The documented schema, with the tenancy `tenantId` column. */
const DDL = [
  `CREATE TABLE "authz_roles" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
  `CREATE TABLE "authz_permissions" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
  `CREATE TABLE "authz_role_permission" ("roleId" text NOT NULL, "permissionId" text NOT NULL, PRIMARY KEY ("roleId","permissionId"))`,
  `CREATE TABLE "authz_user_role" ("userType" text NOT NULL, "userId" text NOT NULL, "roleId" text NOT NULL, "tenantId" text NOT NULL DEFAULT '', PRIMARY KEY ("userType","userId","roleId","tenantId"))`,
];

/** Expose PGlite through the `pg.Pool#query` shape the shared delegates use. */
function asPool(db: PGlite): Pool {
  return {
    async query(text: string, values?: unknown[]) {
      const result = await db.query<Record<string, unknown>>(text, values);
      return { rows: result.rows, rowCount: result.affectedRows ?? 0 };
    },
  } as unknown as Pool;
}

/** Structural client shaped like `PrismaClient`: `$queryRaw` lives on the prototype. */
class ThisBoundClient implements PrismaAuthzClientLike {
  readonly role: PrismaModelDelegate;
  readonly permission: PrismaModelDelegate;
  readonly rolePermission: PrismaModelDelegate;
  readonly userRole: PrismaModelDelegate;
  rawCalls = 0;

  constructor(private readonly db: PGlite) {
    const pool = asPool(db);
    this.role = makeDelegate(pool, TABLE.role);
    this.permission = makeDelegate(pool, TABLE.permission);
    this.rolePermission = makeDelegate(pool, TABLE.rolePermission);
    this.userRole = makeDelegate(pool, TABLE.userRole);
  }

  /** Prisma's tagged-template binding: values become `$1, $2, ...`, never inlined. */
  async $queryRaw<T = unknown>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T> {
    this.rawCalls++;
    let text = strings[0] ?? '';
    for (let i = 0; i < values.length; i++) text += `$${i + 1}${strings[i + 1] ?? ''}`;
    const result = await this.db.query(text, values);
    return result.rows as T;
  }
}

describe('PrismaAuthzStore $queryRaw fast path (PGlite, this-bound client)', () => {
  let db: PGlite;
  const alice = { type: 'user', id: '1' };

  beforeAll(async () => {
    db = new PGlite();
    for (const stmt of DDL) await db.query(stmt);
  });

  afterAll(async () => {
    await db.close();
  });

  beforeEach(async () => {
    await db.query(
      'TRUNCATE "authz_roles", "authz_permissions", "authz_role_permission", "authz_user_role"',
    );
  });

  /** Spy every delegate read the fallback would make. */
  function spyFallback(client: ThisBoundClient) {
    return [
      vi.spyOn(client.userRole, 'findMany'),
      vi.spyOn(client.rolePermission, 'findMany'),
      vi.spyOn(client.permission, 'findMany'),
    ];
  }

  it('takes the single-query path: no delegate fallback', async () => {
    const client = new ThisBoundClient(db);
    const store = new PrismaAuthzStore(client);
    await store.givePermissionToRole('editor', 'posts.*');
    await store.givePermissionToRole('editor', 'users.ban');
    await store.givePermissionToRole('writer', 'posts.*');
    await store.givePermissionToRole('writer', 'posts.edit');
    await store.assignRole(alice, 'editor');
    await store.assignRole(alice, 'writer');

    const spies = spyFallback(client);
    expect((await store.getPermissionsForUser(alice)).sort()).toEqual([
      'posts.*',
      'posts.edit',
      'users.ban',
    ]);
    expect(client.rawCalls).toBe(1);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it('tenantScoped: the raw query applies the tenant condition, still without fallback', async () => {
    const client = new ThisBoundClient(db);
    const store = new PrismaAuthzStore(client, { tenantScoped: true });
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('viewer', 'posts.read');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.assignRole(alice, 'viewer');

    const spies = spyFallback(client);
    expect((await store.getPermissionsForUser(alice, { tenantId: 'acme' })).sort()).toEqual([
      'posts.publish',
      'posts.read',
    ]);
    expect(await store.getPermissionsForUser(alice, { tenantId: 'globex' })).toEqual([
      'posts.read',
    ]);
    expect(await store.getPermissionsForUser(alice)).toEqual(['posts.read']);
    expect(await store.userHasPermission(alice, 'posts.publish', { tenantId: 'globex' })).toBe(
      false,
    );
    expect(client.rawCalls).toBe(4);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });
});
