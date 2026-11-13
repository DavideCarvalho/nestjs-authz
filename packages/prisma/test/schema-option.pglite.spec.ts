import 'reflect-metadata';
import { PGlite } from '@electric-sql/pglite';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import type { PrismaAuthzClientLike, PrismaModelDelegate } from '../src/prisma-client.js';
import { TABLE, makeDelegate } from './support/pg-client.js';

/**
 * The `schema` option: models with `@@schema("authz")`, and the store's raw fast path naming
 * the schema too. `public` holds same-named DECOY tables with other grants, and `search_path`
 * stays at `public`, so a read that forgets the schema returns the wrong answer.
 */
const tables = (schema: string, tenant: boolean) => [
  `CREATE TABLE "${schema}"."authz_roles" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
  `CREATE TABLE "${schema}"."authz_permissions" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
  `CREATE TABLE "${schema}"."authz_role_permission" ("roleId" text NOT NULL, "permissionId" text NOT NULL, PRIMARY KEY ("roleId","permissionId"))`,
  `CREATE TABLE "${schema}"."authz_user_role" ("userType" text NOT NULL, "userId" text NOT NULL, "roleId" text NOT NULL${tenant ? `, "tenantId" text NOT NULL DEFAULT ''` : ''}, PRIMARY KEY ("userType","userId","roleId"${tenant ? ',"tenantId"' : ''}))`,
];

function asPool(db: PGlite): Pool {
  return {
    async query(text: string, values?: unknown[]) {
      const result = await db.query<Record<string, unknown>>(text, values);
      return { rows: result.rows, rowCount: result.affectedRows ?? 0 };
    },
  } as unknown as Pool;
}

/** A client shaped like `PrismaClient` with `@@schema` models; raw methods read `this`. */
class SchemaClient implements PrismaAuthzClientLike {
  readonly role: PrismaModelDelegate;
  readonly permission: PrismaModelDelegate;
  readonly rolePermission: PrismaModelDelegate;
  readonly userRole: PrismaModelDelegate;
  unsafeCalls = 0;
  taggedCalls = 0;
  _activeProvider = 'postgresql';

  constructor(
    private readonly db: PGlite,
    schema: string,
  ) {
    const pool = asPool(db);
    this.role = makeDelegate(pool, TABLE.role, schema);
    this.permission = makeDelegate(pool, TABLE.permission, schema);
    this.rolePermission = makeDelegate(pool, TABLE.rolePermission, schema);
    this.userRole = makeDelegate(pool, TABLE.userRole, schema);
  }

  async $queryRaw<T = unknown>(_strings: TemplateStringsArray, ..._values: unknown[]): Promise<T> {
    this.taggedCalls++;
    throw new Error('the tagged template cannot name a schema');
  }

  async $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T> {
    this.unsafeCalls++;
    return (await this.db.query(query, values)).rows as T;
  }
}

describe('PrismaAuthzStore with schema (PGlite)', () => {
  let db: PGlite;
  const alice = { type: 'user', id: '1' };

  beforeAll(async () => {
    db = new PGlite();
    for (const schema of ['authz', 'authz_t']) {
      await db.query(`CREATE SCHEMA "${schema}"`);
      for (const stmt of tables(schema, schema === 'authz_t')) await db.query(stmt);
    }
    // Decoys in public: alice is an admin there.
    for (const stmt of tables('public', false)) await db.query(stmt);
    await db.query(`INSERT INTO "authz_roles" VALUES ('r', 'admin', NULL, now())`);
    await db.query(`INSERT INTO "authz_permissions" VALUES ('p', '*', NULL, now())`);
    await db.query(`INSERT INTO "authz_role_permission" VALUES ('r', 'p')`);
    await db.query(`INSERT INTO "authz_user_role" VALUES ('user', '1', 'r')`);
    // PGlite boots a WASM Postgres: slow on a loaded CI runner.
  }, 60_000);

  afterAll(async () => {
    await db.close();
  });

  it('reads and writes only in the schema, one raw query per permission read', async () => {
    const client = new SchemaClient(db, 'authz');
    const store = new PrismaAuthzStore(client, { schema: 'authz' });
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole(alice, 'editor');
    const fallback = vi.spyOn(client.rolePermission, 'findMany');
    expect(await store.getPermissionsForUser(alice)).toEqual(['posts.publish']);
    expect(client.unsafeCalls).toBe(1);
    expect(client.taggedCalls).toBe(0);
    expect(fallback).not.toHaveBeenCalled();
    expect(await store.getRolesForUser(alice)).toEqual(['editor']);
    expect(await store.userHasPermission(alice, '*')).toBe(false);
  });

  it('tenantScoped: the raw query keeps the tenant condition', async () => {
    const client = new SchemaClient(db, 'authz_t');
    const store = new PrismaAuthzStore(client, { schema: 'authz_t', tenantScoped: true });
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('viewer', 'posts.view');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.assignRole(alice, 'viewer');
    expect((await store.getPermissionsForUser(alice, { tenantId: 'acme' })).sort()).toEqual([
      'posts.publish',
      'posts.view',
    ]);
    expect(await store.getPermissionsForUser(alice)).toEqual(['posts.view']);
    expect(client.unsafeCalls).toBe(2);
  });

  it('without $queryRawUnsafe it uses the model delegates (still in the schema)', async () => {
    const client = new SchemaClient(db, 'authz');
    (client as { $queryRawUnsafe?: unknown }).$queryRawUnsafe = undefined;
    const store = new PrismaAuthzStore(client, { schema: 'authz' });
    expect(await store.getPermissionsForUser(alice)).toEqual(['posts.publish']);
  });

  it('refuses a schema on a provider without @@schema, and a bad name', () => {
    const client = new SchemaClient(db, 'authz');
    client._activeProvider = 'mysql';
    expect(() => new PrismaAuthzStore(client, { schema: 'authz' })).toThrow(/needs Postgres/);
    client._activeProvider = 'sqlite';
    expect(() => new PrismaAuthzStore(client, { schema: 'authz' })).toThrow(/needs Postgres/);
    client._activeProvider = 'postgresql';
    expect(() => new PrismaAuthzStore(client, { schema: 'a.b' })).toThrow(/Unsafe/);
    expect(() => new PrismaAuthzStore(client, { schema: 'a'.repeat(64) })).toThrow(/63/);
  });
});
