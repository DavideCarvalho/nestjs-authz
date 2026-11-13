import 'reflect-metadata';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import type { PrismaAuthzClientLike } from '../src/prisma-client.js';
import { TABLE, makeDelegate } from './support/pg-client.js';

/**
 * Real Postgres: models with `@@schema("authz_s")`, the raw fast path naming the schema, and
 * nothing read from or written to `public` (search_path stays at its default).
 */
const describeIntegration = process.env.AUTHZ_TEST_SKIP ? describe.skip : describe;
const SCHEMA = 'authz_s';

describeIntegration('PrismaAuthzStore with schema (real Postgres)', () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({
      host: process.env.AUTHZ_TEST_PG_HOST,
      port: Number(process.env.AUTHZ_TEST_PG_PORT),
      user: process.env.AUTHZ_TEST_PG_USER,
      password: process.env.AUTHZ_TEST_PG_PASSWORD,
      database: process.env.AUTHZ_TEST_PG_DB,
    });
    await pool.query(`DROP SCHEMA IF EXISTS "${SCHEMA}" CASCADE`);
    await pool.query(`CREATE SCHEMA "${SCHEMA}"`);
    for (const stmt of [
      `CREATE TABLE "${SCHEMA}"."authz_roles" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
      `CREATE TABLE "${SCHEMA}"."authz_permissions" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now())`,
      `CREATE TABLE "${SCHEMA}"."authz_role_permission" ("roleId" text NOT NULL, "permissionId" text NOT NULL, PRIMARY KEY ("roleId","permissionId"))`,
      `CREATE TABLE "${SCHEMA}"."authz_user_role" ("userType" text NOT NULL, "userId" text NOT NULL, "roleId" text NOT NULL, "tenantId" text NOT NULL DEFAULT '', PRIMARY KEY ("userType","userId","roleId","tenantId"))`,
    ]) {
      await pool.query(stmt);
    }
  });

  afterAll(async () => {
    await pool?.query(`DROP SCHEMA IF EXISTS "${SCHEMA}" CASCADE`);
    await pool?.end();
  });

  it('reads and writes in the schema through the raw fast path', async () => {
    let unsafeCalls = 0;
    const client: PrismaAuthzClientLike = {
      role: makeDelegate(pool, TABLE.role, SCHEMA),
      permission: makeDelegate(pool, TABLE.permission, SCHEMA),
      rolePermission: makeDelegate(pool, TABLE.rolePermission, SCHEMA),
      userRole: makeDelegate(pool, TABLE.userRole, SCHEMA),
      async $queryRawUnsafe<T>(query: string, ...values: unknown[]) {
        unsafeCalls++;
        return (await pool.query(query, values)).rows as T;
      },
    };
    const store = new PrismaAuthzStore(client, { schema: SCHEMA, tenantScoped: true });
    const alice = { type: 'user', id: '1' };
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    expect(await store.getPermissionsForUser(alice, { tenantId: 'acme' })).toEqual([
      'posts.publish',
    ]);
    expect(await store.getPermissionsForUser(alice)).toEqual([]);
    expect(unsafeCalls).toBe(2);
    // Other specs may own `public.authz_*` in this container: none of this test's rows are there.
    const inPublic = await pool.query(`SELECT to_regclass('public.authz_roles') AS t`);
    if (inPublic.rows[0]?.t) {
      const editor = await pool.query(`SELECT 1 FROM public.authz_roles WHERE "name" = 'editor'`);
      expect(editor.rows).toEqual([]);
    }
  });
});
