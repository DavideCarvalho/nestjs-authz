import 'reflect-metadata';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import { createSchema, makePgClient, truncateAll } from './support/pg-client.js';

/** The admin management operations against real Postgres (documented legacy schema). */
const describeIntegration = process.env.AUTHZ_TEST_SKIP ? describe.skip : describe;

describeIntegration('PrismaAuthzStore — admin management operations (real Postgres)', () => {
  let pool: Pool;
  let store: PrismaAuthzStore;

  beforeAll(async () => {
    pool = new Pool({
      host: process.env.AUTHZ_TEST_PG_HOST,
      port: Number(process.env.AUTHZ_TEST_PG_PORT),
      user: process.env.AUTHZ_TEST_PG_USER,
      password: process.env.AUTHZ_TEST_PG_PASSWORD,
      database: process.env.AUTHZ_TEST_PG_DB,
    });
    await createSchema(pool);
    store = new PrismaAuthzStore(makePgClient(pool));
  });

  afterAll(async () => {
    await pool?.end();
  });

  beforeEach(async () => {
    await truncateAll(pool);
  });

  it('syncRolePermissions / getRolePermissions / deleteRole / listRoleAssignments / removeUser', async () => {
    await store.syncRolePermissions('editor', ['posts.edit', 'posts.view']);
    await store.syncRolePermissions('editor', ['posts.view', 'posts.delete']);
    await store.createRole('empty');
    expect(await store.getRolePermissions(['editor', 'empty', 'ghost'])).toEqual({
      editor: ['posts.delete', 'posts.view'],
      empty: [],
    });

    await store.assignRole(1, 'editor');
    await store.assignRole(2, 'empty');
    await store.assignRole(2, 'editor');
    expect(await store.listRoleAssignments({ role: 'editor' })).toEqual([
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: null },
      { userType: 'user', userId: '2', role: 'editor', source: 'manual', tenantId: null },
    ]);

    await store.removeUser(2);
    expect(await store.listRoleAssignments()).toEqual([
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: null },
    ]);

    expect(await store.deleteRole('editor')).toBe(true);
    expect(await store.listRoleAssignments()).toEqual([]);
    expect(await store.getRolePermissions(['editor', 'empty'])).toEqual({ empty: [] });
  });
});
