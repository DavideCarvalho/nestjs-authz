import 'reflect-metadata';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import { createSchema, makePgClient, truncateAll } from './support/pg-client.js';

/**
 * Real-Postgres integration for {@link PrismaAuthzStore.getPermissionsForUser}.
 *
 * Proves the `$queryRaw` single-JOIN executes correctly against actual Postgres
 * (identifier double-quoting + tagged-template parameterization), which the in-memory
 * fake cannot validate — it only stands in for the JOIN's result shape.
 *
 * Self-skips green when Docker is unavailable (global setup sets `AUTHZ_TEST_SKIP`).
 */
const describeIntegration = process.env.AUTHZ_TEST_SKIP ? describe.skip : describe;

describeIntegration('PrismaAuthzStore — real Postgres ($queryRaw JOIN)', () => {
  let pool: Pool;

  const user = { type: 'user', id: '7' };
  const expectedPermissions = ['posts.*', 'posts.edit', 'users.ban'];

  beforeAll(async () => {
    pool = new Pool({
      host: process.env.AUTHZ_TEST_PG_HOST,
      port: Number(process.env.AUTHZ_TEST_PG_PORT),
      user: process.env.AUTHZ_TEST_PG_USER,
      password: process.env.AUTHZ_TEST_PG_PASSWORD,
      database: process.env.AUTHZ_TEST_PG_DB,
    });
    await createSchema(pool);
  });

  afterAll(async () => {
    await pool?.end();
  });

  beforeEach(async () => {
    await truncateAll(pool);
  });

  /**
   * Seed a user with TWO roles whose permissions overlap on a wildcard (`posts.*`):
   *   role A (editor) → ['posts.*', 'users.ban']
   *   role B (writer) → ['posts.*', 'posts.edit']
   * Effective deduped set → ['posts.*', 'posts.edit', 'users.ban'].
   */
  async function seed(): Promise<void> {
    const store = new PrismaAuthzStore(makePgClient(pool));
    await store.givePermissionToRole('editor', 'posts.*');
    await store.givePermissionToRole('editor', 'users.ban');
    await store.givePermissionToRole('writer', 'posts.*');
    await store.givePermissionToRole('writer', 'posts.edit');
    await store.assignRole(user, 'editor');
    await store.assignRole(user, 'writer');
  }

  it('RAW path: $queryRaw JOIN returns the deduped full set on real Postgres', async () => {
    await seed();
    const client = makePgClient(pool);
    expect(typeof client.$queryRaw).toBe('function');
    const store = new PrismaAuthzStore(client);

    const perms = await store.getPermissionsForUser(user);
    expect(perms.sort()).toEqual(expectedPermissions);
  });

  it('FALLBACK path: client without $queryRaw returns the SAME set via 3 queries', async () => {
    await seed();
    const noRaw = makePgClient(pool, { rawQuery: false });
    expect(noRaw.$queryRaw).toBeUndefined();
    const store = new PrismaAuthzStore(noRaw);

    const perms = await store.getPermissionsForUser(user);
    expect(perms.sort()).toEqual(expectedPermissions);
  });

  it('userHasPermission is true for a granted name and false for an ungranted one', async () => {
    await seed();
    const store = new PrismaAuthzStore(makePgClient(pool));

    expect(await store.userHasPermission(user, 'users.ban')).toBe(true);
    expect(await store.userHasPermission(user, 'posts.*')).toBe(true);
    expect(await store.userHasPermission(user, 'comments.delete')).toBe(false);
  });

  it('a user with no roles returns []', async () => {
    const store = new PrismaAuthzStore(makePgClient(pool));
    expect(await store.getPermissionsForUser({ type: 'user', id: 'nobody' })).toEqual([]);
  });
});
