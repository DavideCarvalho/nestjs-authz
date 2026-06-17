import 'reflect-metadata';
import type { DataSource } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';

/**
 * A recording DataSource stub. It captures every SQL string the store emits and
 * returns empty result sets, so we can assert the *placeholder style* per dialect
 * WITHOUT a live database (no pg driver is available in this environment).
 */
function recordingDataSource(type: string): { ds: DataSource; sql: string[] } {
  const sql: string[] = [];
  let inserted = false;
  const ds = {
    options: { type },
    driver: { escape: (id: string) => `"${id}"` },
    query: vi.fn(async (text: string) => {
      sql.push(text);
      if (text.startsWith('INSERT')) {
        inserted = true;
        return [];
      }
      // SELECT: "not found" before the INSERT, then a row on the re-read so the
      // store's race-tolerant create resolves an id (mimics a real DB).
      return inserted ? [{ id: 'fake-id' }] : [];
    }),
  } as unknown as DataSource;
  return { ds, sql };
}

describe('TypeOrmAuthzStore dialect-correct SQL (P1)', () => {
  it('emits $n placeholders on a postgres DataSource', async () => {
    const { ds, sql } = recordingDataSource('postgres');
    const store = new TypeOrmAuthzStore(ds);

    await store.createRole('editor');

    // The SELECT (findRoleId) binds one param → "$1".
    const select = sql.find((s) => s.startsWith('SELECT'));
    expect(select).toBeDefined();
    expect(select).toContain('$1');
    expect(select).not.toContain('?');

    // The INSERT binds three params → "$1, $2, $3" and ON CONFLICT DO NOTHING.
    const insert = sql.find((s) => s.startsWith('INSERT'));
    expect(insert).toBeDefined();
    expect(insert).toContain('$1');
    expect(insert).toContain('$2');
    expect(insert).toContain('$3');
    expect(insert).not.toContain('?');
    expect(insert).toContain('ON CONFLICT DO NOTHING');
  });

  it('emits ? placeholders on a sqlite DataSource', async () => {
    const { ds, sql } = recordingDataSource('sqlite');
    const store = new TypeOrmAuthzStore(ds);

    await store.createRole('editor');

    const insert = sql.find((s) => s.startsWith('INSERT'));
    expect(insert).toBeDefined();
    expect(insert).toContain('?');
    expect(insert).not.toMatch(/\$\d/);
    expect(insert).toContain('ON CONFLICT DO NOTHING');
  });

  it('emits INSERT IGNORE (no ON CONFLICT) on mysql', async () => {
    const { ds, sql } = recordingDataSource('mysql');
    const store = new TypeOrmAuthzStore(ds);

    await store.createRole('editor');

    const insert = sql.find((s) => s.startsWith('INSERT'));
    expect(insert).toBeDefined();
    expect(insert).toContain('INSERT IGNORE');
    expect(insert).not.toContain('ON CONFLICT');
    expect(insert).toContain('?');
  });
});

describe('TypeOrmAuthzStore rejects hostile identifiers (P4)', () => {
  const { ds } = recordingDataSource('sqlite');

  it('throws when a BYO table name contains a double-quote', () => {
    expect(
      () =>
        new TypeOrmAuthzStore(ds, {
          tableNames: { roles: 'roles"; DROP TABLE users; --' },
        }),
    ).toThrow(/Unsafe table name/);
  });

  it('throws when a BYO schema is hostile', () => {
    expect(() => new TypeOrmAuthzStore(ds, { schema: 'public"; --' })).toThrow(
      /Unsafe schema name/,
    );
  });

  it('accepts a clean BYO schema + table names', () => {
    expect(
      () =>
        new TypeOrmAuthzStore(ds, {
          schema: 'rbac',
          tableNames: { roles: 'rbac_roles' },
        }),
    ).not.toThrow();
  });
});
