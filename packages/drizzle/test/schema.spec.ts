import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import {
  DEFAULT_TABLE_NAMES,
  authzSchemaDdl,
  authzTables,
  createAuthzTables,
} from '../src/schema.js';
import { freshAuthzDb } from './support/db.js';

describe('createAuthzTables / authzSchemaDdl', () => {
  it('defaults to the canonical cross-adapter table names', () => {
    expect(getTableConfig(authzTables.roles).name).toBe(DEFAULT_TABLE_NAMES.roles);
    expect(getTableConfig(authzTables.userPermission).name).toBe(
      DEFAULT_TABLE_NAMES.userPermission,
    );
    expect(getTableConfig(authzTables.roles).schema).toBeUndefined();
  });

  it('honors BYO names + schema and derives constraint names from them', () => {
    const t = createAuthzTables({ tableNames: { userRole: 'app_user_role' }, schema: 'rbac' });
    const cfg = getTableConfig(t.userRole);
    expect(cfg.name).toBe('app_user_role');
    expect(cfg.schema).toBe('rbac');
    expect(cfg.primaryKeys[0]?.getName()).toBe('app_user_role_pkey');
    expect(cfg.indexes[0]?.config.name).toBe('app_user_role_user_idx');
    expect(getTableConfig(t.roles).name).toBe('authz_roles');
  });

  it('rejects unsafe table / schema names', () => {
    expect(() => createAuthzTables({ tableNames: { roles: 'x"; drop' } })).toThrow(/Unsafe/);
    expect(() => createAuthzTables({ schema: 'a.b' })).toThrow(/Unsafe/);
  });

  it('the DDL declares every column the Drizzle tables declare (they cannot drift)', () => {
    const ddl = authzSchemaDdl().join('\n');
    for (const table of Object.values(authzTables)) {
      const cfg = getTableConfig(table);
      const create = authzSchemaDdl().find((s) => s.includes(`"${cfg.name}" (`));
      expect(create, cfg.name).toBeDefined();
      for (const column of cfg.columns) expect(create).toContain(`"${column.name}"`);
    }
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS');
    expect(ddl).not.toMatch(/DROP/);
    // The only ALTER is the non-destructive, idempotent column add for pre-source tables.
    for (const statement of authzSchemaDdl().filter((x) => x.startsWith('ALTER'))) {
      expect(statement).toMatch(/^ALTER TABLE "authz_user_role" ADD COLUMN IF NOT EXISTS "source"/);
    }
  });

  it('ensureSchema creates tables matching the Drizzle definition, idempotently', async () => {
    const fx = await freshAuthzDb();
    const store = new DrizzleAuthzStore(fx.db, fx.options);
    await store.ensureSchema();
    await store.ensureSchema();
    for (const table of Object.values(store.tables)) {
      const cfg = getTableConfig(table);
      const rows = await fx.query<{ column_name: string }>(
        'SELECT column_name FROM information_schema.columns WHERE table_name = $1',
        [cfg.name],
      );
      expect(rows.map((r) => r.column_name).sort()).toEqual(cfg.columns.map((c) => c.name).sort());
    }
    await fx.close();
  });
});
