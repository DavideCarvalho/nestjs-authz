import 'reflect-metadata';
import type { DataSource } from 'typeorm';
import { describe, expect, it } from 'vitest';
import { Placeholders, assertSafeIdentifier, isPostgresFamily, placeholder } from '../src/sql.js';

/** A minimal DataSource stub — only `options.type` is read by the sql helpers. */
function ds(type: string): DataSource {
  return { options: { type } } as unknown as DataSource;
}

describe('sql placeholder generation (P1)', () => {
  it('uses ? for sqlite/mysql/mariadb', () => {
    for (const t of ['sqlite', 'better-sqlite3', 'mysql', 'mariadb', 'aurora-mysql']) {
      expect(isPostgresFamily(ds(t))).toBe(false);
      expect(placeholder(ds(t), 0)).toBe('?');
      expect(placeholder(ds(t), 3)).toBe('?');
    }
  });

  it('uses $n for postgres-family drivers', () => {
    for (const t of ['postgres', 'aurora-postgres', 'cockroachdb']) {
      expect(isPostgresFamily(ds(t))).toBe(true);
      expect(placeholder(ds(t), 0)).toBe('$1');
      expect(placeholder(ds(t), 2)).toBe('$3');
    }
  });

  it('Placeholders hands out sequential, dialect-correct tokens', () => {
    const pg = Placeholders.for(ds('postgres'));
    expect([pg.next(), pg.next(), pg.next()]).toEqual(['$1', '$2', '$3']);

    const lite = Placeholders.for(ds('sqlite'));
    expect([lite.next(), lite.next(), lite.next()]).toEqual(['?', '?', '?']);
  });
});

describe('identifier allowlist (P4)', () => {
  it('accepts safe identifiers', () => {
    for (const ok of ['authz_roles', 'Roles', '_x', 'a1_b2', 'schema_2']) {
      expect(() => assertSafeIdentifier(ok, 'table name')).not.toThrow();
    }
  });

  it('rejects hostile identifiers', () => {
    for (const bad of [
      'roles"; DROP TABLE users; --',
      'a"b',
      "a'b",
      'a b',
      'a.b',
      '1leading',
      'a-b',
      '',
      'a`b',
    ]) {
      expect(() => assertSafeIdentifier(bad, 'table name')).toThrow(/Unsafe table name/);
    }
  });
});
