import type { DataSource } from 'typeorm';

// Re-exported so the package's existing `./sql.js` import sites (and tests) keep working while the
// guard itself is single-sourced in core.
export { assertSafeIdentifier } from '@dudousxd/nestjs-authz';

/**
 * Database types whose driver binds parameters with positional `$1, $2, …`
 * placeholders instead of `?`. Postgres (and its aurora/cockroach kin) reject the
 * `?` style that MySQL/SQLite accept, so the store must emit the right one.
 */
const POSTGRES_FAMILY = new Set(['postgres', 'aurora-postgres', 'cockroachdb', 'spanner']);

/** True when the DataSource's driver expects `$n` positional placeholders. */
export function isPostgresFamily(dataSource: DataSource): boolean {
  return POSTGRES_FAMILY.has(dataSource.options.type);
}

/**
 * Build the placeholder token for the parameter at 0-based `index`, dialect-correct
 * for the given DataSource: `$1, $2, …` on Postgres-family drivers, `?` elsewhere.
 */
export function placeholder(dataSource: DataSource, index: number): string {
  return isPostgresFamily(dataSource) ? `$${index + 1}` : '?';
}

/**
 * A tiny helper that hands out dialect-correct, sequentially-numbered placeholders.
 * Each call to {@link Placeholders.next} returns the next token (`?` or `$n`), so a
 * single query can interleave them in parameter order regardless of dialect.
 */
export class Placeholders {
  private index = 0;
  constructor(private readonly postgres: boolean) {}

  static for(dataSource: DataSource): Placeholders {
    return new Placeholders(isPostgresFamily(dataSource));
  }

  /** The next placeholder token, advancing the positional counter. */
  next(): string {
    const token = this.postgres ? `$${this.index + 1}` : '?';
    this.index += 1;
    return token;
  }
}
