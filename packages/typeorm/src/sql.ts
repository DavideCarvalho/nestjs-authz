import type { DataSource } from 'typeorm';

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

/**
 * SQL identifiers (table / schema names) are interpolated into query text, NOT
 * passed as bound parameters — `driver.escape()` only wraps them in quotes, it does
 * NOT neutralize an embedded quote. To keep BYO `tableNames`/`schema` safe, restrict
 * them to a conservative allowlist and reject anything else loudly.
 */
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Validate an identifier (table/schema name) against {@link SAFE_IDENTIFIER}.
 * Throws on anything containing quotes, dots, whitespace, or other unsafe chars.
 *
 * @param value the identifier to check
 * @param what  a label for the error message (e.g. `table name "roles"`)
 */
export function assertSafeIdentifier(value: string, what: string): void {
  if (!SAFE_IDENTIFIER.test(value)) {
    throw new Error(
      `Unsafe ${what}: ${JSON.stringify(value)}. Identifiers must match /^[A-Za-z_][A-Za-z0-9_]*$/ (letters, digits, underscore; not starting with a digit). This blocks SQL injection via configured names.`,
    );
  }
}
