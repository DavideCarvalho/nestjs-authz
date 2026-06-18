import type { Pool } from 'pg';
import type { PrismaAuthzClientLike, PrismaModelDelegate } from '../../src/prisma-client.js';

/**
 * A REAL, `pg`-backed structural client satisfying {@link PrismaAuthzClientLike}.
 *
 * Unlike the in-memory fake, this runs every query against real Postgres so the store's
 * actual SQL (identifier double-quoting, tagged-template parameterization) is exercised
 * verbatim. It exists only for the integration spec.
 *
 * The model→table mapping mirrors the documented `@@map` names; columns are the
 * documented camelCase identifiers and MUST be double-quoted in raw SQL so Postgres does
 * not fold them to lowercase.
 */

/** Documented `@@map` table names per Prisma model. */
const TABLE: Record<'role' | 'permission' | 'rolePermission' | 'userRole', string> = {
  role: 'authz_roles',
  permission: 'authz_permissions',
  rolePermission: 'authz_role_permission',
  userRole: 'authz_user_role',
};

type Row = Record<string, unknown>;
type WhereValue = unknown | { in: unknown[] };
type Where = Record<string, WhereValue>;

/** Quote a camelCase identifier for Postgres (preserves case). */
function quoteId(id: string): string {
  return `"${id.replace(/"/g, '""')}"`;
}

/**
 * Build the parameterized `WHERE` fragment for a flat-equality / `{ in: [...] }` clause —
 * the only two shapes the store uses. Equality → `"col" = $n`; `{ in }` → `"col" = ANY($n)`
 * (a single array param, matching how Prisma binds an `in` list on Postgres).
 */
function buildWhere(where: Where): { text: string; values: unknown[] } {
  const clauses: string[] = [];
  const values: unknown[] = [];
  for (const [col, cond] of Object.entries(where)) {
    if (cond && typeof cond === 'object' && 'in' in (cond as Row)) {
      values.push((cond as { in: unknown[] }).in);
      clauses.push(`${quoteId(col)} = ANY($${values.length})`);
    } else {
      values.push(cond);
      clauses.push(`${quoteId(col)} = $${values.length}`);
    }
  }
  const text = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  return { text, values };
}

/** A real pg-backed model delegate for one table. */
function makeDelegate(pool: Pool, table: string): PrismaModelDelegate {
  const tbl = quoteId(table);
  return {
    async create(args: { data: Row }) {
      const cols = Object.keys(args.data);
      const vals = Object.values(args.data);
      const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
      const colList = cols.map(quoteId).join(', ');
      const { rows } = await pool.query(
        `INSERT INTO ${tbl} (${colList}) VALUES (${placeholders}) RETURNING *`,
        vals,
      );
      return rows[0];
    },
    async findFirst(args: { where: Where }) {
      const { text, values } = buildWhere(args.where);
      const { rows } = await pool.query(`SELECT * FROM ${tbl} ${text} LIMIT 1`, values);
      return rows[0] ?? null;
    },
    async findMany(args: { where: Where }) {
      const { text, values } = buildWhere(args.where);
      const { rows } = await pool.query(`SELECT * FROM ${tbl} ${text}`, values);
      return rows;
    },
    async deleteMany(args: { where: Where }) {
      const { text, values } = buildWhere(args.where);
      const result = await pool.query(`DELETE FROM ${tbl} ${text}`, values);
      return { count: result.rowCount ?? 0 };
    },
  };
}

/**
 * Faithfully replicate Prisma's tagged-template `$queryRaw` against `pg`.
 *
 * Prisma's `$queryRaw\`... ${a} ... ${b}\`` interleaves the static `strings` with `$1,
 * $2, ...` placeholders (one per interpolated value, IN ORDER) and binds the values as
 * query parameters — interpolated values are NEVER concatenated into the SQL text. We do
 * exactly that here, so the store's raw SQL (literal double-quoted identifiers, values as
 * `${}`) is sent to real Postgres unchanged.
 */
function makeQueryRaw(pool: Pool): PrismaAuthzClientLike['$queryRaw'] {
  return (async <T = unknown>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T> => {
    let text = strings[0] ?? '';
    for (let i = 0; i < values.length; i++) {
      text += `$${i + 1}${strings[i + 1] ?? ''}`;
    }
    const result = await pool.query(text, values);
    return result.rows as T;
  }) as PrismaAuthzClientLike['$queryRaw'];
}

/**
 * Build a real pg-backed structural client. Pass `{ rawQuery: false }` to OMIT
 * `$queryRaw` (forcing the store onto its three-query delegate fallback against real PG).
 */
export function makePgClient(pool: Pool, opts: { rawQuery?: boolean } = {}): PrismaAuthzClientLike {
  const { rawQuery = true } = opts;
  const client: PrismaAuthzClientLike = {
    role: makeDelegate(pool, TABLE.role),
    permission: makeDelegate(pool, TABLE.permission),
    rolePermission: makeDelegate(pool, TABLE.rolePermission),
    userRole: makeDelegate(pool, TABLE.userRole),
  };
  if (rawQuery) {
    client.$queryRaw = makeQueryRaw(pool);
  }
  return client;
}

/** DDL matching the documented schema (quoted camelCase columns, `@@map` table names). */
const DDL: string[] = [
  `CREATE TABLE IF NOT EXISTS "authz_roles" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now());`,
  `CREATE TABLE IF NOT EXISTS "authz_permissions" ("id" text PRIMARY KEY, "name" text UNIQUE NOT NULL, "guard" text, "createdAt" timestamptz DEFAULT now());`,
  `CREATE TABLE IF NOT EXISTS "authz_role_permission" ("roleId" text NOT NULL, "permissionId" text NOT NULL, PRIMARY KEY ("roleId","permissionId"));`,
  `CREATE TABLE IF NOT EXISTS "authz_user_role" ("userType" text NOT NULL, "userId" text NOT NULL, "roleId" text NOT NULL, PRIMARY KEY ("userType","userId","roleId"));`,
];

/** Create the 4 RBAC tables (idempotent). */
export async function createSchema(pool: Pool): Promise<void> {
  for (const stmt of DDL) {
    await pool.query(stmt);
  }
}

/** Truncate all 4 RBAC tables for per-test isolation. */
export async function truncateAll(pool: Pool): Promise<void> {
  await pool.query(
    'TRUNCATE "authz_roles", "authz_permissions", "authz_role_permission", "authz_user_role";',
  );
}
