import type { PrismaAuthzClientLike, PrismaModelDelegate } from '../src/prisma-client.js';

type Row = Record<string, unknown>;

/** Does `row` match the (flat or `{ in: [...] }`) `where` clause? */
function matches(row: Row, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, cond]) => {
    if (cond && typeof cond === 'object' && 'in' in (cond as Row)) {
      const list = (cond as { in: unknown[] }).in;
      return list.includes(row[key]);
    }
    return row[key] === cond;
  });
}

/** A minimal in-memory model delegate — enough to back the store's queries. */
function makeDelegate(): PrismaModelDelegate & { rows: Row[] } {
  const rows: Row[] = [];
  return {
    rows,
    async create(args: { data: Row }) {
      const row = { ...args.data };
      rows.push(row);
      return row;
    },
    async findFirst(args: { where: Record<string, unknown> }) {
      return rows.find((r) => matches(r, args.where)) ?? null;
    },
    async findMany(args: { where: Record<string, unknown> }) {
      return rows.filter((r) => matches(r, args.where));
    },
    async deleteMany(args: { where: Record<string, unknown> }) {
      let count = 0;
      for (let i = rows.length - 1; i >= 0; i--) {
        const r = rows[i];
        if (r && matches(r, args.where)) {
          rows.splice(i, 1);
          count++;
        }
      }
      return { count };
    },
  };
}

/**
 * A structural fake Prisma client (in-memory) satisfying {@link PrismaAuthzClientLike}.
 *
 * By default it includes a `$queryRaw` that SIMULATES the permission JOIN over the
 * in-memory tables (it computes the exact same set the three-query delegate path would),
 * so unit tests can exercise the store's raw fast-path branch. The simulation only
 * stands in for the JOIN's *result shape* — real SQL string/dialect correctness is the
 * job of integration/real-DB tests, not this fake.
 *
 * Pass `{ rawQuery: false }` to omit `$queryRaw` entirely (forcing the store onto its
 * three-query fallback), or `{ rawQuery: 'throw' }` to have `$queryRaw` throw (forcing
 * the store's catch-and-fallback branch).
 */
export function makeFakeClient(opts: { rawQuery?: boolean | 'throw' } = {}): PrismaAuthzClientLike {
  const { rawQuery = true } = opts;
  const role = makeDelegate();
  const permission = makeDelegate();
  const rolePermission = makeDelegate();
  const userRole = makeDelegate();

  const client: PrismaAuthzClientLike = { role, permission, rolePermission, userRole };

  if (rawQuery) {
    // The store only ever calls `$queryRaw` with the permission JOIN whose bound
    // params, in order, are `[userType, userId]`. We don't parse the SQL — we
    // reproduce the join's result from the in-memory rows.
    client.$queryRaw = (async <T = unknown>(
      _query: TemplateStringsArray,
      ...values: unknown[]
    ): Promise<T> => {
      if (rawQuery === 'throw') {
        throw new Error('simulated $queryRaw failure');
      }
      const [userType, userId] = values as [string, string];

      const roleIds = userRole.rows
        .filter((r) => r.userType === userType && r.userId === userId)
        .map((r) => r.roleId as string);
      const permissionIds = new Set(
        rolePermission.rows
          .filter((rp) => roleIds.includes(rp.roleId as string))
          .map((rp) => rp.permissionId as string),
      );
      const names = new Set(
        permission.rows
          .filter((p) => permissionIds.has(p.id as string))
          .map((p) => p.name as string),
      );
      return [...names].map((name) => ({ name })) as T;
    }) as PrismaAuthzClientLike['$queryRaw'];
  }

  return client;
}
