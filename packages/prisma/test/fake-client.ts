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

/** A structural fake Prisma client (in-memory) satisfying {@link PrismaAuthzClientLike}. */
export function makeFakeClient(): PrismaAuthzClientLike {
  return {
    role: makeDelegate(),
    permission: makeDelegate(),
    rolePermission: makeDelegate(),
    userRole: makeDelegate(),
  };
}
