/**
 * Structural typings + DI token for the Prisma client consumed by
 * {@link PrismaAuthzStore}.
 *
 * The adapter deliberately does NOT import a generated `@prisma/client` type.
 * Instead it depends on a minimal structural interface describing only the model
 * delegate methods it uses. This keeps the package free of any `prisma generate`
 * step and decouples it from the consumer's generated client location/version — a
 * real `PrismaClient` instance structurally satisfies {@link PrismaAuthzClientLike},
 * so you can inject it directly.
 *
 * ## Required Prisma models
 *
 * The consumer's `schema.prisma` must declare these models (the user is referenced
 * **by id only** — this package never owns a users table):
 *
 * ```prisma
 * model Role {
 *   id        String   @id
 *   name      String   @unique
 *   guard     String?
 *   createdAt DateTime @default(now())
 *
 *   @@map("authz_roles")
 * }
 *
 * model Permission {
 *   id        String   @id
 *   name      String   @unique
 *   guard     String?
 *   createdAt DateTime @default(now())
 *
 *   @@map("authz_permissions")
 * }
 *
 * model RolePermission {
 *   roleId       String
 *   permissionId String
 *
 *   @@id([roleId, permissionId])
 *   @@map("authz_role_permission")
 * }
 *
 * model UserRole {
 *   userType String
 *   userId   String
 *   roleId   String
 *
 *   @@id([userType, userId, roleId])
 *   @@index([userType, userId])
 *   @@map("authz_user_role")
 * }
 * ```
 *
 * Apply it with `prisma migrate` / `prisma db push` — this adapter is
 * consumer-managed and never runs DDL.
 *
 * ## Optional single-round-trip fast path (`$queryRaw`)
 *
 * `getPermissionsForUser` can assemble a user's granted-permission set in ONE
 * database round-trip via a raw JOIN instead of the default three sequential
 * delegate queries. To allow that, the interface exposes an OPTIONAL `$queryRaw`
 * tagged-template method (see {@link PrismaAuthzClientLike.$queryRaw}).
 *
 * Why raw SQL and not a Prisma relation filter?
 * - A relation filter (`permission.findMany({ where: { rolePermissions: { some } } })`)
 *   would force every consumer to declare a full back-relation graph across all four
 *   models in THEIR `schema.prisma`. That couples this adapter to the consumer's
 *   schema shape and breaks the package's "minimal structural client, no relations
 *   required" philosophy. REJECTED.
 * - A `$queryRaw` JOIN needs NO relation fields in the consumer's schema — it works
 *   off the existing tables/columns documented above. This preserves the decoupled,
 *   relation-free design. CHOSEN.
 *
 * The trade-off: the raw SQL hard-codes the documented `@@map` table names plus the
 * (camelCase, unquoted-in-schema → must be double-quoted) column names, so it is NOT
 * portable to every SQL dialect or custom `@@map`. The store therefore treats the raw
 * path as an OPTIONAL optimization and gracefully FALLS BACK to the three-query path
 * on any failure — correctness is preserved everywhere; speed is gained on the common
 * (Postgres + documented schema) case.
 */

/**
 * Minimal structural view of a Prisma model delegate (the methods the store calls).
 *
 * The arg/return types are intentionally `any`: a generated Prisma delegate's method
 * signatures are far narrower (model-specific), and a structural `unknown`/`Record` here
 * would make a real `PrismaClient` *not* assignable to this interface (arg positions are
 * contravariant). `any` keeps a concrete client structurally compatible without pulling in
 * `@prisma/client`.
 */
export interface PrismaModelDelegate {
  // biome-ignore lint/suspicious/noExplicitAny: see interface doc — keeps a real PrismaClient structurally assignable.
  create(args: { data: any }): Promise<any>;
  // biome-ignore lint/suspicious/noExplicitAny: see interface doc — keeps a real PrismaClient structurally assignable.
  findFirst(args: { where: any }): Promise<any>;
  // biome-ignore lint/suspicious/noExplicitAny: see interface doc — keeps a real PrismaClient structurally assignable.
  findMany(args: { where: any }): Promise<any[]>;
  // biome-ignore lint/suspicious/noExplicitAny: see interface doc — keeps a real PrismaClient structurally assignable.
  deleteMany(args: { where: any }): Promise<{ count: number }>;
}

/** Minimal structural view of a Prisma client exposing the four RBAC models. */
export interface PrismaAuthzClientLike {
  role: PrismaModelDelegate;
  permission: PrismaModelDelegate;
  rolePermission: PrismaModelDelegate;
  userRole: PrismaModelDelegate;

  /**
   * OPTIONAL tagged-template raw query, matching the real `PrismaClient.$queryRaw`
   * signature. A real `PrismaClient` always provides it (so there is NO extra burden
   * on consumers injecting one). It is declared OPTIONAL so that purely structural
   * clients / in-memory fakes that omit it — or setups where the raw path is unsafe
   * (non-Postgres quoting, custom `@@map` table names) — remain assignable and simply
   * fall back to the three-query delegate path. See the file-level doc for the full
   * raw-vs-relation rationale.
   *
   * The `any` value type mirrors `PrismaModelDelegate` above: a narrower
   * `unknown`/`Record` would make a real `PrismaClient` not structurally assignable
   * (arg/return-position variance), which is exactly what this package avoids.
   */
  // biome-ignore lint/suspicious/noExplicitAny: see doc — keeps a real PrismaClient structurally assignable.
  $queryRaw?<T = unknown>(query: TemplateStringsArray, ...values: any[]): Promise<T>;
}

/**
 * DI token for the app-provided Prisma client ({@link PrismaAuthzClientLike})
 * injected into {@link PrismaAuthzStore}.
 */
export const PRISMA_CLIENT = Symbol.for('@dudousxd/nestjs-authz-prisma:client');
