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
}

/**
 * DI token for the app-provided Prisma client ({@link PrismaAuthzClientLike})
 * injected into {@link PrismaAuthzStore}.
 */
export const PRISMA_CLIENT = Symbol.for('@dudousxd/nestjs-authz-prisma:client');
