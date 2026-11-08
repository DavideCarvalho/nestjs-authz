import 'reflect-metadata';
import type { ExecutionContext, Type } from '@nestjs/common';

/**
 * The metadata keys `@nestjs/authorization` reads and writes. The package does not
 * export them, so they are spelled here, once. `test/official-contract.spec.ts`
 * fails if the official package stops honoring metadata written under these keys.
 */
export const OFFICIAL_POLICY_METADATA = 'authorization:policy';
/** Written by the official `@Can()`: an array of {@link OfficialCanRequirement}, read top-down. */
export const OFFICIAL_CAN_METADATA = 'authorization:can';
/** Written by the official `Can.Anyone()`. */
export const OFFICIAL_CAN_ANYONE_METADATA = 'authorization:can-anyone';
/**
 * Written by `@nestjs/authentication`'s `@Public()` (`true`) and `@Authenticate()` (`false`).
 * A registry symbol, which the official guard reads without depending on that package.
 */
export const OFFICIAL_PUBLIC_METADATA = Symbol.for('@nestjs/authentication:public');

/** One official `@Can()` requirement, as stored in the metadata. */
export interface OfficialCanRequirement {
  policy: Type<unknown>;
  ability: string;
  args?: (context: ExecutionContext) => readonly unknown[] | Promise<readonly unknown[]>;
}

/** True when `value` is a class marked with the official `@Policy()`. */
export function isOfficialPolicy(value: unknown): value is Type<unknown> {
  return (
    typeof value === 'function' && Reflect.getMetadata(OFFICIAL_POLICY_METADATA, value) === true
  );
}

/** The official `@Can()` requirements declared directly on `target` (a class or a method). */
export function readCanRequirements(target: object): OfficialCanRequirement[] {
  return (Reflect.getMetadata(OFFICIAL_CAN_METADATA, target) as OfficialCanRequirement[]) ?? [];
}

/**
 * The requirements the official guard enforces on `handler` of `type`: the class's
 * first, then the method's, the class's dropped when the method is opened with
 * `Can.Anyone()` or `@Public()`. Mirrors the official `routeChecks()`.
 */
export function routeRequirements(type: Type<unknown>, handler: object): OfficialCanRequirement[] {
  const methodOpen =
    Reflect.getMetadata(OFFICIAL_PUBLIC_METADATA, handler) === true ||
    Reflect.getMetadata(OFFICIAL_CAN_ANYONE_METADATA, handler) === true;
  return [...(methodOpen ? [] : readCanRequirements(type)), ...readCanRequirements(handler)];
}

/**
 * `dependency`, or a clear error when `@nestjs/authorization`'s `AuthorizationModule` is not
 * imported: without it Nest only reports an unresolvable constructor argument of `consumer`.
 */
export function requireOfficial<T>(dependency: T | undefined, name: string, consumer: string): T {
  if (dependency !== undefined && dependency !== null) return dependency;
  throw new Error(
    `AuthzModule: ${consumer} needs ${name} from @nestjs/authorization, which is not available. ` +
      'Import AuthorizationModule.forRoot() (global, its default) next to AuthzModule: ' +
      'imports: [AuthorizationModule.forRoot(), AuthzModule.forRoot()].',
  );
}
