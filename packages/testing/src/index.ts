/**
 * Test helpers for `@dudousxd/nestjs-authz` on `@nestjs/authorization`.
 *
 * {@link buildGate} compiles a real Nest testing module with the official
 * `AuthorizationModule` and `AuthzModule`, so every policy decision goes through the
 * official `AuthorizationService`, exactly as in the app. Assert with
 * {@link expectCan} / {@link expectCannot}, and read what a route requires with
 * {@link requirementsOf}.
 *
 * @example
 * ```ts
 * const gate = await buildGate({ policies: [PostPolicy] });
 * await expectCan(gate, { id: 1 }, 'update', new Post(10, 1));       // linked with @PolicyFor(Post)
 * await expectCan(gate, { id: 1 }, PostPolicy, 'update', new Post(10, 1)); // official style
 * ```
 *
 * @module
 */

import {
  AuthzModule,
  BoundGate,
  Gate,
  type GateFn,
  PERMISSION_PROVIDER,
  type PermissionProvider,
  ROLE_PROVIDER,
  type Resource,
  type ResourceResolver,
  type RoleProvider,
  type SuperAdminHook,
  type User,
  getStaticCanArgs,
  routeRequirements,
} from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import type { ExecutionContext, Provider, Type } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';

export { FakePermissionProvider, FakeRoleProvider } from './fakes.js';
export type { FakePermissionGrants } from './fakes.js';

/** Fixture configuration for {@link buildGate}. Every field is optional. */
export interface BuildGateOptions {
  /** Official `@Policy()` classes (or providers, e.g. `{ provide: PostPolicy, useValue }`). */
  policies?: Provider[];
  /** More providers the policies depend on. */
  providers?: Provider[];
  /** Controllers, when the test also boots routes. */
  controllers?: Type<unknown>[];
  /** Ad-hoc gates keyed by ability name (`gate.define(name, fn)`). */
  gates?: Record<string, GateFn>;
  /** The global super-admin hook. */
  superAdmin?: SuperAdminHook;
  /** How roles are read off the user (default `user.roles` / `user.role`). */
  resolveRoles?: (user: User) => string[] | undefined | Promise<string[] | undefined>;
  /** The resolver `byId()` uses. */
  resourceResolver?: ResourceResolver;
  /** The official `getUser`, for routes. */
  getUser?: (context: ExecutionContext) => unknown;
  /** An in-memory permission seam. See {@link FakePermissionProvider}. */
  permissionProvider?: PermissionProvider;
  /** An in-memory role seam. See {@link FakeRoleProvider}. */
  roleProvider?: RoleProvider;
}

/** The compiled testing module, initialized, and its {@link Gate}. */
export interface AuthzTestingModule {
  module: TestingModule;
  gate: Gate;
}

/**
 * Compile and initialize a Nest testing module with the official `AuthorizationModule`,
 * `AuthzModule` and the fixtures. Close `module` when done (or let the test process end).
 */
export async function createAuthzTestingModule(
  options: BuildGateOptions = {},
): Promise<AuthzTestingModule> {
  const module = await Test.createTestingModule({
    imports: [
      AuthorizationModule.forRoot(options.getUser ? { getUser: options.getUser } : {}),
      AuthzModule.forRoot({
        ...(options.superAdmin ? { superAdmin: options.superAdmin } : {}),
        ...(options.resolveRoles ? { resolveRoles: options.resolveRoles } : {}),
        ...(options.resourceResolver ? { resourceResolver: options.resourceResolver } : {}),
      }),
    ],
    controllers: options.controllers ?? [],
    providers: [
      ...(options.policies ?? []),
      ...(options.providers ?? []),
      ...(options.permissionProvider
        ? [{ provide: PERMISSION_PROVIDER, useValue: options.permissionProvider }]
        : []),
      ...(options.roleProvider ? [{ provide: ROLE_PROVIDER, useValue: options.roleProvider }] : []),
    ],
  }).compile();
  module.useLogger(false);
  await module.init();
  const gate = module.get(Gate);
  for (const [ability, fn] of Object.entries(options.gates ?? {})) gate.define(ability, fn);
  return { module, gate };
}

/** A real {@link Gate} from fixtures. See {@link createAuthzTestingModule}. */
export async function buildGate(options: BuildGateOptions = {}): Promise<Gate> {
  return (await createAuthzTestingModule(options)).gate;
}

/** A {@link BoundGate} for a fixture `user`: `(await buildGate(options)).forUser(user)`. */
export async function buildBoundGate(
  user: User,
  options: BuildGateOptions = {},
): Promise<BoundGate> {
  return (await buildGate(options)).forUser(user);
}

/** A {@link Gate} (then `user` is required) or an already-bound {@link BoundGate}. */
export type GateLike = Gate | BoundGate;

function bind(gate: GateLike, user: User): BoundGate {
  return gate instanceof BoundGate ? gate : gate.forUser(user);
}

/** A thrown assertion failure from {@link expectCan}/{@link expectCannot}. */
export class AuthzAssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthzAssertionError';
  }
}

/** What a check names: a string ability (+ resource), or an official policy + ability (+ args). */
type Check =
  | [ability: string, resource?: Resource]
  | [policy: Type<unknown>, ability: string, ...args: unknown[]];

function allows(gate: BoundGate, check: Check): Promise<boolean> {
  return (gate.allows as (...a: unknown[]) => Promise<boolean>).apply(gate, check);
}

function describeCheck(check: Check): string {
  if (typeof check[0] === 'function') return `${check[0].name}.${String(check[1])}`;
  const [ability, resource] = check as [string, Resource | undefined];
  return `"${ability}"${describeResource(resource)}`;
}

/**
 * Assert the user CAN: `expectCan(gate, user, 'update', post)` or
 * `expectCan(gate, user, PostPolicy, 'update', post)`. Throws {@link AuthzAssertionError}.
 */
export async function expectCan(gate: GateLike, user: User, ...check: Check): Promise<void> {
  if (!(await allows(bind(gate, user), check))) {
    throw new AuthzAssertionError(
      `Expected user to be able to ${describeCheck(check)}, but it was DENIED.`,
    );
  }
}

/**
 * Assert the user CANNOT. An unresolved ability (no policy, gate or permission answers
 * it) counts as "cannot", the deny-by-default outcome.
 */
export async function expectCannot(gate: GateLike, user: User, ...check: Check): Promise<void> {
  let allowed: boolean;
  try {
    allowed = await allows(bind(gate, user), check);
  } catch {
    return;
  }
  if (allowed) {
    throw new AuthzAssertionError(
      `Expected user to be UNABLE to ${describeCheck(check)}, but it was ALLOWED.`,
    );
  }
}

/** One official `@Can()` requirement of a route, with its static arguments when it has some. */
export interface RouteRequirement {
  policy: Type<unknown>;
  ability: string;
  /** The arguments of a static resolver (`roles('admin')`, `permission(...)`), else `undefined`. */
  staticArgs: readonly unknown[] | undefined;
  /** True when the resolver depends on the call (`byId(Post)`, a custom function). */
  dynamic: boolean;
}

/**
 * What the official guard requires on `controller.method`, class-level first. Lets a test
 * assert a route's protection without booting HTTP:
 *
 * ```ts
 * expect(requirementsOf(PostController, 'publish')).toEqual([
 *   { policy: PermissionPolicy, ability: 'has', staticArgs: ['posts.publish'], dynamic: false },
 * ]);
 * ```
 */
export function requirementsOf(controller: Type<unknown>, method: string): RouteRequirement[] {
  const handler = (controller.prototype as Record<string, object>)[method];
  if (!handler) throw new Error(`${controller.name} has no method '${method}'.`);
  return routeRequirements(controller, handler).map(({ policy, ability, args }) => {
    const staticArgs = getStaticCanArgs(args);
    return { policy, ability, staticArgs, dynamic: args !== undefined && staticArgs === undefined };
  });
}

function describeResource(resource: Resource | undefined): string {
  if (resource === undefined) return '';
  const name = (resource as { constructor?: { name?: string } }).constructor?.name;
  return name && name !== 'Object' ? ` on a ${name}` : ' on the resource';
}
