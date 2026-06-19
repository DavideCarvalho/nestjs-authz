/**
 * Test helpers for `@dudousxd/nestjs-authz`.
 *
 * Build a real {@link Gate} (no Nest module, no DB) from fixture policies, ad-hoc
 * gates, hooks, and an optional in-memory permission/role provider — then assert
 * verdicts with {@link expectCan}/{@link expectCannot}. The helpers exercise the
 * SAME resolution path the production Gate uses, so a policy that passes here passes
 * in the app.
 *
 * @example
 * ```ts
 * const gate = buildGate({ policies: [new PostPolicy()] });
 * await expectCan(gate, { id: 1 }, 'update', new Post(1, 1));
 * await expectCannot(gate, { id: 2 }, 'update', new Post(1, 1));
 * ```
 *
 * @module
 */

import {
  type AfterHook,
  BoundGate,
  Gate,
  type GateFn,
  type PermissionProvider,
  type PolicyInstance,
  PolicyRegistry,
  type Resource,
  type RoleProvider,
  type SuperAdminHook,
  type User,
} from '@dudousxd/nestjs-authz';

export {
  FakePermissionProvider,
  FakeRoleProvider,
} from './fakes.js';
export type { FakePermissionGrants } from './fakes.js';

/** Fixture configuration for {@link buildGate}. Every field is optional. */
export interface BuildGateOptions {
  /**
   * Policy INSTANCES to register (e.g. `new PostPolicy()`). Unlike the Nest module,
   * the test helper does not run DI — pass already-constructed instances. Each MUST be
   * `@Policy(Resource)`-decorated (the registry resolves by resource constructor and
   * throws on an undecorated class, same as production).
   */
  policies?: PolicyInstance[];
  /** Ad-hoc, model-less gates keyed by ability name (same as `gate.define(name, fn)`). */
  gates?: Record<string, GateFn>;
  /** Global super-admin before-hook (Laravel `Gate::before`). */
  superAdmin?: SuperAdminHook;
  /** Global `after` hook (Laravel `Gate::after`). */
  after?: AfterHook;
  /** Override how a user's roles are derived (default reads `user.roles`/`user.role`). */
  resolveRoles?: (user: User) => string[] | undefined | Promise<string[] | undefined>;
  /**
   * An in-memory {@link PermissionProvider} (the RBAC seam) — grants named abilities
   * when the fixture user holds the permission. Use {@link FakePermissionProvider} for
   * a zero-DB stand-in.
   */
  permissionProvider?: PermissionProvider;
  /** An in-memory {@link RoleProvider} for coarse role checks. Use {@link FakeRoleProvider}. */
  roleProvider?: RoleProvider;
}

/**
 * Build a real {@link Gate} from fixtures — no Nest container, no database. The
 * returned Gate behaves exactly like the production one (same hooks, same RBAC seam,
 * same resolution order); only the wiring is in-memory.
 */
export function buildGate(options: BuildGateOptions = {}): Gate {
  const registry = new PolicyRegistry();
  for (const policy of options.policies ?? []) registry.register(policy);

  const moduleOptions = {
    ...(options.superAdmin ? { superAdmin: options.superAdmin } : {}),
    ...(options.after ? { after: options.after } : {}),
    ...(options.resolveRoles ? { resolveRoles: options.resolveRoles } : {}),
  };

  // Ctor: (policies, options, context?, moduleRef?, permissionProvider?, roleProvider?).
  const gate = new Gate(
    registry,
    moduleOptions,
    undefined,
    undefined,
    options.permissionProvider,
    options.roleProvider,
  );

  for (const [ability, fn] of Object.entries(options.gates ?? {})) {
    gate.define(ability, fn);
  }
  return gate;
}

/**
 * Build a {@link BoundGate} for a fixture `user` directly — sugar over
 * `buildGate(options).forUser(user)` for tests that focus on a single principal.
 */
export function buildBoundGate(user: User, options: BuildGateOptions = {}): BoundGate {
  return buildGate(options).forUser(user);
}

/**
 * Accept either a {@link Gate} (then `user` is required) or an already-bound
 * {@link BoundGate}. Lets the assertion helpers serve both styles.
 */
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

/**
 * Assert the user CAN perform `ability` (optionally on `resource`). Resolves when
 * allowed; throws {@link AuthzAssertionError} when denied. Works with either a
 * {@link Gate} (+ `user`) or a {@link BoundGate} (pass `undefined` for `user`).
 *
 * @example await expectCan(gate, { id: 1 }, 'update', post);
 * @example await expectCan(boundGate, undefined, 'create');
 */
export async function expectCan(
  gate: GateLike,
  user: User,
  ability: string,
  resource?: Resource,
): Promise<void> {
  const allowed = await bind(gate, user).allows(ability, resource);
  if (!allowed) {
    throw new AuthzAssertionError(
      `Expected user to be able to "${ability}"${describeResource(resource)}, but it was DENIED.`,
    );
  }
}

/**
 * Assert the user CANNOT perform `ability` (optionally on `resource`). Resolves when
 * denied; throws {@link AuthzAssertionError} when allowed. An unresolved ability
 * (no policy/gate) counts as "cannot" — the deny-by-default outcome a caller wants
 * to assert — so this never leaks the underlying `AbilityNotResolvedException`.
 */
export async function expectCannot(
  gate: GateLike,
  user: User,
  ability: string,
  resource?: Resource,
): Promise<void> {
  let allowed: boolean;
  try {
    allowed = await bind(gate, user).allows(ability, resource);
  } catch {
    // Unresolved/ambiguous ability → effectively "cannot" (deny by default).
    return;
  }
  if (allowed) {
    throw new AuthzAssertionError(
      `Expected user to be UNABLE to "${ability}"${describeResource(resource)}, but it was ALLOWED.`,
    );
  }
}

function describeResource(resource: Resource | undefined): string {
  if (resource === undefined) return '';
  const name = (resource as { constructor?: { name?: string } }).constructor?.name;
  return name && name !== 'Object' ? ` on a ${name}` : ' on the resource';
}
