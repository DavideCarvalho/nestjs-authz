import { defaultGetUser } from '@nestjs/authorization';
import type { ExecutionContext } from '@nestjs/common';
import type { DecisionProvider } from './decision-provider.js';
import { IdParamResourceResolver, type ResourceResolver } from './resource-resolver.js';
import type { SuperAdminHook } from './types.js';

/**
 * What `@Can()` argument resolvers and policy base classes need from the app but
 * cannot inject: the official resolvers run with only the `ExecutionContext`, and a
 * policy base class cannot add constructor parameters to its subclasses. `AuthzModule`
 * fills this in when it boots. One application per process is the expected case; with
 * several, the last one to boot wins.
 */
interface AuthzRuntime {
  resourceResolver: ResourceResolver;
  superAdmin: SuperAdminHook | undefined;
  /** The external decision point, looked up lazily (an adapter may register it late). */
  decisionProvider: () => DecisionProvider | undefined;
  getUser: (context: ExecutionContext) => unknown;
}

const noDecisionProvider = (): DecisionProvider | undefined => undefined;

const runtime: AuthzRuntime = {
  resourceResolver: new IdParamResourceResolver(),
  superAdmin: undefined,
  decisionProvider: noDecisionProvider,
  getUser: defaultGetUser,
};

/** @internal Called by `AuthzModule` at boot, and by the testing helpers. */
export function configureAuthzRuntime(patch: Partial<AuthzRuntime>): void {
  if (patch.resourceResolver) runtime.resourceResolver = patch.resourceResolver;
  if ('superAdmin' in patch) runtime.superAdmin = patch.superAdmin;
  if (patch.decisionProvider) runtime.decisionProvider = patch.decisionProvider;
  if (patch.getUser) runtime.getUser = patch.getUser;
}

/** @internal Restore the defaults (tests). */
export function resetAuthzRuntime(): void {
  runtime.resourceResolver = new IdParamResourceResolver();
  runtime.superAdmin = undefined;
  runtime.decisionProvider = noDecisionProvider;
  runtime.getUser = defaultGetUser;
}

/** @internal */
export function authzRuntime(): Readonly<AuthzRuntime> {
  return runtime;
}

/**
 * The user the official guard sees for this call: the `getUser` given to
 * `AuthorizationModule.forRoot()`, else the official `defaultGetUser`. `null` for a guest.
 */
export async function currentUserOf(context: ExecutionContext): Promise<unknown> {
  const user = await runtime.getUser(context);
  return user === undefined || user === false ? null : user;
}
