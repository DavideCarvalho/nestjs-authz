import { normalizeVerdict } from '../decision-provider.js';
import { authzRuntime } from '../runtime.js';

/** The resource of a policy check: its first argument, when that is an object or a class. */
function resourceOf(args: readonly unknown[]): object | undefined {
  const first = args[0];
  return (typeof first === 'object' && first !== null) || typeof first === 'function'
    ? (first as object)
    : undefined;
}

/**
 * Asks the `superAdmin` hook given to `AuthzModule.forRoot()`. `true` grants; anything
 * else falls through. Call it from your own `before()` when a policy cannot extend
 * {@link AuthzPolicy}.
 */
export async function superAdminBefore(
  user: unknown,
  ability: string,
  resource?: object,
): Promise<true | undefined> {
  const hook = authzRuntime().superAdmin;
  if (!hook) return undefined;
  return (await hook(user ?? null, ability, resource)) === true ? true : undefined;
}

/**
 * Asks the external decision point (`DECISION_PROVIDER`, e.g. the Cerbos adapter), when
 * one is registered: `true` allows, `false` denies, `undefined` abstains (no provider, or
 * it has no opinion). Call it from your own `before()` when a policy cannot extend
 * {@link AuthzPolicy}.
 */
export async function decisionProviderBefore(
  user: unknown,
  ability: string,
  resource?: object,
): Promise<boolean | undefined> {
  const provider = authzRuntime().decisionProvider();
  if (!provider) return undefined;
  return normalizeVerdict(await provider.decide(user ?? null, ability, resource)).allowed;
}

/**
 * Base class for official policies that honor the global `superAdmin` hook and the
 * optional external decision point.
 *
 * The official guard runs only each policy's own `before()`, so a global "super-admins
 * may do anything" needs every policy to ask. Extend this class and they do:
 *
 * ```ts
 * @Policy()
 * export class PostPolicy extends AuthzPolicy {
 *   update(user: User | null, post: Post) { return post.authorId === user?.id; }
 * }
 * ```
 *
 * `before()` asks `superAdmin(user, ability, resource)` (a `true` allows), then the
 * `DECISION_PROVIDER` when one is registered (its allow or deny is final, `undefined`
 * abstains), then lets the ability decide. The resource is the check's first argument.
 * To add your own `before()`, override it and call `super.before(...)` first.
 */
export abstract class AuthzPolicy {
  before(
    user: unknown,
    ability: string,
    ...args: unknown[]
  ): boolean | undefined | Promise<boolean | undefined> {
    const resource = resourceOf(args);
    return (async () => {
      if (await superAdminBefore(user, ability, resource)) return true;
      return decisionProviderBefore(user, ability, resource);
    })();
  }
}
