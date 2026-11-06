import { type ExecutionContext, ForbiddenException, type Type } from '@nestjs/common';
import { authzRuntime } from './runtime.js';

/**
 * The key, in the global symbol registry, of the arguments a static `@Can()` resolver
 * always returns. Tools that evaluate a requirement without a call (the Aviary agent,
 * before it offers a tool to a model) read it off the resolver function.
 */
export const STATIC_CAN_ARGS = Symbol.for('@dudousxd/static-can-args');

/** An official `@Can()` argument resolver. */
export type CanArgsResolver<A extends readonly unknown[] = readonly unknown[]> = (
  context: ExecutionContext,
) => A | Promise<A>;

/**
 * A resolver for `@Can()` that returns the same arguments on every call, marked as
 * static so they can be read without a call (see {@link STATIC_CAN_ARGS}).
 *
 * @example `@Can(FeaturePolicy, 'enabled', staticCanArgs('billing'))`
 */
export function staticCanArgs<const A extends readonly unknown[]>(...args: A): CanArgsResolver<A> {
  const resolver: CanArgsResolver<A> = () => args;
  Object.defineProperty(resolver, STATIC_CAN_ARGS, { value: args, enumerable: false });
  return resolver;
}

/** The arguments of a static resolver (from {@link staticCanArgs}), or `undefined`. */
export function getStaticCanArgs(resolver: unknown): readonly unknown[] | undefined {
  if (typeof resolver !== 'function') return undefined;
  const args = (resolver as unknown as Record<symbol, unknown>)[STATIC_CAN_ARGS];
  return Array.isArray(args) ? args : undefined;
}

/** `@Can(RolePolicy, 'has', roles('admin', 'editor'))`: the user holds any of the roles. */
export function roles<const R extends readonly string[]>(...names: R): CanArgsResolver<R> {
  return staticCanArgs(...names);
}

/** `@Can(PermissionPolicy, 'has', permission('posts.update'))`: the user holds the permission (wildcards apply). */
export function permission<const P extends readonly string[]>(...names: P): CanArgsResolver<P> {
  return staticCanArgs(...names);
}

/** Alias of {@link permission}, for several. */
export const permissions = permission;

/** `@Can(GatePolicy, 'allows', ability('access-admin'))`: a `gate.define()` gate or a named permission. */
export function ability<const A extends string>(name: A): CanArgsResolver<readonly [A]> {
  return staticCanArgs(name);
}

/** Options for {@link byId}. */
export interface ByIdOptions {
  /** The route param holding the id. Default: the resolver's (`'id'` for the default one). */
  param?: string;
}

const RESOLVED_RESOURCES = Symbol.for('@dudousxd/nestjs-authz:resolved-resources');

/**
 * `@Can(PostPolicy, 'update', byId(Post))`: loads the `Post` the route's `:id` names
 * with the registered {@link ResourceResolver}, and passes it to the ability. A
 * resource that is not found refuses the call with a 403 before the policy runs.
 *
 * The loaded record is kept on the request: read it in the handler with
 * {@link authorizedResource} instead of loading it again.
 */
export function byId<T>(
  resource: Type<T>,
  options: ByIdOptions = {},
): CanArgsResolver<readonly [T]> {
  return async (context) => {
    const hints = options.param === undefined ? {} : { param: options.param };
    const loaded = await authzRuntime().resourceResolver.resolve(resource, context, hints);
    if (loaded === undefined || loaded === null) throw new ForbiddenException();
    remember(context, resource, loaded);
    return [loaded as T] as const;
  };
}

function carrierOf(context: ExecutionContext): object | undefined {
  try {
    if (context.getType() === 'http') return context.switchToHttp().getRequest();
  } catch {
    return undefined;
  }
  return undefined;
}

function remember(context: ExecutionContext, resource: Type<unknown>, value: unknown): void {
  const carrier = carrierOf(context) as Record<symbol, Map<unknown, unknown>> | undefined;
  if (!carrier) return;
  const map = carrier[RESOLVED_RESOURCES] ?? new Map<unknown, unknown>();
  map.set(resource, value);
  carrier[RESOLVED_RESOURCES] = map;
}

/**
 * The record `byId(resource)` loaded for this request, if it ran. Pass the HTTP request
 * (or the execution context).
 */
export function authorizedResource<T>(requestOrContext: object, resource: Type<T>): T | undefined {
  const carrier =
    typeof (requestOrContext as ExecutionContext).switchToHttp === 'function'
      ? carrierOf(requestOrContext as ExecutionContext)
      : requestOrContext;
  const map = (carrier as Record<symbol, Map<unknown, unknown>> | undefined)?.[RESOLVED_RESOURCES];
  return map?.get(resource) as T | undefined;
}
