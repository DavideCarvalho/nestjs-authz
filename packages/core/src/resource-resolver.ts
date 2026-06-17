import type { ExecutionContext, Type } from '@nestjs/common';

/**
 * Resolves a resource instance for a `@Can(ability, Resource)` route so the guard
 * can pass it to the policy method. Apps register an implementation (typically
 * ORM-backed) via `AuthzModule.forRoot({ ... })` or as a provider bound to the
 * {@link RESOURCE_RESOLVER} token.
 *
 * Class-level abilities (no resource class on `@Can`) never call the resolver.
 */
export interface ResourceResolver {
  /**
   * Load the resource instance for `resource` in the given request context.
   * Return `undefined` to signal "not found" — the guard treats a missing
   * resource as a denial.
   */
  resolve(
    resource: Type<unknown>,
    ctx: ExecutionContext,
  ): Promise<object | undefined> | object | undefined;
}

/**
 * Default resolver: reads the route `:id` param and produces a lightweight
 * `{ id }` shim of the requested resource class. This keeps the guard usable
 * out-of-the-box (e.g. ownership checks on `resource.id`) without an ORM, while
 * apps that need real entities register their own {@link ResourceResolver}.
 */
export class IdParamResourceResolver implements ResourceResolver {
  constructor(private readonly param: string = 'id') {}

  resolve(resource: Type<unknown>, ctx: ExecutionContext): object | undefined {
    const req = ctx.switchToHttp().getRequest<{ params?: Record<string, unknown> }>();
    const id = req?.params?.[this.param];
    if (id === undefined) return undefined;
    // Construct a shaped instance so `instance.constructor === resource`, which
    // is how PolicyRegistry maps an instance back to its policy.
    const instance = Object.create(resource.prototype) as Record<string, unknown>;
    instance.id = id;
    return instance;
  }
}
