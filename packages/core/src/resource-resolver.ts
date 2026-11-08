import type { ExecutionContext, Type } from '@nestjs/common';

/** Per-call hints `byId(Resource, { param })` passes to the resolver. */
export interface ResourceResolveHints {
  /** The route param holding the id, when `byId` named one. */
  param?: string;
}

/**
 * Loads the resource a `byId(Resource)` argument resolver hands to the policy
 * (`@Can(PostPolicy, 'update', byId(Post))`). Register one, typically ORM-backed, with
 * `AuthzModule.forRoot({ resourceResolver })`. Return `undefined` for "not found":
 * `byId` then refuses the call with a 403 before the policy runs.
 */
export interface ResourceResolver {
  resolve(
    resource: Type<unknown>,
    ctx: ExecutionContext,
    hints?: ResourceResolveHints,
  ): Promise<object | undefined> | object | undefined;
}

/**
 * Default resolver: reads the route `:id` param and produces a lightweight `{ id }`
 * object whose prototype is the resource class's, enough for ownership checks on
 * `resource.id` without an ORM. Register your own {@link ResourceResolver} to load
 * real entities.
 */
export class IdParamResourceResolver implements ResourceResolver {
  constructor(private readonly param: string = 'id') {}

  resolve(
    resource: Type<unknown>,
    ctx: ExecutionContext,
    hints?: ResourceResolveHints,
  ): object | undefined {
    if (ctx.getType() !== 'http') return undefined;
    const req = ctx.switchToHttp().getRequest<{ params?: Record<string, unknown> }>();
    const id = req?.params?.[hints?.param ?? this.param];
    if (id === undefined) return undefined;
    const instance = Object.create(resource.prototype) as Record<string, unknown>;
    instance.id = id;
    return instance;
  }
}
