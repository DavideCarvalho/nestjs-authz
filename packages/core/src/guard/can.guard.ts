import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
} from '@nestjs/common';
import { ModuleRef, Reflector } from '@nestjs/core';
import type { CanMetadata } from '../decorator/can.decorator.js';
import { ResourceResolverMissingException } from '../errors/exceptions.js';
import { Gate } from '../gate.js';
import type { ResourceResolver } from '../resource-resolver.js';
import { CAN_METADATA, RESOURCE_RESOLVER } from '../tokens.js';
import type { Resource } from '../types.js';

/**
 * Enforces `@Can(ability, Resource?)` on routes.
 *
 * - No `@Can` metadata → allow (the guard is inert on un-annotated routes).
 * - Resource class + not class-level → load instance via {@link ResourceResolver}
 *   (a missing/undefined instance is a denial).
 * - Class-level or no resource → dispatch against the class / ad-hoc gate.
 *
 * The decision is delegated to {@link Gate.authorize}, which throws
 * `ForbiddenException` on denial.
 */
@Injectable()
export class CanGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly gate: Gate,
    private readonly moduleRef: ModuleRef,
    @Optional()
    @Inject(RESOURCE_RESOLVER)
    private readonly resolver?: ResourceResolver,
  ) {}

  /**
   * Locate the resource resolver. Prefers the value injected into this module;
   * falls back to a non-strict {@link ModuleRef} lookup so a resolver provided by
   * ANY module (e.g. the app root) is found even though the guard lives in the
   * global AuthzModule.
   */
  private resolveResolver(): ResourceResolver | undefined {
    if (this.resolver) return this.resolver;
    try {
      return this.moduleRef.get<ResourceResolver>(RESOURCE_RESOLVER, { strict: false });
    } catch {
      return undefined;
    }
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const meta = this.reflector.getAllAndOverride<CanMetadata | undefined>(CAN_METADATA, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (!meta) return true;

    // Ad-hoc gate or class-level → no instance to load.
    if (!meta.resource || meta.classLevel) {
      const resource = meta.classLevel ? (meta.resource as unknown as Resource) : undefined;
      await this.gate.authorize(meta.ability, resource);
      return true;
    }

    // Instance ability → resolve the resource by route param / app resolver.
    const resolver = this.resolveResolver();
    if (!resolver) {
      throw new ResourceResolverMissingException(meta.ability);
    }
    const instance = await resolver.resolve(meta.resource, ctx);
    if (instance === undefined) {
      // Not found → deny rather than dispatch a policy with a bogus resource.
      throw new ForbiddenException(`Unauthorized: ${meta.ability}`);
    }
    await this.gate.authorize(meta.ability, instance);
    return true;
  }
}
