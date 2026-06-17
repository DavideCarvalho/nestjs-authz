import { Body, Controller, Inject, Optional, type Type } from '@nestjs/common';
import { Post as HttpPost } from '@nestjs/common';
import { Gate } from './gate.js';
import { RESOURCE_HYDRATOR } from './tokens.js';
import type { ResourceLoaderMap } from './types.js';

/**
 * Request body for the fallback `can` endpoint. Mirrors the payload emitted by
 * the codegen `can()` helper: `{ ability, resource?: { type, id } | null }`.
 */
export interface CanRequestBody {
  ability: string;
  resource?: { type: string; id?: string | number } | null;
}

/** Response shape: a single boolean verdict. */
export interface CanResponseBody {
  allowed: boolean;
}

/**
 * Build the opt-in fallback controller class, mounted at `path`. Kept as a
 * factory so the route path is configurable via `AuthzModule.forRoot({ canEndpoint })`.
 *
 * The endpoint runs `gate.allows(ability, resource?)` for the CURRENT (context)
 * user.
 *
 * RESOURCE REHYDRATION — how per-instance decisions resolve:
 * the client sends a `{ type, id }` shim whose constructor is `Object`, which never
 * matches a registered instance `@Policy` (those are keyed by the entity constructor).
 * To bridge that, register `resourceLoaders` in `AuthzModule.forRoot({ resourceLoaders })`
 * (keyed by the `type` name): when a loader exists for `resource.type`, the endpoint
 * `await`s `loader(id)` and authorizes the REAL entity, so the instance `@Policy`
 * matches and its method runs. A loader returning nullish → `{ allowed: false }` (not
 * found). With NO loader for the type the raw shim is forwarded as before, so only
 * class-level abilities and ad-hoc gates resolve and a resource-bound ability denies
 * (a deliberate, documented fall-through, not a silent dead-end). An unresolved ability
 * is likewise treated as a deny (never a 500).
 */
export function createCanController(path: string): Type<unknown> {
  @Controller(path)
  class AuthzCanController {
    constructor(
      private readonly gate: Gate,
      @Optional()
      @Inject(RESOURCE_HYDRATOR)
      private readonly loaders?: ResourceLoaderMap,
    ) {}

    @HttpPost()
    async can(@Body() body: CanRequestBody): Promise<CanResponseBody> {
      const ability = body?.ability;
      if (typeof ability !== 'string' || ability.length === 0) {
        return { allowed: false };
      }
      const resource = body?.resource ?? undefined;
      try {
        const target = await this.rehydrate(resource);
        // A registered loader that produced nothing → not found → deny.
        if (target === null) return { allowed: false };
        const allowed = await this.gate.allows(ability, target);
        return { allowed };
      } catch {
        // Unresolved/ambiguous ability — fail closed.
        return { allowed: false };
      }
    }

    /**
     * Turn the client's `{ type, id }` shim into the resource the gate authorizes.
     * - No resource → `undefined` (class-level ability).
     * - Loader registered for `type` → the loaded entity, or `null` when the loader
     *   yields nullish ("not found", which the caller maps to a deny).
     * - No loader for `type` → the raw shim, forwarded as before (class-level / gate only).
     */
    private async rehydrate(
      resource: CanRequestBody['resource'] | undefined,
    ): Promise<object | null | undefined> {
      if (resource == null) return undefined;
      const loader = this.loaders?.[resource.type];
      if (typeof loader !== 'function') return resource as object;
      const loaded = await loader(resource.id as string | number);
      return loaded == null ? null : (loaded as object);
    }
  }

  return AuthzCanController;
}

/** Default mount path for the fallback endpoint (matches codegen's `/authz/can`). */
export const DEFAULT_CAN_ENDPOINT_PATH = 'authz/can';
