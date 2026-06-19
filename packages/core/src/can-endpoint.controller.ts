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
 * Batch request body: an array of `{ ability, resource? }` items. The endpoint
 * accepts EITHER a single {@link CanRequestBody} or this array — a list page can
 * authorize all of its cards in ONE round-trip instead of N. Mirrors the payload
 * the client's `createCanBatch` emits.
 */
export type CanBatchRequestBody = CanRequestBody[];

/** One batch result: echoes the item's `ability`/`resource` plus the verdict. */
export interface CanBatchResultItem {
  ability: string;
  resource?: { type: string; id?: string | number } | null;
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
    async can(
      @Body() body: CanRequestBody | CanBatchRequestBody,
    ): Promise<CanResponseBody | CanBatchResultItem[]> {
      // Array body → batch path (one user/permission resolution for the whole list).
      if (Array.isArray(body)) {
        return this.canBatch(body);
      }
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
     * Batch verdicts for an array body. Rehydrates each item's resource shim (via
     * `resourceLoaders`, same as the single path), then resolves the whole list in
     * ONE pass via `gate.forUser(currentUser).allowsMany(...)` so the user and the
     * permission set are resolved once. Each result echoes the original
     * `ability`/`resource` so the client can map verdicts back to its cards. A
     * not-found loader, an empty ability, or an unresolved ability denies that item
     * (never fails the whole batch).
     */
    private async canBatch(items: CanBatchRequestBody): Promise<CanBatchResultItem[]> {
      // Validate + rehydrate each item up front. `verdicts[i] === false` already
      // pins the outright-denials (bad ability / not-found resource); `undefined`
      // means "send to the batch". `batchInput` carries the surviving items plus
      // their original index so verdicts map back in order.
      const verdicts: Array<boolean | undefined> = new Array(items.length).fill(undefined);
      const echo: Array<CanRequestBody['resource'] | undefined> = new Array(items.length);
      const batchInput: Array<{ index: number; ability: string; resource?: object }> = [];

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        echo[i] = item?.resource ?? undefined;
        const ability = item?.ability;
        if (typeof ability !== 'string' || ability.length === 0) {
          verdicts[i] = false;
          continue;
        }
        const target = await this.rehydrate(item?.resource ?? undefined);
        if (target === null) {
          // A registered loader produced nothing → not found → deny this item.
          verdicts[i] = false;
          continue;
        }
        batchInput.push(
          target === undefined ? { index: i, ability } : { index: i, ability, resource: target },
        );
      }

      // ONE pass over the surviving items: user + permission set resolved once.
      // `allowsMany` is fault-isolating, so an unresolved ability denies just its item.
      const results = await this.gate.allowsMany(
        batchInput.map((b) =>
          b.resource === undefined
            ? { ability: b.ability }
            : { ability: b.ability, resource: b.resource },
        ),
      );
      results.forEach((r, k) => {
        const original = batchInput[k];
        if (original) verdicts[original.index] = r.allowed;
      });

      return items.map((item, i) => {
        const ability = typeof item?.ability === 'string' ? item.ability : '';
        const allowed = verdicts[i] ?? false;
        const resource = echo[i];
        return resource == null ? { ability, allowed } : { ability, resource, allowed };
      });
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
