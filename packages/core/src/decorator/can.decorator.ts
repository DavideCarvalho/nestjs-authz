import 'reflect-metadata';
import { SetMetadata, type Type } from '@nestjs/common';
import { CAN_METADATA } from '../tokens.js';

export interface CanOptions {
  /**
   * Class-level ability (e.g. `create`): the policy method is keyed to the
   * resource class but receives NO instance, so the guard skips resource loading.
   */
  classLevel?: boolean;
}

export interface CanMetadata {
  ability: string;
  /** Resource class — to load an instance, or (for class-level) to locate the policy. */
  resource?: Type<unknown>;
  /** When true, skip resource loading and dispatch against the resource class. */
  classLevel?: boolean;
}

/**
 * Guard a route with an authorization check.
 *
 * @example
 *   `@Can('update', Post)`                    // resolve Post by :id, run PostPolicy.update(user, post)
 *   `@Can('create', Post, { classLevel: true })` // run PostPolicy.create(user) — no instance loaded
 *   `@Can('access-admin')`                    // ad-hoc gate, no resource
 *
 * When a resource class is provided (and not `classLevel`), the guard loads an
 * instance via the registered `ResourceResolver` (default: by route `:id`).
 */
export function Can(
  ability: string,
  resource?: Type<unknown>,
  options?: CanOptions,
): MethodDecorator & ClassDecorator {
  const meta: CanMetadata = { ability };
  if (resource !== undefined) meta.resource = resource;
  if (options?.classLevel) meta.classLevel = true;
  return SetMetadata(CAN_METADATA, meta);
}
