import type { ResourceRef } from '@dudousxd/nestjs-authz-client';
import type { ReactNode } from 'react';
import { useCan } from './use-can.js';

/** Props for {@link Can}. */
export interface CanProps {
  /** The ability to check (e.g. `'post.create'` or `'update'`). */
  ability: string;
  /** Optional resource the ability is checked against (`{ type, id }`). */
  of?: ResourceRef;
  /** Rendered when the verdict is allowed. */
  children: ReactNode;
  /** Rendered when the verdict is denied (default: nothing). */
  fallback?: ReactNode;
}

/**
 * Render `children` only when `useCan(ability, of)` is allowed; otherwise render
 * `fallback` (default `null`). For a hydrated ability the decision is synchronous
 * with no request.
 *
 * ```tsx
 * <Can ability="update" of={{ type: 'Post', id: post.id }} fallback={<Locked />}>
 *   <EditButton />
 * </Can>
 * ```
 */
export function Can({ ability, of, children, fallback = null }: CanProps) {
  const { allowed } = useCan(ability, of);
  return <>{allowed ? children : fallback}</>;
}
