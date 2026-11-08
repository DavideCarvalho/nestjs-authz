import 'reflect-metadata';
import { AuthorizationModule } from '@nestjs/authorization';
import type { ExecutionContext, INestApplication, Provider, Type } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { Gate } from '../../src/gate.js';
import { AuthzModule } from '../../src/module.js';
import type { PermissionProvider } from '../../src/permission-provider.js';
import type { RoleProvider } from '../../src/role-provider.js';
import { PERMISSION_PROVIDER, ROLE_PROVIDER } from '../../src/tokens.js';
import type { AuthzModuleOptions } from '../../src/types.js';

/** The official guard's user: the JSON in the `x-user` header, a guest without it. */
export function userFromHeader(ctx: ExecutionContext): unknown {
  if (ctx.getType() !== 'http') return undefined;
  const raw = ctx.switchToHttp().getRequest<{ headers: Record<string, string> }>().headers[
    'x-user'
  ];
  return raw ? JSON.parse(raw) : undefined;
}

export const asUser = (user: object) => ({ 'x-user': JSON.stringify(user) });

export interface BootOptions {
  controllers?: Type<unknown>[];
  providers?: Provider[];
  authz?: AuthzModuleOptions;
  permissions?: PermissionProvider;
  roles?: RoleProvider;
}

/** A tiny in-memory permission seam: `{ userId: grants }`, listed so wildcards apply. */
export function permissionTable(table: Record<string, string[]>) {
  const calls = { getPermissions: 0 };
  const provider: PermissionProvider = {
    hasPermission: (user, permission) =>
      table[String((user as { id?: unknown })?.id)]?.includes(permission) ?? false,
    getPermissions: (user) => {
      calls.getPermissions++;
      return table[String((user as { id?: unknown })?.id)];
    },
  };
  return { provider, calls };
}

export function roleTable(table: Record<string, string[]>): RoleProvider {
  return { getRoles: (user) => table[String((user as { id?: unknown })?.id)] };
}

function moduleFor(options: BootOptions) {
  return Test.createTestingModule({
    imports: [
      AuthorizationModule.forRoot({ getUser: userFromHeader }),
      AuthzModule.forRoot(options.authz ?? {}),
    ],
    controllers: options.controllers ?? [],
    providers: [
      ...(options.providers ?? []),
      ...(options.permissions
        ? [{ provide: PERMISSION_PROVIDER, useValue: options.permissions }]
        : []),
      ...(options.roles ? [{ provide: ROLE_PROVIDER, useValue: options.roles }] : []),
    ],
  });
}

/** An HTTP app with the official module and the extras. */
export async function bootApp(
  options: BootOptions = {},
): Promise<{ app: INestApplication; gate: Gate }> {
  const mod = await moduleFor(options).compile();
  const app = mod.createNestApplication({ logger: false });
  await app.init();
  return { app, gate: app.get(Gate) };
}

/** An application context (no HTTP), for service-layer checks. */
export async function bootContext(
  options: BootOptions = {},
): Promise<{ mod: TestingModule; gate: Gate }> {
  const mod = await moduleFor(options).compile();
  mod.useLogger(false);
  await mod.init();
  return { mod, gate: mod.get(Gate) };
}
