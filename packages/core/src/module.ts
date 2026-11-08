import {
  AUTHORIZATION_MODULE_OPTIONS,
  type AuthorizationModuleOptions,
  defaultGetUser,
} from '@nestjs/authorization';
import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnModuleInit,
  Optional,
  type Provider,
  type Type,
} from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR, DiscoveryModule } from '@nestjs/core';
import { AuthzGuard, AuthzGuardStartupCheck } from './authz.guard.js';
import { DEFAULT_CAN_ENDPOINT_PATH, createCanController } from './can-endpoint.controller.js';
import { AuthzDecisionPublisher } from './decisions.js';
import { Gate } from './gate.js';
import { OFFICIAL_CAN_ANYONE_METADATA } from './official.js';
import { GatePolicy } from './policies/gate.policy.js';
import { PermissionPolicy } from './policies/permission.policy.js';
import { RolePolicy } from './policies/role.policy.js';
import { PolicyIndex } from './policy-index.js';
import { AuthzRbac } from './rbac.js';
import { IdParamResourceResolver, type ResourceResolver } from './resource-resolver.js';
import { configureAuthzRuntime } from './runtime.js';
import { AUTHZ_MODULE_OPTIONS, RESOURCE_HYDRATOR, RESOURCE_RESOLVER } from './tokens.js';
import type {
  AuthzModuleAsyncOptions,
  AuthzModuleOptions,
  AuthzModuleOptionsFactory,
  AuthzModuleStaticOptions,
  ResourceLoaderMap,
} from './types.js';

/**
 * Hands the official `@Can()` argument resolvers and `AuthzPolicy` what they cannot
 * inject: the resource resolver, the `superAdmin` hook, the external decision point,
 * and the official `getUser`.
 */
@Injectable()
class AuthzRuntimeBootstrap implements OnModuleInit {
  constructor(
    @Inject(RESOURCE_RESOLVER) private readonly resolver: ResourceResolver,
    private readonly rbac: AuthzRbac,
    @Optional() @Inject(AUTHZ_MODULE_OPTIONS) private readonly options?: AuthzModuleOptions,
    @Optional()
    @Inject(AUTHORIZATION_MODULE_OPTIONS)
    private readonly official?: AuthorizationModuleOptions,
  ) {}

  onModuleInit(): void {
    configureAuthzRuntime({
      resourceResolver: this.resolver,
      superAdmin: this.options?.superAdmin,
      decisionProvider: () => this.rbac.decisions(),
      // Always set: an app without its own `getUser` must not keep a previous app's.
      getUser: this.official?.getUser ?? defaultGetUser,
    });
  }
}

/** The static options, which a `forRootAsync()` factory returning them would silently drop. */
const STATIC_OPTIONS = ['unannotated', 'decorators'] as const;

function checkFactoryOptions(options: AuthzModuleOptions): AuthzModuleOptions {
  for (const key of STATIC_OPTIONS) {
    if (options?.[key] !== undefined) {
      throw new Error(
        `AuthzModule: \`${key}\` is in the options the forRootAsync() factory returned. It goes at the top level of forRootAsync(), next to useFactory, because it decides what the module registers.`,
      );
    }
  }
  return options;
}

const EXPORTS = [
  Gate,
  AuthzGuard,
  PolicyIndex,
  AuthzRbac,
  RolePolicy,
  PermissionPolicy,
  GatePolicy,
  AUTHZ_MODULE_OPTIONS,
  RESOURCE_RESOLVER,
  RESOURCE_HYDRATOR,
];

/**
 * The extras on top of `@nestjs/authorization`. Import it next to the official module:
 *
 * ```ts
 * imports: [
 *   AuthorizationModule.forRoot(),            // the official guard, @Can, AuthorizationService
 *   AuthzModule.forRoot({ superAdmin: (u) => u?.isRoot === true }),
 * ]
 * ```
 *
 * Registers `RolePolicy`, `PermissionPolicy` and `GatePolicy` (official policies), the
 * `Gate`, the resource resolver `byId()` uses, and the allow+deny decision event.
 * It needs the official module to be global (its default).
 */
@Module({})
export class AuthzModule {
  static forRoot(options: AuthzModuleOptions = {}): DynamicModule {
    return {
      module: AuthzModule,
      global: true,
      imports: [DiscoveryModule],
      controllers: AuthzModule.controllers(options),
      providers: [
        { provide: AUTHZ_MODULE_OPTIONS, useValue: options },
        ...AuthzModule.common(),
        ...AuthzModule.guards(options),
      ],
      exports: EXPORTS,
    };
  }

  static forRootAsync(options: AuthzModuleAsyncOptions): DynamicModule {
    return {
      module: AuthzModule,
      global: true,
      imports: [DiscoveryModule, ...((options.imports ?? []) as DynamicModule[])],
      controllers: AuthzModule.controllers(options),
      providers: [
        ...AuthzModule.asyncOptionsProviders(options),
        ...AuthzModule.common(),
        ...AuthzModule.guards(options),
      ],
      exports: EXPORTS,
    };
  }

  private static common(): Provider[] {
    return [
      PolicyIndex,
      AuthzRbac,
      Gate,
      RolePolicy,
      PermissionPolicy,
      GatePolicy,
      {
        provide: RESOURCE_RESOLVER,
        useFactory: (options?: AuthzModuleOptions): ResourceResolver =>
          options?.resourceResolver ?? new IdParamResourceResolver(options?.idParam),
        inject: [{ token: AUTHZ_MODULE_OPTIONS, optional: true }],
      },
      {
        provide: RESOURCE_HYDRATOR,
        useFactory: (options?: AuthzModuleOptions): ResourceLoaderMap | undefined =>
          options?.resourceLoaders,
        inject: [{ token: AUTHZ_MODULE_OPTIONS, optional: true }],
      },
      AuthzGuard,
      AuthzRuntimeBootstrap,
      AuthzDecisionPublisher,
      { provide: APP_INTERCEPTOR, useExisting: AuthzDecisionPublisher },
    ];
  }

  /**
   * `unannotated: 'allow'`: the migration guard, registered globally, and the check that the
   * official global guard is off. Static, so it is read from `forRoot()` / the top level of
   * `forRootAsync()`, never from the factory.
   */
  private static guards(options: AuthzModuleStaticOptions): Provider[] {
    const mode = options.unannotated ?? 'deny';
    if (mode !== 'allow' && mode !== 'deny') {
      throw new Error(
        `AuthzModule: \`unannotated\` must be 'allow' or 'deny', got ${String(mode)}.`,
      );
    }
    if (mode === 'deny') return [];
    return [AuthzGuardStartupCheck, { provide: APP_GUARD, useExisting: AuthzGuard }];
  }

  /**
   * The controllers this module mounts, each a fresh class (so `decorators` never leak between
   * registrations), open to the official guard, then decorated with `decorators`.
   */
  private static controllers(options: AuthzModuleStaticOptions): Type<unknown>[] {
    const { canEndpoint, decorators = [] } = options;
    if (!canEndpoint) return [];
    const path = typeof canEndpoint === 'string' ? canEndpoint : DEFAULT_CAN_ENDPOINT_PATH;
    const controller = createCanController(path);
    Reflect.defineMetadata(OFFICIAL_CAN_ANYONE_METADATA, true, controller);
    // Applied in order, after the module's own, like a stack written above the class.
    for (const decorate of [...decorators].reverse()) {
      decorate(controller);
    }
    return [controller];
  }

  private static asyncOptionsProviders(options: AuthzModuleAsyncOptions): Provider[] {
    const { useFactory } = options;
    if (useFactory) {
      return [
        {
          provide: AUTHZ_MODULE_OPTIONS,
          useFactory: async (...args: unknown[]) => checkFactoryOptions(await useFactory(...args)),
          inject: (options.inject ?? []) as Array<Type<unknown>>,
        },
      ];
    }
    const factory = (options.useClass ?? options.useExisting) as Type<AuthzModuleOptionsFactory>;
    return [
      ...(options.useClass ? [{ provide: options.useClass, useClass: options.useClass }] : []),
      {
        provide: AUTHZ_MODULE_OPTIONS,
        useFactory: async (f: AuthzModuleOptionsFactory) =>
          checkFactoryOptions(await f.createAuthzOptions()),
        inject: [factory],
      },
    ];
  }
}
