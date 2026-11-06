import {
  AUTHORIZATION_MODULE_OPTIONS,
  type AuthorizationModuleOptions,
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
import { APP_INTERCEPTOR, DiscoveryModule } from '@nestjs/core';
import { DEFAULT_CAN_ENDPOINT_PATH, createCanController } from './can-endpoint.controller.js';
import { AuthzDecisionPublisher } from './decisions.js';
import { Gate } from './gate.js';
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
      ...(this.official?.getUser ? { getUser: this.official.getUser } : {}),
    });
  }
}

const EXPORTS = [
  Gate,
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
      controllers: AuthzModule.canControllers(options.canEndpoint),
      providers: [{ provide: AUTHZ_MODULE_OPTIONS, useValue: options }, ...AuthzModule.common()],
      exports: EXPORTS,
    };
  }

  static forRootAsync(options: AuthzModuleAsyncOptions): DynamicModule {
    return {
      module: AuthzModule,
      global: true,
      imports: [DiscoveryModule, ...((options.imports ?? []) as DynamicModule[])],
      controllers: AuthzModule.canControllers(options.canEndpoint),
      providers: [...AuthzModule.asyncOptionsProviders(options), ...AuthzModule.common()],
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
      AuthzRuntimeBootstrap,
      AuthzDecisionPublisher,
      { provide: APP_INTERCEPTOR, useExisting: AuthzDecisionPublisher },
    ];
  }

  private static canControllers(canEndpoint: boolean | string | undefined): Type<unknown>[] {
    if (!canEndpoint) return [];
    const path = typeof canEndpoint === 'string' ? canEndpoint : DEFAULT_CAN_ENDPOINT_PATH;
    return [createCanController(path)];
  }

  private static asyncOptionsProviders(options: AuthzModuleAsyncOptions): Provider[] {
    if (options.useFactory) {
      return [
        {
          provide: AUTHZ_MODULE_OPTIONS,
          useFactory: options.useFactory,
          inject: (options.inject ?? []) as Array<Type<unknown>>,
        },
      ];
    }
    const factory = (options.useClass ?? options.useExisting) as Type<AuthzModuleOptionsFactory>;
    return [
      ...(options.useClass ? [{ provide: options.useClass, useClass: options.useClass }] : []),
      {
        provide: AUTHZ_MODULE_OPTIONS,
        useFactory: async (f: AuthzModuleOptionsFactory) => f.createAuthzOptions(),
        inject: [factory],
      },
    ];
  }
}
