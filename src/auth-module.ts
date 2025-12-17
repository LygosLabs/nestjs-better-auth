import { Inject, Logger, Module } from "@nestjs/common";
import type {
  DynamicModule,
  FactoryProvider,
  MiddlewareConsumer,
  ModuleMetadata,
  NestModule,
  OnModuleInit,
  Provider,
  Type,
} from "@nestjs/common";
import {
  APP_FILTER,
  DiscoveryModule,
  DiscoveryService,
  HttpAdapterHost,
  MetadataScanner,
} from "@nestjs/core";
import type { Auth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import { createAuthMiddleware } from "better-auth/plugins";
import type { Request, Response } from "express";
import { APIErrorExceptionFilter } from "./api-error-exception-filter";
import { AuthService } from "./auth-service";
import { SkipBodyParsingMiddleware } from "./middlewares";
import {
  AFTER_HOOK_KEY,
  AUTH_INSTANCE_KEY,
  AUTH_MODULE_OPTIONS_KEY,
  BEFORE_HOOK_KEY,
  HOOK_KEY,
} from "./symbols";

/**
 * Configuration options for the AuthModule
 */
export type AuthModuleOptions = {
  disableExceptionFilter?: boolean;
  disableTrustedOriginsCors?: boolean;
  disableBodyParser?: boolean;
};

/**
 * Interface for async configuration of AuthModule
 */
export interface AuthModuleAsyncOptions
  extends Pick<ModuleMetadata, "imports"> {
  /**
   * Factory function that returns the auth instance
   */
  useFactory: (...args: any[]) => Promise<any> | any;
  /**
   * Dependencies to inject into the factory function
   */
  inject?: any[];
  /**
   * Configuration options for the module
   */
  options?: AuthModuleOptions;
}

/**
 * Alternative interface for class-based async configuration
 */
export interface AuthModuleOptionsFactory {
  createAuthModuleOptions():
    | Promise<{ auth: any; options?: AuthModuleOptions }>
    | { auth: any; options?: AuthModuleOptions };
}

/**
 * Interface for class-based async configuration
 */
export interface AuthModuleAsyncOptionsWithClass
  extends Pick<ModuleMetadata, "imports"> {
  /**
   * Class that implements AuthModuleOptionsFactory
   */
  useClass: Type<AuthModuleOptionsFactory>;
  /**
   * Dependencies to inject
   */
  inject?: any[];
}

/**
 * Union type for all async configuration options
 */
export type AuthModuleAsyncConfig =
  | AuthModuleAsyncOptions
  | AuthModuleAsyncOptionsWithClass;

const HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" as const },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" as const },
];

/**
 * NestJS module that integrates the Auth library with NestJS applications.
 * Provides authentication middleware, hooks, and exception handling.
 */
@Module({
  imports: [DiscoveryModule],
})
export class AuthModule implements NestModule, OnModuleInit {
  private readonly logger = new Logger(AuthModule.name);
  constructor(
    @Inject(AUTH_INSTANCE_KEY) private readonly auth: Auth,
    @Inject(DiscoveryService)
    private readonly discoveryService: DiscoveryService,
    @Inject(MetadataScanner)
    private readonly metadataScanner: MetadataScanner,
    @Inject(HttpAdapterHost)
    private readonly adapter: HttpAdapterHost,
    @Inject(AUTH_MODULE_OPTIONS_KEY)
    private readonly options: AuthModuleOptions
  ) {}

  onModuleInit(): void {
    // Setup hooks
    if (!this.auth.options.hooks) return;

    const providers = this.discoveryService
      .getProviders()
      .filter(
        ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype)
      );

    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);

      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        this.setupHooks(providerMethod, provider.instance);
      }
    }
  }

  configure(consumer: MiddlewareConsumer): void {
    const trustedOrigins = this.auth.options.trustedOrigins;
    // function-based trustedOrigins requires a Request (from web-apis) object to evaluate, which is not available in NestJS (we only have a express Request object)
    // if we ever need this, take a look at better-call which show an implementation for this
    const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);

    if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
      });
    } else if (
      trustedOrigins &&
      !this.options.disableTrustedOriginsCors &&
      !isNotFunctionBased
    )
      throw new Error(
        "Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true."
      );

    if (!this.options.disableBodyParser)
      consumer.apply(SkipBodyParsingMiddleware).forRoutes("*path");

    // Get basePath from options or use default
    let basePath = this.auth.options.basePath ?? "/api/auth";

    // Ensure basePath starts with /
    if (!basePath.startsWith("/")) {
      basePath = `/${basePath}`;
    }

    // Ensure basePath doesn't end with /
    if (basePath.endsWith("/")) {
      basePath = basePath.slice(0, -1);
    }

    const handler = toNodeHandler(this.auth);
    this.adapter.httpAdapter
      .getInstance()
      // little hack to ignore any global prefix
      // for now i'll just not support a global prefix
      .use(basePath, (req: Request, res: Response) => {
        req.url = req.originalUrl;

        return handler(req, res);
      });
    this.logger.log(`AuthModule initialized BetterAuth on '${basePath}/*'`);
  }

  private setupHooks(
    providerMethod: (...args: unknown[]) => unknown,
    providerClass: { new (...args: unknown[]): unknown }
  ) {
    if (!this.auth.options.hooks) return;

    for (const { metadataKey, hookType } of HOOKS) {
      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);
      if (!hookPath) continue;

      const originalHook = this.auth.options.hooks[hookType];
      this.auth.options.hooks[hookType] = createAuthMiddleware(async (ctx) => {
        if (originalHook) {
          await originalHook(ctx);
        }

        if (hookPath === ctx.path) {
          await providerMethod.apply(providerClass, [ctx]);
        }
      });
    }
  }

  /**
   * Static factory method to create and configure the AuthModule.
   * @param auth - The Auth instance to use
   * @param options - Configuration options for the module
   */
  static forRoot(
    // biome-ignore lint/suspicious/noExplicitAny: i still need to find a type for the auth instance
    auth: any,
    options: AuthModuleOptions = {}
  ): DynamicModule {
    // Initialize hooks with an empty object if undefined
    // Without this initialization, the setupHook method won't be able to properly override hooks
    // It won't throw an error, but any hook functions we try to add won't be called
    auth.options.hooks = {
      ...auth.options.hooks,
    };

    const providers: Provider[] = [
      {
        provide: AUTH_INSTANCE_KEY,
        useValue: auth,
      },
      {
        provide: AUTH_MODULE_OPTIONS_KEY,
        useValue: options,
      },
      AuthService,
    ];

    if (!options.disableExceptionFilter) {
      providers.push({
        provide: APP_FILTER,
        useClass: APIErrorExceptionFilter,
      });
    }

    return {
      global: true,
      module: AuthModule,
      providers: providers,
      exports: [
        {
          provide: AUTH_INSTANCE_KEY,
          useValue: auth,
        },
        {
          provide: AUTH_MODULE_OPTIONS_KEY,
          useValue: options,
        },
        AuthService,
      ],
    };
  }

  /**
   * Static factory method to create and configure the AuthModule asynchronously.
   * Useful when you need to inject dependencies or fetch configuration from external sources.
   * @param asyncOptions - Async configuration options
   */
  static forRootAsync(asyncOptions: AuthModuleAsyncConfig): DynamicModule {
    const providers = this.createAsyncProviders(asyncOptions);

    return {
      global: true,
      module: AuthModule,
      imports: asyncOptions.imports || [],
      providers: [...providers, AuthService],
      exports: [AUTH_INSTANCE_KEY, AUTH_MODULE_OPTIONS_KEY, AuthService],
    };
  }

  /**
   * Creates the async providers for the AuthModule
   */
  private static createAsyncProviders(
    options: AuthModuleAsyncConfig
  ): Provider[] {
    const providers: Provider[] = [];

    if ("useFactory" in options) {
      // Factory-based configuration
      const authProvider: FactoryProvider = {
        provide: AUTH_INSTANCE_KEY,
        useFactory: async (...args: any[]) => {
          const auth = await options.useFactory(...args);
          // Initialize hooks with an empty object if undefined
          // Without this initialization, the setupHook method won't be able to properly override hooks
          // It won't throw an error, but any hook functions we try to add won't be called
          auth.options.hooks = {
            ...auth.options.hooks,
          };
          return auth;
        },
        inject: options.inject || [],
      };

      const optionsProvider: Provider = {
        provide: AUTH_MODULE_OPTIONS_KEY,
        useValue: options.options || {},
      };

      providers.push(authProvider, optionsProvider);

      // Add exception filter if not disabled
      if (!options.options?.disableExceptionFilter) {
        providers.push({
          provide: APP_FILTER,
          useClass: APIErrorExceptionFilter,
        });
      }
    } else if ("useClass" in options) {
      // Class-based configuration
      const factoryProvider: FactoryProvider = {
        provide: AUTH_INSTANCE_KEY,
        useFactory: async (optionsFactory: AuthModuleOptionsFactory) => {
          const config = await optionsFactory.createAuthModuleOptions();
          // Initialize hooks with an empty object if undefined
          config.auth.options.hooks = {
            ...config.auth.options.hooks,
          };
          return config.auth;
        },
        inject: [options.useClass],
      };

      const optionsFactoryProvider: FactoryProvider = {
        provide: AUTH_MODULE_OPTIONS_KEY,
        useFactory: async (optionsFactory: AuthModuleOptionsFactory) => {
          const config = await optionsFactory.createAuthModuleOptions();
          return config.options || {};
        },
        inject: [options.useClass],
      };

      const classProvider: Provider = {
        provide: options.useClass,
        useClass: options.useClass,
      };

      providers.push(factoryProvider, optionsFactoryProvider, classProvider);

      // For class-based config, we'll add the exception filter by default
      // Users can still disable it by returning disableExceptionFilter: true in their factory
      // This is simpler than trying to conditionally register providers
      providers.push({
        provide: APP_FILTER,
        useClass: APIErrorExceptionFilter,
      });
    }

    return providers;
  }
}
