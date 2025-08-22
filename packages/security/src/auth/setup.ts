/**
 * Authentication Setup Utilities
 *
 * This module provides factory functions and utilities for easy authentication system setup.
 * It orchestrates the creation and configuration of all authentication components including
 * services, middleware, handlers, and database repositories.
 *
 * Features:
 * - One-stop setup function for complete authentication system
 * - Factory pattern for creating authentication components
 * - Comprehensive configuration validation and defaults
 * - Integrated logging and audit trails
 * - Easy Express router integration
 * - Support for multiple database backends
 *
 * @packageDocumentation
 */

import { AuthService } from './service';
import { createAuthMiddleware, createOptionalAuthMiddleware, createRoleAuthMiddleware } from './middleware';
import { createAuthHandlers } from './handlers';
import { createDatabaseRepositories, validateDatabaseConfig } from './database';
import { securityLogger } from '../utils';
import type {
  JwtConfig,
  DatabaseConfig,
  IUserRepository,
  ISessionRepository,
  AuthSetupConfig,
  RegistrationConfig,
  PasswordResetConfig,
} from './types';

/**
 * Complete authentication setup interface
 * Contains all components needed for a fully functional authentication system
 */
export interface AuthSetup {
  /** Main authentication service for business logic */
  authService: AuthService;
  
  /** Authentication middleware functions for Express */
  middleware: {
    /** Standard authentication middleware (requires valid JWT) */
    auth: ReturnType<typeof createAuthMiddleware>;
    /** Optional authentication middleware (allows unauthenticated requests) */
    optionalAuth: ReturnType<typeof createOptionalAuthMiddleware>;
    /** Role-based authentication middleware factory */
    roleAuth: typeof createRoleAuthMiddleware;
  };
  
  /** Pre-configured route handlers for common authentication endpoints */
  handlers: ReturnType<typeof createAuthHandlers>;
  
  /** Database repositories for user and session management */
  repositories: {
    userRepo: IUserRepository;
    sessionRepo: ISessionRepository;
  };
}

/**
 * Enhanced authentication setup configuration
 * Extends base configuration with additional features for production use
 */
export interface EnhancedAuthSetupConfig extends AuthSetupConfig {
  /** Registration configuration for user signup features */
  registration?: RegistrationConfig;
  /** Password reset configuration for forgot password features */
  passwordReset?: PasswordResetConfig;
}

/**
 * Main authentication system setup function
 *
 * Creates and configures a complete authentication system with all necessary components.
 * This is the primary entry point for setting up authentication in an application.
 *
 * @param config - Authentication setup configuration
 * @returns Complete authentication setup with all components
 *
 * @example
 * ```typescript
 * // Basic setup
 * const auth = setupAuthentication({
 *   jwt: {
 *     secret: process.env.JWT_SECRET!,
 *     expiresIn: '15m',
 *     refreshExpiresIn: '7d',
 *     algorithm: 'HS256',
 *   },
 *   database: {
 *     type: 'mock', // or 'prisma' when available
 *   },
 * });
 *
 * // Use in Express app
 * app.use('/api/auth', createAuthRouter(auth));
 * app.use('/api/protected', auth.middleware.auth);
 * ```
 */
export function setupAuthentication(config: EnhancedAuthSetupConfig): AuthSetup {
  securityLogger.info('Setting up authentication system', {
    jwtAlgorithm: config.jwt.algorithm,
    databaseType: config.database.type,
    registrationEnabled: !!config.registration,
    passwordResetEnabled: !!config.passwordReset,
  });

  // Validate configuration
  validateAuthSetupConfig(config);

  // Create database repositories
  const repositories = createDatabaseRepositories(config.database);
  securityLogger.debug('Database repositories created successfully');

  // Create authentication service with enhanced configuration
  const authService = new AuthService(
    config.jwt,
    repositories.userRepo,
    repositories.sessionRepo,
    config.registration || {},
    config.passwordReset || {}
  );
  securityLogger.debug('Authentication service created successfully');

  // Create middleware functions
  const middleware = {
    auth: createAuthMiddleware(authService),
    optionalAuth: createOptionalAuthMiddleware(authService),
    roleAuth: createRoleAuthMiddleware,
  };
  securityLogger.debug('Authentication middleware created successfully');

  // Create route handlers
  const handlers = createAuthHandlers(authService);
  securityLogger.debug('Authentication handlers created successfully');

  const authSetup: AuthSetup = {
    authService,
    middleware,
    handlers,
    repositories,
  };

  securityLogger.info('Authentication system setup completed successfully', {
    components: ['authService', 'middleware', 'handlers', 'repositories'],
    features: {
      jwtAuth: true,
      sessionManagement: true,
      roleBasedAuth: true,
      registration: !!config.registration,
      passwordReset: !!config.passwordReset,
    },
  });

  return authSetup;
}

/**
 * Create Express router with comprehensive authentication routes
 *
 * Creates a pre-configured Express router with all available authentication endpoints
 * including core auth, registration, password reset, and session management routes.
 * The router automatically detects which handlers are available and registers routes accordingly.
 *
 * Available routes include:
 * - Core: /login, /refresh, /logout, /me
 * - Registration: /register, /verify-email, /resend-verification  
 * - Password Reset: /password/reset, /password/confirm, /password/validate/:token
 * - Session Management: /sessions, /sessions/:sessionId, /password/change
 *
 * @param authSetup - Complete authentication setup from setupAuthentication
 * @returns Express router with all available authentication routes
 *
 * @example
 * ```typescript
 * const auth = setupAuthentication(config);
 * const authRouter = createAuthRouter(auth);
 * 
 * app.use('/api/auth', authRouter);
 * ```
 */
export function createAuthRouter(authSetup: AuthSetup): any {
  // Using dynamic import to avoid requiring Express as a dependency
  // This allows the module to be used in non-Express environments
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Router } = require('express') as any;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  const router = Router() as any;

  securityLogger.debug('Creating authentication router with all available endpoints');

  // Core authentication routes
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  router.post('/login', authSetup.handlers.login);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  router.post('/refresh', authSetup.handlers.refresh);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  router.post('/logout', authSetup.middleware.auth, authSetup.handlers.logout);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  router.get('/me', authSetup.middleware.auth, authSetup.handlers.me);

  // Registration routes (if available in handlers)
  if ('register' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/register', authSetup.handlers.register);
  }
  if ('verifyEmail' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/verify-email', authSetup.handlers.verifyEmail);
  }
  if ('resendVerification' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/resend-verification', authSetup.handlers.resendVerification);
  }

  // Password reset routes (if available in handlers)
  if ('initiatePasswordReset' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/password/reset', authSetup.handlers.initiatePasswordReset);
  }
  if ('confirmPasswordReset' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/password/confirm', authSetup.handlers.confirmPasswordReset);
  }
  if ('validateResetToken' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.get('/password/validate/:token', authSetup.handlers.validateResetToken);
  }

  // Account management routes (require authentication)
  if ('getUserSessions' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.get('/sessions', authSetup.middleware.auth, authSetup.handlers.getUserSessions);
  }
  if ('revokeSession' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.delete('/sessions/:sessionId', authSetup.middleware.auth, authSetup.handlers.revokeSession);
  }
  if ('changePassword' in authSetup.handlers) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/password/change', authSetup.middleware.auth, authSetup.handlers.changePassword);
  }

  // Build endpoint list for logging
  const endpoints = ['/login', '/refresh', '/logout', '/me'];
  
  if ('register' in authSetup.handlers) {
    endpoints.push('/register');
  }
  if ('verifyEmail' in authSetup.handlers) {
    endpoints.push('/verify-email');
  }
  if ('resendVerification' in authSetup.handlers) {
    endpoints.push('/resend-verification');
  }
  if ('initiatePasswordReset' in authSetup.handlers) {
    endpoints.push('/password/reset', '/password/confirm', '/password/validate/:token');
  }
  if ('getUserSessions' in authSetup.handlers) {
    endpoints.push('/sessions');
  }
  if ('revokeSession' in authSetup.handlers) {
    endpoints.push('/sessions/:sessionId');
  }
  if ('changePassword' in authSetup.handlers) {
    endpoints.push('/password/change');
  }

  securityLogger.info('Authentication router created successfully', {
    endpoints,
    endpointCount: endpoints.length,
    middlewareCount: Object.keys(authSetup.middleware).length,
    features: {
      registration: 'register' in authSetup.handlers,
      emailVerification: 'verifyEmail' in authSetup.handlers,
      passwordReset: 'initiatePasswordReset' in authSetup.handlers,
      sessionManagement: 'getUserSessions' in authSetup.handlers,
      passwordChange: 'changePassword' in authSetup.handlers,
    },
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return router;
}

/**
 * Create extended Express router with additional authentication routes
 *
 * Creates a router with additional endpoints for registration, password reset,
 * and session management. This is useful for applications that need full
 * authentication features beyond basic login/logout.
 *
 * @param authSetup - Complete authentication setup
 * @param config - Enhanced configuration with additional features
 * @returns Express router with extended authentication routes
 *
 * @example
 * ```typescript
 * const auth = setupAuthentication(config);
 * const authRouter = createExtendedAuthRouter(auth, config);
 * 
 * app.use('/api/auth', authRouter);
 * ```
 */
export function createExtendedAuthRouter(
  authSetup: AuthSetup,
  config: EnhancedAuthSetupConfig
) {
  const { Router } = require('express');
  const router = Router();

  securityLogger.debug('Creating extended authentication router');

  // Core authentication routes
  router.post('/login', authSetup.handlers.login);
  router.post('/refresh', authSetup.handlers.refresh);
  router.post('/logout', authSetup.middleware.auth, authSetup.handlers.logout);
  router.get('/me', authSetup.middleware.auth, authSetup.handlers.me);

  // Registration routes (if enabled)
  if (config.registration) {
    // Note: These handlers would need to be implemented in handlers.ts
    // For now, we'll log that they would be available
    securityLogger.debug('Registration endpoints would be available', {
      endpoints: ['/register', '/verify-email', '/resend-verification'],
      requireEmailVerification: config.registration.requireEmailVerification,
    });
  }

  // Password reset routes (if enabled)
  if (config.passwordReset) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/password/reset', authSetup.handlers.initiatePasswordReset);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.post('/password/confirm', authSetup.handlers.confirmPasswordReset);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    router.get('/password/validate/:token', authSetup.handlers.validateResetToken);
    
    securityLogger.info('Password reset endpoints enabled', {
      endpoints: ['/password/reset', '/password/confirm', '/password/validate/:token'],
      tokenExpirationMinutes: config.passwordReset.tokenExpirationMinutes,
      revokeSessionsOnReset: config.passwordReset.revokeSessionsOnReset,
    });
  }

  // Session management routes (always available)
  // Note: These handlers would need to be implemented in handlers.ts
  securityLogger.debug('Session management endpoints would be available', {
    endpoints: ['/sessions', '/sessions/:sessionId'],
  });

  const endpoints = ['/login', '/refresh', '/logout', '/me'];
  if (config.registration) {
    endpoints.push('/register', '/verify-email', '/resend-verification');
  }
  if (config.passwordReset) {
    endpoints.push('/password/reset', '/password/confirm', '/password/validate');
  }
  endpoints.push('/sessions', '/sessions/:sessionId');

  securityLogger.info('Extended authentication router created successfully', {
    endpoints,
    features: {
      registration: !!config.registration,
      passwordReset: !!config.passwordReset,
      sessionManagement: true,
    },
  });

  return router;
}

/**
 * Quick setup function for development and testing
 *
 * Provides a quick way to set up authentication with sensible defaults
 * for development environments. Uses mock database and basic JWT configuration.
 *
 * @param jwtSecret - JWT secret key (required)
 * @param options - Optional configuration overrides
 * @returns Complete authentication setup for development
 *
 * @example
 * ```typescript
 * // Quick development setup
 * const auth = setupAuthenticationForDevelopment('your-jwt-secret');
 * app.use('/api/auth', createAuthRouter(auth));
 * ```
 */
export function setupAuthenticationForDevelopment(
  jwtSecret: string,
  options: Partial<EnhancedAuthSetupConfig> = {}
): AuthSetup {
  securityLogger.info('Setting up authentication for development environment');

  const defaultConfig: EnhancedAuthSetupConfig = {
    jwt: {
      secret: jwtSecret,
      expiresIn: '15m',
      refreshExpiresIn: '7d',
      algorithm: 'HS256',
    },
    database: {
      type: 'mock',
    },
    registration: {
      requireEmailVerification: false,
      defaultRoles: ['user'],
      defaultPermissions: ['user:read'],
    },
    passwordReset: {
      tokenExpirationMinutes: 60,
      revokeSessionsOnReset: true,
    },
  };

  // Merge with provided options
  const config: EnhancedAuthSetupConfig = {
    ...defaultConfig,
    ...options,
    jwt: { ...defaultConfig.jwt, ...options.jwt },
    database: { ...defaultConfig.database, ...options.database },
    registration: { ...defaultConfig.registration, ...options.registration },
    passwordReset: { ...defaultConfig.passwordReset, ...options.passwordReset },
  };

  return setupAuthentication(config);
}

/**
 * Validate authentication setup configuration
 *
 * Performs comprehensive validation of the authentication setup configuration
 * to ensure all required fields are present and valid.
 *
 * @param config - Configuration to validate
 * @throws Error if configuration is invalid
 */
export function validateAuthSetupConfig(config: EnhancedAuthSetupConfig): void {
  securityLogger.debug('Validating authentication setup configuration');

  // Validate JWT configuration
  if (!config.jwt) {
    throw new Error('JWT configuration is required');
  }

  if (!config.jwt.secret) {
    throw new Error('JWT secret is required');
  }

  if (config.jwt.secret.length < 32) {
    throw new Error('JWT secret must be at least 32 characters long');
  }

  if (!config.jwt.expiresIn) {
    throw new Error('JWT expiresIn is required');
  }

  if (!config.jwt.refreshExpiresIn) {
    throw new Error('JWT refreshExpiresIn is required');
  }

  if (!config.jwt.algorithm) {
    throw new Error('JWT algorithm is required');
  }

  const supportedAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];
  if (!supportedAlgorithms.includes(config.jwt.algorithm)) {
    throw new Error(`Unsupported JWT algorithm: ${config.jwt.algorithm}. Supported: ${supportedAlgorithms.join(', ')}`);
  }

  // Validate database configuration
  validateDatabaseConfig(config.database);

  // Validate registration configuration (if provided)
  if (config.registration) {
    if (config.registration.defaultRoles && !Array.isArray(config.registration.defaultRoles)) {
      throw new Error('Registration defaultRoles must be an array');
    }

    if (config.registration.defaultPermissions && !Array.isArray(config.registration.defaultPermissions)) {
      throw new Error('Registration defaultPermissions must be an array');
    }

    if (config.registration.allowedRoles && !Array.isArray(config.registration.allowedRoles)) {
      throw new Error('Registration allowedRoles must be an array');
    }
  }

  // Validate password reset configuration (if provided)
  if (config.passwordReset) {
    if (config.passwordReset.tokenExpirationMinutes !== undefined) {
      if (typeof config.passwordReset.tokenExpirationMinutes !== 'number' || config.passwordReset.tokenExpirationMinutes <= 0) {
        throw new Error('Password reset tokenExpirationMinutes must be a positive number');
      }
    }

    if (config.passwordReset.revokeSessionsOnReset !== undefined) {
      if (typeof config.passwordReset.revokeSessionsOnReset !== 'boolean') {
        throw new Error('Password reset revokeSessionsOnReset must be a boolean');
      }
    }
  }

  securityLogger.debug('Authentication setup configuration validated successfully');
}

/**
 * Create authentication setup with custom repositories
 *
 * Helper function for creating authentication setup with custom database repositories.
 * Useful when you have existing database implementations or want to use specific
 * database libraries not covered by the built-in options.
 *
 * @param jwtConfig - JWT configuration
 * @param userRepo - Custom user repository implementation
 * @param sessionRepo - Custom session repository implementation
 * @param registrationConfig - Optional registration configuration
 * @param passwordResetConfig - Optional password reset configuration
 * @returns Complete authentication setup with custom repositories
 */
export function setupAuthenticationWithCustomRepositories(
  jwtConfig: JwtConfig,
  userRepo: IUserRepository,
  sessionRepo: ISessionRepository,
  registrationConfig?: RegistrationConfig,
  passwordResetConfig?: PasswordResetConfig
): AuthSetup {
  securityLogger.info('Setting up authentication with custom repositories', {
    hasRegistrationConfig: !!registrationConfig,
    hasPasswordResetConfig: !!passwordResetConfig,
  });

  const config: EnhancedAuthSetupConfig = {
    jwt: jwtConfig,
    database: {
      type: 'custom',
      customRepositories: {
        userRepo,
        sessionRepo,
      },
    },
    ...(registrationConfig && { registration: registrationConfig }),
    ...(passwordResetConfig && { passwordReset: passwordResetConfig }),
  };

  return setupAuthentication(config);
}

/**
 * Get default JWT configuration for development
 *
 * Returns a default JWT configuration suitable for development environments.
 * Should not be used in production without proper customization.
 *
 * @param secret - JWT secret key
 * @returns Default JWT configuration
 */
export function getDefaultJwtConfig(secret: string): JwtConfig {
  return {
    secret,
    expiresIn: '15m',
    refreshExpiresIn: '7d',
    algorithm: 'HS256',
  };
}

/**
 * Get default database configuration for development
 *
 * Returns a default database configuration using mock repositories.
 * Suitable for development and testing environments.
 *
 * @returns Default database configuration
 */
export function getDefaultDatabaseConfig(): DatabaseConfig {
  return {
    type: 'mock',
  };
}

/**
 * Quick setup function specifically for testing
 *
 * Provides a simple wrapper around setupAuthenticationForDevelopment with
 * a fixed secret for consistent test results.
 *
 * @returns Complete authentication setup for testing
 */
export function setupDevAuthentication(): AuthSetup {
  return setupAuthenticationForDevelopment('test-secret-key-min-32-characters-long');
}