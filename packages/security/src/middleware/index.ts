/**
 * Middleware module for the @agenda-bella/security package
 *
 * This module provides comprehensive middleware utilities for Express applications,
 * including basic security middleware, authentication middleware, and utilities.
 * Combines functionality from SUB-SEC-001-09 and auth integration from SUB-SEC-002-12.
 *
 * @packageDocumentation
 */

// Export all types and interfaces
export * from './types';

// Export all utility functions and constants  
export * from './utils';

// Re-export authentication middleware for convenience
export {
  createAuthMiddleware,
  createOptionalAuthMiddleware,
  createRoleAuthMiddleware,
} from '../auth/middleware';

// Re-export authentication setup utilities
export {
  setupAuthentication,
  setupAuthenticationForDevelopment,
  setupAuthenticationWithCustomRepositories,
  createAuthRouter,
  createExtendedAuthRouter,
  validateAuthSetupConfig,
  getDefaultJwtConfig,
  getDefaultDatabaseConfig,
} from '../auth/setup';

// Re-export authentication types for convenience
export type {
  AuthSetupConfig,
  AuthenticatedUser,
  JwtConfig,
  DatabaseConfig,
  RegistrationConfig,
  PasswordResetConfig,
} from '../auth/types';

// Re-export setup-specific types
export type {
  AuthSetup,
  EnhancedAuthSetupConfig,
} from '../auth/setup';
