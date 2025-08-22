/**
 * Authentication module
 *
 * This module provides comprehensive authentication functionality including
 * JWT token management, session handling, multi-factor authentication,
 * and security utilities for the application.
 *
 * @packageDocumentation
 */

// Core JWT functionality
export { JwtManager, createJwtManager } from './jwt';
export { AuthService, createAuthService } from './service';
export { TokenBlacklistManager, MemoryTokenBlacklist, createTokenBlacklistManager, createMemoryTokenBlacklistManager } from './blacklist';

// Registration functionality
export { RegistrationService, createRegistrationService } from './registration';
export type { RegistrationServiceConfig } from './registration';

// Password reset functionality
export { PasswordResetService, createPasswordResetService } from './password-reset';
export type { PasswordResetRequest, PasswordResetConfirm, PasswordResetServiceConfig } from './password-reset';

// Database abstraction layer
export { 
  MockUserRepository, 
  MockSessionRepository, 
  createMockDatabaseRepositories, 
  createDatabaseRepositories,
  validateDatabaseConfig 
} from './database';

// Express middleware
export { 
  createAuthMiddleware, 
  createOptionalAuthMiddleware, 
  createRoleAuthMiddleware,
  default as authMiddleware 
} from './middleware';

// Types and interfaces
export type {
  JwtPayload,
  JwtConfig,
  JwtManagerConfig,
  AuthTokens,
  TokenValidationResult,
  JwtTokenGenerationOptions,
  JwtTokenGenerationResult,
  JwtTokenRefreshRequest,
  JwtTokenRefreshResult,
  AuthenticatedUser,
  LoginCredentials,
  LoginResult,
  RefreshTokenRequest,
  LogoutRequest,
  IUserRepository,
  ISessionRepository,
  AuthenticationCredentials,
  AuthenticationResult,
  TokenRefreshResult,
  AuthenticatedRequest,
  AuthMiddlewareOptions,
  SessionData,
  SessionManagementResult,
  MfaSetupRequest,
  MfaSetupResult,
  MfaVerificationRequest,
  MfaVerificationResult,
  AccountSecurityStatus,
  RegistrationData,
  RegistrationResult,
  DatabaseConfig,
  RegistrationConfig,
  PasswordResetConfig,
  AuthSetupConfig,
} from './types';

// Utilities and constants
export {
  AUTH_CONSTANTS,
  JwtUtils,
  SecurityUtils,
  TimeUtils,
  AuthorizationUtils,
  ValidationUtils,
} from './utils';

// TODO: Export remaining authentication implementations
// These will be implemented in Phase 2 (SEC-002)
// export { SessionService } from './session.service';
// export { MfaService } from './mfa.service';
// export { PasswordService } from './password.service';

// Route protection guards
export {
  requireRole,
  requireAnyRole,
  requirePermission,
  requireOwnership,
  requireRoleAndPermission,
  canUser,
  hasRole,
  hasAnyRole,
  hasPermission,
} from './guards';
export type { OwnershipChecker, GuardAuthenticatedRequest } from './guards';

// Authentication route handlers
export { createAuthHandlers, default as authHandlers } from './handlers';
export type { AuthHandlers } from './handlers';

// Authentication setup utilities
export {
  setupAuthentication,
  setupAuthenticationForDevelopment,
  setupAuthenticationWithCustomRepositories,
  createAuthRouter,
  createExtendedAuthRouter,
  validateAuthSetupConfig,
  getDefaultJwtConfig,
  getDefaultDatabaseConfig,
} from './setup';
export type { AuthSetup, EnhancedAuthSetupConfig } from './setup';

// Authentication middleware - IMPLEMENTED ✓
// Provides Express middleware for JWT authentication with comprehensive error handling