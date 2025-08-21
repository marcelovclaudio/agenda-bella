/**
 * Authentication module
 *
 * This module provides comprehensive authentication functionality including
 * JWT token management, session handling, multi-factor authentication,
 * and security utilities for the application.
 *
 * @packageDocumentation
 */

// Export all authentication types
export type {
  JwtPayload,
  AuthTokens,
  TokenValidationResult,
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
} from './types';

// Export all authentication utilities and constants
export {
  AUTH_CONSTANTS,
  JwtUtils,
  SecurityUtils,
  TimeUtils,
  AuthorizationUtils,
  ValidationUtils,
} from './utils';

// TODO: Export authentication implementations when ready
// These will be implemented in Phase 2 (SEC-002)
// export { JwtService } from './jwt.service';
// export { AuthService } from './auth.service';
// export { SessionService } from './session.service';
// export { MfaService } from './mfa.service';
// export { PasswordService } from './password.service';
