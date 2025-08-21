/**
 * Security package types and interfaces
 *
 * This module exports all security-related types and interfaces used throughout
 * the security package for authentication, authorization, rate limiting, and
 * other security operations.
 *
 * @packageDocumentation
 */

// Export all common types and interfaces
export type {
  SecurityContext,
  SecurityConfig,
  SecurityEventType,
  SecurityEvent,
  SecurityError,
  AuthResult,
  AuthorizationResult,
  RateLimitResult,
} from './common.types';

// Export all error types and classes
export {
  SecurityError as SecurityErrorClass,
  AuthenticationError,
  InvalidCredentialsError,
  InvalidTokenError,
  TokenExpiredError,
  InvalidRefreshTokenError,
  AuthorizationError,
  InsufficientPermissionsError,
  ResourceNotFoundError,
  OperationForbiddenError,
  RateLimitError,
  TooManyRequestsError,
  TooManyLoginAttemptsError,
  PasswordPolicyError,
  WeakPasswordError,
  PasswordReuseError,
  PasswordExpiredError,
  AccountSecurityError,
  AccountLockedError,
  AccountSuspendedError,
  EmailVerificationRequiredError,
  MfaRequiredError,
  InvalidMfaCodeError,
  SessionError,
  SessionExpiredError,
  InvalidSessionError,
  SecurityConfigError,
  CryptographicError,
  isSecurityError,
  isAuthenticationError,
  isAuthorizationError,
  isRateLimitError,
  type SecurityErrorType,
} from './errors.types';

// Export all configuration types
export type {
  JwtConfig,
  PasswordConfig,
  RateLimitConfig,
  HelmetConfig,
  CorsConfig,
  SessionConfig,
  RedisConfig,
  AuditConfig,
  SecurityEnvironmentConfig,
} from './config.types';
