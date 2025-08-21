/**
 * @agenda-bella/security
 *
 * Fundação modular para autenticação, autorização, rate limiting e segurança.
 * Fornece utilities criptográficos, validações, error handling e middleware Express.
 *
 * @packageDocumentation
 */

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

// Core types - explicit exports for better tree-shaking
export type {
  SecurityContext,
  SecurityConfig,
  SecurityEventType,
  SecurityEvent,
  AuthResult,
  AuthorizationResult,
  RateLimitResult,
} from './types/common.types';

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
} from './types/config.types';

// ============================================================================
// ERROR CLASSES AND UTILITIES
// ============================================================================

// Error classes - explicit exports for instanceof checks
export {
  SecurityError,
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
} from './types/errors.types';

export type { SecurityErrorType } from './types/errors.types';

// ============================================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================================

export {
  generateSecureToken,
  generateSecureSecret,
  generateSecureUUID,
  hashSHA256,
  constantTimeCompare,
  createHMACSignature,
  verifyHMACSignature,
} from './utils/crypto';

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

export {
  isValidEmail,
  isValidPassword,
  getPasswordValidationDetails,
  sanitizeInput,
  isValidIPAddress,
  isValidIPv4,
  isValidIPv6,
  isValidURL,
  isValidUsername,
  isValidPhoneNumber,
  DEFAULT_PASSWORD_REQUIREMENTS,
} from './utils/validation';

export type { PasswordRequirements } from './utils/validation';
export type { PasswordValidationResult } from './password/types';

// ============================================================================
// MIDDLEWARE UTILITIES
// ============================================================================

export {
  createErrorHandler,
  extractBearerToken,
  getClientIP,
  createSecurityContext,
} from './middleware/utils';

export type {
  ExpressRequest,
  ExpressResponse,
  ExpressNextFunction,
  ExpressMiddleware,
  SecurityMiddleware,
  ExpressErrorMiddleware,
  SecurityMiddlewareConfig,
} from './middleware/types';

// ============================================================================
// LOGGING AND AUDIT
// ============================================================================

export {
  securityLogger,
  auditLog,
  logSecurityError,
  trackSecurityMetric,
  logger, // Re-export from shared
  winston,
  createChildLogger,
} from './utils';

// ============================================================================
// CONSTANTS
// ============================================================================

export { ERROR_CODES, ERROR_MESSAGES } from './constants/errors';
export type { ErrorCode } from './constants/errors';

export {
  SYSTEM_PERMISSIONS,
  ROLE_IDENTIFIERS,
  PERMISSION_GROUPS,
  DEFAULT_ROLE_PERMISSIONS,
} from './constants/permissions';
export type { SystemPermission, RoleIdentifier } from './constants/permissions';

export {
  SECURITY_DEFAULTS,
  SECURITY_HEADERS,
  SECURITY_HEADER_VALUES,
  CRYPTO_ALGORITHMS,
  ENVIRONMENT_SECURITY,
  COOKIE_OPTIONS,
} from './constants/security';
export type { CryptoAlgorithm } from './constants/security';

// ============================================================================
// FOUNDATION MODULES (Base implementations for future SEC-002 to SEC-005)
// ============================================================================

// Auth module foundation
export * from './auth';

// Authorization module foundation
export * from './authorization';

// Password module foundation
export * from './password';

// Rate limiter module foundation
export * from './rate-limiter';

// ============================================================================
// CONVENIENCE GROUPED EXPORTS
// ============================================================================

// Export grouped utilities for common use cases
export * as CryptoUtils from './utils/crypto';
export * as ValidationUtils from './utils/validation';
export * as MiddlewareUtils from './middleware/utils';
export * as SecurityConstants from './constants';
export * as SecurityTypes from './types';
