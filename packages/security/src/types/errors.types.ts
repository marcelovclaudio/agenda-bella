/**
 * Hierarchical error system for security operations
 *
 * This module provides a comprehensive error hierarchy for security-related operations,
 * including authentication, authorization, rate limiting, and password security.
 *
 * @packageDocumentation
 */

import type { SecurityContext } from './common.types';

/**
 * Base abstract class for all security-related errors
 * Provides common functionality and structure for error handling
 */
export abstract class SecurityError extends Error {
  /** Unique error code for categorization and handling */
  abstract readonly code: string;

  /** HTTP status code associated with this error */
  abstract readonly statusCode: number;

  /** Timestamp when the error occurred */
  readonly timestamp = new Date();

  /** Whether this error should be logged for security monitoring */
  readonly shouldLog = true;

  /** Error severity level for monitoring and alerting */
  abstract readonly severity: 'low' | 'medium' | 'high' | 'critical';

  constructor(
    message: string,
    /** Security context when the error occurred */
    public readonly context?: SecurityContext,
    /** Additional error-specific data for debugging */
    public readonly details?: Record<string, unknown>,
    /** Original error that caused this security error (for error chaining) */
    public override readonly cause?: Error
  ) {
    super(message);
    this.name = this.constructor.name;

    // Maintain proper stack trace
    Error.captureStackTrace(this, this.constructor);

    // Set the cause if provided (Node.js 16.9.0+ feature)
    if (cause && 'cause' in Error.prototype) {
      (this as unknown as { cause: unknown }).cause = cause;
    }
  }

  /**
   * Convert error to a serializable object for API responses
   * Excludes sensitive information and stack traces in production
   */
  toJSON(): Record<string, unknown> {
    const isProduction = process.env['NODE_ENV'] === 'production';

    return {
      name: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      timestamp: this.timestamp.toISOString(),
      severity: this.severity,
      ...(this.details && { details: this.details }),
      ...(this.context && {
        context: {
          sessionId: this.context.sessionId,
          ipAddress: this.context.ipAddress,
          timestamp: this.context.timestamp.toISOString(),
          // Include userId only if not in production or if error is not authentication related
          ...((!isProduction || this.statusCode !== 401) &&
            this.context.userId && {
              userId: this.context.userId,
            }),
        },
      }),
      // Include stack trace only in development
      ...(!isProduction && { stack: this.stack }),
      // Include cause chain if present
      ...(this.cause && {
        cause:
          this.cause instanceof SecurityError
            ? this.cause.toJSON()
            : { name: this.cause.name, message: this.cause.message },
      }),
    };
  }

  /**
   * Get error information suitable for audit logging
   */
  toAuditLog(): Record<string, unknown> {
    return {
      errorType: this.name,
      errorCode: this.code,
      message: this.message,
      statusCode: this.statusCode,
      severity: this.severity,
      timestamp: this.timestamp.toISOString(),
      context: this.context,
      details: this.details,
      stack: this.stack,
      cause: this.cause?.message,
    };
  }
}

/**
 * Base authentication error
 */
export class AuthenticationError extends SecurityError {
  readonly code = 'AUTH_ERROR';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Invalid credentials provided
 */
export class InvalidCredentialsError extends SecurityError {
  readonly code = 'INVALID_CREDENTIALS';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * JWT token is invalid or malformed
 */
export class InvalidTokenError extends SecurityError {
  readonly code = 'INVALID_TOKEN';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * JWT token has expired
 */
export class TokenExpiredError extends SecurityError {
  readonly code = 'TOKEN_EXPIRED';
  readonly statusCode = 401;
  readonly severity = 'low' as const;
}

/**
 * Refresh token is invalid or expired
 */
export class InvalidRefreshTokenError extends SecurityError {
  readonly code = 'INVALID_REFRESH_TOKEN';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Multi-factor authentication required
 */
export class MfaRequiredError extends SecurityError {
  readonly code = 'MFA_REQUIRED';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Invalid MFA code provided
 */
export class InvalidMfaCodeError extends SecurityError {
  readonly code = 'INVALID_MFA_CODE';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Base authorization error
 */
export class AuthorizationError extends SecurityError {
  readonly code = 'AUTHZ_ERROR';
  readonly statusCode = 403;
  readonly severity = 'medium' as const;
}

/**
 * User lacks required permissions
 */
export class InsufficientPermissionsError extends SecurityError {
  readonly code = 'INSUFFICIENT_PERMISSIONS';
  readonly statusCode = 403;
  readonly severity = 'medium' as const;
}

/**
 * Attempting to access a resource that doesn't exist or user cannot see
 */
export class ResourceNotFoundError extends SecurityError {
  readonly code = 'RESOURCE_NOT_FOUND';
  readonly statusCode = 404;
  readonly severity = 'low' as const;
}

/**
 * Operation forbidden for this user/role
 */
export class OperationForbiddenError extends SecurityError {
  readonly code = 'OPERATION_FORBIDDEN';
  readonly statusCode = 403;
  readonly severity = 'medium' as const;
}

/**
 * Base rate limiting error
 */
export class RateLimitError extends SecurityError {
  readonly code = 'RATE_LIMIT_ERROR';
  readonly statusCode = 429;
  readonly severity = 'medium' as const;

  constructor(
    message: string,
    context?: SecurityContext,
    /** Rate limit specific information */
    public readonly rateLimitDetails?: {
      limit: number;
      remaining: number;
      resetTime: Date;
      resetTimeMs: number;
    },
    cause?: Error
  ) {
    super(message, context, rateLimitDetails, cause);
  }
}

/**
 * Too many requests from this IP/user
 */
export class TooManyRequestsError extends SecurityError {
  readonly code = 'TOO_MANY_REQUESTS';
  readonly statusCode = 429;
  readonly severity = 'medium' as const;

  constructor(
    message: string,
    context?: SecurityContext,
    /** Rate limit specific information */
    public readonly rateLimitDetails?: {
      limit: number;
      remaining: number;
      resetTime: Date;
      resetTimeMs: number;
    },
    cause?: Error
  ) {
    super(message, context, rateLimitDetails, cause);
  }
}

/**
 * Too many failed login attempts
 */
export class TooManyLoginAttemptsError extends SecurityError {
  readonly code = 'TOO_MANY_LOGIN_ATTEMPTS';
  readonly statusCode = 429;
  readonly severity = 'high' as const;

  constructor(
    message: string,
    context?: SecurityContext,
    /** Rate limit specific information */
    public readonly rateLimitDetails?: {
      limit: number;
      remaining: number;
      resetTime: Date;
      resetTimeMs: number;
    },
    cause?: Error
  ) {
    super(message, context, rateLimitDetails, cause);
  }
}

/**
 * Base password policy error
 */
export class PasswordPolicyError extends SecurityError {
  readonly code = 'PASSWORD_POLICY_ERROR';
  readonly statusCode = 400;
  readonly severity = 'low' as const;
}

/**
 * Password doesn't meet complexity requirements
 */
export class WeakPasswordError extends SecurityError {
  readonly code = 'WEAK_PASSWORD';
  readonly statusCode = 400;
  readonly severity = 'low' as const;
}

/**
 * Password has been used recently and cannot be reused
 */
export class PasswordReuseError extends SecurityError {
  readonly code = 'PASSWORD_REUSE';
  readonly statusCode = 400;
  readonly severity = 'low' as const;
}

/**
 * Password has expired and must be changed
 */
export class PasswordExpiredError extends SecurityError {
  readonly code = 'PASSWORD_EXPIRED';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Base account security error
 */
export class AccountSecurityError extends SecurityError {
  readonly code = 'ACCOUNT_SECURITY_ERROR';
  readonly statusCode = 403;
  readonly severity = 'high' as const;
}

/**
 * Account has been locked due to security violations
 */
export class AccountLockedError extends SecurityError {
  readonly code = 'ACCOUNT_LOCKED';
  readonly statusCode = 403;
  readonly severity = 'high' as const;
}

/**
 * Account has been suspended by administrator
 */
export class AccountSuspendedError extends SecurityError {
  readonly code = 'ACCOUNT_SUSPENDED';
  readonly statusCode = 403;
  readonly severity = 'high' as const;
}

/**
 * Account requires email verification
 */
export class EmailVerificationRequiredError extends SecurityError {
  readonly code = 'EMAIL_VERIFICATION_REQUIRED';
  readonly statusCode = 403;
  readonly severity = 'medium' as const;
}

/**
 * Base session error
 */
export class SessionError extends SecurityError {
  readonly code = 'SESSION_ERROR';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Session has expired
 */
export class SessionExpiredError extends SecurityError {
  readonly code = 'SESSION_EXPIRED';
  readonly statusCode = 401;
  readonly severity = 'low' as const;
}

/**
 * Session is invalid or corrupted
 */
export class InvalidSessionError extends SecurityError {
  readonly code = 'INVALID_SESSION';
  readonly statusCode = 401;
  readonly severity = 'medium' as const;
}

/**
 * Security configuration errors (500 Internal Server Error)
 */
export class SecurityConfigError extends SecurityError {
  readonly code = 'SECURITY_CONFIG_ERROR';
  readonly statusCode = 500;
  readonly severity = 'critical' as const;
  override readonly shouldLog = true;
}

/**
 * Cryptographic operation errors
 */
export class CryptographicError extends SecurityError {
  readonly code = 'CRYPTOGRAPHIC_ERROR';
  readonly statusCode = 500;
  readonly severity = 'critical' as const;
  override readonly shouldLog = true;
}

/**
 * Type guard to check if an error is a SecurityError
 */
export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError;
}

/**
 * Type guard to check if an error is an authentication error
 */
export function isAuthenticationError(
  error: unknown
): error is
  | AuthenticationError
  | InvalidCredentialsError
  | InvalidTokenError
  | TokenExpiredError
  | InvalidRefreshTokenError
  | MfaRequiredError
  | InvalidMfaCodeError {
  return (
    error instanceof AuthenticationError ||
    error instanceof InvalidCredentialsError ||
    error instanceof InvalidTokenError ||
    error instanceof TokenExpiredError ||
    error instanceof InvalidRefreshTokenError ||
    error instanceof MfaRequiredError ||
    error instanceof InvalidMfaCodeError
  );
}

/**
 * Type guard to check if an error is an authorization error
 */
export function isAuthorizationError(
  error: unknown
): error is
  | AuthorizationError
  | InsufficientPermissionsError
  | ResourceNotFoundError
  | OperationForbiddenError {
  return (
    error instanceof AuthorizationError ||
    error instanceof InsufficientPermissionsError ||
    error instanceof ResourceNotFoundError ||
    error instanceof OperationForbiddenError
  );
}

/**
 * Type guard to check if an error is a rate limit error
 */
export function isRateLimitError(
  error: unknown
): error is RateLimitError | TooManyRequestsError | TooManyLoginAttemptsError {
  return (
    error instanceof RateLimitError ||
    error instanceof TooManyRequestsError ||
    error instanceof TooManyLoginAttemptsError
  );
}

/**
 * Union type of all security error classes for type safety
 */
export type SecurityErrorType =
  | AuthenticationError
  | InvalidCredentialsError
  | InvalidTokenError
  | TokenExpiredError
  | InvalidRefreshTokenError
  | MfaRequiredError
  | InvalidMfaCodeError
  | AuthorizationError
  | InsufficientPermissionsError
  | ResourceNotFoundError
  | OperationForbiddenError
  | RateLimitError
  | TooManyRequestsError
  | TooManyLoginAttemptsError
  | PasswordPolicyError
  | WeakPasswordError
  | PasswordReuseError
  | PasswordExpiredError
  | AccountSecurityError
  | AccountLockedError
  | AccountSuspendedError
  | EmailVerificationRequiredError
  | SessionError
  | SessionExpiredError
  | InvalidSessionError
  | SecurityConfigError
  | CryptographicError;
