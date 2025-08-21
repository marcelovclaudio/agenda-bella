/**
 * Error codes and constants for the @agenda-bella/security package
 *
 * This module defines standardized error codes used across the security package
 * for consistent error handling and identification.
 *
 * @packageDocumentation
 */

/**
 * Standardized error codes for security-related operations
 *
 * These codes are used throughout the security package to provide
 * consistent error identification and handling across all modules.
 */
export const ERROR_CODES = {
  // Authentication errors
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED_TOKEN: 'EXPIRED_TOKEN',
  MISSING_TOKEN: 'MISSING_TOKEN',

  // Authorization errors
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  INVALID_ROLE: 'INVALID_ROLE',

  // Rate limiting errors
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // Password errors
  WEAK_PASSWORD: 'WEAK_PASSWORD',
  PASSWORD_MISMATCH: 'PASSWORD_MISMATCH',
} as const;

/**
 * Type for error code values
 */
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

/**
 * Error messages mapped to error codes
 * Provides human-readable descriptions for each error code
 */
export const ERROR_MESSAGES = {
  [ERROR_CODES.INVALID_TOKEN]: 'The provided token is invalid or malformed',
  [ERROR_CODES.EXPIRED_TOKEN]: 'The token has expired and is no longer valid',
  [ERROR_CODES.MISSING_TOKEN]: 'Authentication token is required but not provided',
  [ERROR_CODES.INSUFFICIENT_PERMISSIONS]:
    'User does not have required permissions for this operation',
  [ERROR_CODES.INVALID_ROLE]: 'The specified role is invalid or does not exist',
  [ERROR_CODES.RATE_LIMIT_EXCEEDED]: 'Too many requests - rate limit exceeded',
  [ERROR_CODES.WEAK_PASSWORD]: 'Password does not meet security requirements',
  [ERROR_CODES.PASSWORD_MISMATCH]: 'Password confirmation does not match',
} as const;
