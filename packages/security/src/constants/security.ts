/**
 * Security configuration constants for the @agenda-bella/security package
 *
 * This module defines default security configurations, timeouts, and other
 * security-related constants used throughout the security package.
 *
 * @packageDocumentation
 */

/**
 * Default security configuration values
 *
 * These constants provide sensible defaults for security operations
 * and can be overridden by application-specific configurations.
 */
export const SECURITY_DEFAULTS = {
  // HTTP Headers
  TOKEN_HEADER: 'authorization',
  TOKEN_PREFIX: 'Bearer ',
  SESSION_COOKIE_NAME: 'session_id',
  CSRF_HEADER: 'x-csrf-token',

  // Timeouts (in milliseconds)
  AUTH_TIMEOUT_MS: 5000,
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  SESSION_TIMEOUT_MS: 24 * 60 * 60 * 1000, // 24 hours

  // Encryption and Hashing
  BCRYPT_ROUNDS: 12,
  TOKEN_SECRET_MIN_LENGTH: 32,

  // Token expiration
  ACCESS_TOKEN_EXPIRES_IN: '15m',
  REFRESH_TOKEN_EXPIRES_IN: '7d',

  // Rate limiting
  DEFAULT_RATE_LIMIT: 100,
  AUTH_RATE_LIMIT: 5,

  // Password constraints
  MIN_PASSWORD_LENGTH: 8,
  MAX_PASSWORD_LENGTH: 128,
} as const;

/**
 * HTTP security headers configuration
 *
 * Standard security headers that should be applied to HTTP responses
 */
export const SECURITY_HEADERS = {
  CONTENT_SECURITY_POLICY: 'Content-Security-Policy',
  STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',
  X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
  X_FRAME_OPTIONS: 'X-Frame-Options',
  X_XSS_PROTECTION: 'X-XSS-Protection',
  REFERRER_POLICY: 'Referrer-Policy',
  PERMISSIONS_POLICY: 'Permissions-Policy',
} as const;

/**
 * Security header values
 *
 * Default values for security headers
 */
export const SECURITY_HEADER_VALUES = {
  [SECURITY_HEADERS.CONTENT_SECURITY_POLICY]: "default-src 'self'",
  [SECURITY_HEADERS.STRICT_TRANSPORT_SECURITY]: 'max-age=31536000; includeSubDomains',
  [SECURITY_HEADERS.X_CONTENT_TYPE_OPTIONS]: 'nosniff',
  [SECURITY_HEADERS.X_FRAME_OPTIONS]: 'DENY',
  [SECURITY_HEADERS.X_XSS_PROTECTION]: '1; mode=block',
  [SECURITY_HEADERS.REFERRER_POLICY]: 'strict-origin-when-cross-origin',
  [SECURITY_HEADERS.PERMISSIONS_POLICY]: 'camera=(), microphone=(), geolocation=()',
} as const;

/**
 * Algorithm types for cryptographic operations
 */
export const CRYPTO_ALGORITHMS = {
  // JWT algorithms
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',

  // Hash algorithms
  SHA256: 'sha256',
  SHA384: 'sha384',
  SHA512: 'sha512',

  // Encryption algorithms
  AES_256_GCM: 'aes-256-gcm',
  AES_256_CBC: 'aes-256-cbc',
} as const;

/**
 * Type for crypto algorithm values
 */
export type CryptoAlgorithm = (typeof CRYPTO_ALGORITHMS)[keyof typeof CRYPTO_ALGORITHMS];

/**
 * Environment-specific security settings
 */
export const ENVIRONMENT_SECURITY = {
  DEVELOPMENT: {
    BCRYPT_ROUNDS: 10, // Lower for faster development
    TOKEN_EXPIRES_IN: '1h',
    SECURE_COOKIES: false,
  },
  PRODUCTION: {
    BCRYPT_ROUNDS: 12,
    TOKEN_EXPIRES_IN: '15m',
    SECURE_COOKIES: true,
  },
  TEST: {
    BCRYPT_ROUNDS: 4, // Very low for fast tests
    TOKEN_EXPIRES_IN: '5m',
    SECURE_COOKIES: false,
  },
} as const;

/**
 * Cookie configuration constants
 */
export const COOKIE_OPTIONS = {
  HTTP_ONLY: true,
  SECURE: true, // Should be true in production
  SAME_SITE: 'strict' as const,
  MAX_AGE: 24 * 60 * 60 * 1000, // 24 hours
  PATH: '/',
} as const;
