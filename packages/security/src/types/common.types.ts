/**
 * Core security types and interfaces
 * @packageDocumentation
 */

import type {
  CorsConfig,
  HelmetConfig,
  JwtConfig,
  PasswordConfig,
  RateLimitConfig,
  SessionConfig,
} from './config.types';

/**
 * Security context containing information about the current request/session
 * Used for tracking and auditing security-related operations
 */
export interface SecurityContext {
  /** User identifier if authenticated */
  userId?: string;
  /** Unique session identifier */
  sessionId: string;
  /** Client IP address */
  ipAddress: string;
  /** Client user agent string */
  userAgent?: string;
  /** Timestamp when context was created */
  timestamp: Date;
  /** Additional metadata for the security context */
  metadata?: Record<string, unknown>;
}

/**
 * Main security configuration interface
 * Aggregates all security-related configurations
 * Note: Configuration type imports are done via type-only imports to avoid circular dependencies
 */
export interface SecurityConfig {
  /** JWT authentication configuration */
  jwt?: JwtConfig;
  /** Rate limiting configuration */
  rateLimit?: RateLimitConfig;
  /** Password security configuration */
  password?: PasswordConfig;
  /** Helmet security headers configuration */
  helmet?: HelmetConfig;
  /** CORS configuration */
  cors?: CorsConfig;
  /** Session configuration */
  session?: SessionConfig;
}

/**
 * Security event types for auditing and monitoring
 */
export type SecurityEventType =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'TOKEN_REFRESH'
  | 'PERMISSION_DENIED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'SUSPICIOUS_ACTIVITY'
  | 'PASSWORD_CHANGE'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED';

/**
 * Security event data structure for logging and auditing
 */
export interface SecurityEvent {
  /** Type of security event */
  type: SecurityEventType;
  /** When the event occurred */
  timestamp: Date;
  /** Security context at the time of the event */
  context: SecurityContext;
  /** Additional event-specific data */
  data?: Record<string, unknown>;
  /** Severity level of the event */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Optional description of the event */
  description?: string;
}

/**
 * Base interface for security-related errors
 */
export interface SecurityError extends Error {
  /** Error code for categorization */
  code: string;
  /** HTTP status code associated with the error */
  statusCode: number;
  /** Security context when the error occurred */
  context?: SecurityContext;
  /** Whether this error should be logged for security monitoring */
  shouldLog: boolean;
}

/**
 * Authentication result interface
 */
export interface AuthResult {
  /** Whether authentication was successful */
  success: boolean;
  /** User identifier if authentication succeeded */
  userId?: string;
  /** JWT token if authentication succeeded */
  token?: string;
  /** Refresh token if applicable */
  refreshToken?: string;
  /** Error message if authentication failed */
  error?: string;
  /** Security context */
  context: SecurityContext;
}

/**
 * Authorization result interface
 */
export interface AuthorizationResult {
  /** Whether authorization was granted */
  granted: boolean;
  /** Reason for denial if authorization was not granted */
  reason?: string;
  /** Required permissions that were missing */
  missingPermissions?: string[];
  /** Security context */
  context: SecurityContext;
}

/**
 * Rate limiting result interface
 */
export interface RateLimitResult {
  /** Whether the request was allowed */
  allowed: boolean;
  /** Number of requests remaining in the current window */
  remaining: number;
  /** Total requests allowed in the window */
  limit: number;
  /** When the rate limit window resets */
  resetTime: Date;
  /** Time until the window resets (in milliseconds) */
  resetTimeMs: number;
}
