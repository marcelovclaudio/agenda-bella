/**
 * Authentication types and interfaces
 *
 * This module provides comprehensive type definitions for JWT authentication,
 * token management, session handling, and authentication results.
 *
 * @packageDocumentation
 */

import type { SecurityContext, SecurityError } from '../types';

/**
 * JWT payload structure following RFC 7519 standard
 * Contains standard claims plus application-specific claims
 */
export interface JwtPayload {
  /** Subject - User identifier (standard claim) */
  sub: string;
  /** Issued at - Timestamp when token was issued (standard claim) */
  iat: number;
  /** Expiration time - Timestamp when token expires (standard claim) */
  exp: number;
  /** Audience - Token intended recipients (standard claim) */
  aud?: string;
  /** Issuer - Token issuer identifier (standard claim) */
  iss?: string;
  /** JWT ID - Unique token identifier (standard claim) */
  jti?: string;
  /** Not before - Timestamp when token becomes valid (standard claim) */
  nbf?: number;

  // Application-specific claims
  /** User roles for role-based access control */
  roles?: string[];
  /** User permissions for fine-grained access control */
  permissions?: string[];
  /** User email address */
  email?: string;
  /** User display name */
  name?: string;
  /** Session identifier */
  sessionId?: string;
  /** Token type identifier */
  tokenType?: 'access' | 'refresh';
  /** Additional custom claims */
  [key: string]: unknown;
}

/**
 * Authentication tokens pair with metadata
 * Contains access token, refresh token, and expiration information
 */
export interface AuthTokens {
  /** JWT access token for API requests */
  accessToken: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken: string;
  /** When the access token expires */
  expiresAt: Date;
  /** Token type for Authorization header */
  tokenType: 'Bearer';
  /** When the refresh token expires */
  refreshExpiresAt?: Date;
  /** Token scope/permissions */
  scope?: string[];
}

/**
 * Token validation result
 * Contains validation status and decoded payload or error information
 */
export interface TokenValidationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** Decoded JWT payload if token is valid */
  payload?: JwtPayload;
  /** Error information if token is invalid */
  error?: {
    code: string;
    message: string;
    type:
      | 'expired'
      | 'invalid'
      | 'malformed'
      | 'not_before'
      | 'audience_mismatch'
      | 'issuer_mismatch';
  };
  /** Security context for the validation */
  context: SecurityContext;
}

/**
 * Authentication request credentials
 * Flexible structure for different authentication methods
 */
export interface AuthenticationCredentials {
  /** Authentication method type */
  method: 'password' | 'refresh_token' | 'oauth' | 'saml' | 'ldap' | 'api_key';

  // Password authentication
  /** User identifier (email, username, etc.) */
  identifier?: string;
  /** User password */
  password?: string;

  // Token-based authentication
  /** Refresh token for token renewal */
  refreshToken?: string;
  /** API key for service authentication */
  apiKey?: string;

  // OAuth/external authentication
  /** OAuth provider */
  provider?: string;
  /** OAuth authorization code */
  code?: string;
  /** OAuth access token */
  accessToken?: string;

  // Multi-factor authentication
  /** MFA token/code */
  mfaCode?: string;
  /** MFA method type */
  mfaMethod?: 'totp' | 'sms' | 'email' | 'backup_code';

  // Additional metadata
  /** Client information */
  clientId?: string;
  /** Remember me flag */
  rememberMe?: boolean;
  /** Additional authentication data */
  metadata?: Record<string, unknown>;
}

/**
 * Authentication result with comprehensive status information
 * Integrates with existing SecurityError types from common.types
 */
export interface AuthenticationResult {
  /** Whether authentication was successful */
  success: boolean;
  /** User identifier if authentication succeeded */
  userId?: string;
  /** Authentication tokens if successful */
  tokens?: AuthTokens;
  /** User information if available */
  user?: {
    id: string;
    email?: string;
    name?: string;
    roles?: string[];
    permissions?: string[];
    emailVerified?: boolean;
    accountStatus?: 'active' | 'pending' | 'suspended' | 'locked';
    lastLoginAt?: Date;
    metadata?: Record<string, unknown>;
  };
  /** Error information if authentication failed */
  error?: SecurityError;
  /** Security context for the authentication attempt */
  context: SecurityContext;
  /** Whether multi-factor authentication is required */
  requiresMfa?: boolean;
  /** Available MFA methods if required */
  mfaMethods?: string[];
  /** Session information */
  session?: {
    id: string;
    expiresAt: Date;
    ipAddress: string;
    userAgent?: string;
    metadata?: Record<string, unknown>;
  };
}

/**
 * Token refresh result
 * Result of attempting to refresh an access token
 */
export interface TokenRefreshResult {
  /** Whether refresh was successful */
  success: boolean;
  /** New authentication tokens if successful */
  tokens?: AuthTokens;
  /** Error information if refresh failed */
  error?: SecurityError;
  /** Security context for the refresh attempt */
  context: SecurityContext;
}

/**
 * Authentication middleware request interface
 * Extends request objects with authentication information
 */
export interface AuthenticatedRequest {
  /** Security context for the request */
  securityContext: SecurityContext;
  /** Authenticated user information */
  user?: {
    id: string;
    email?: string;
    name?: string;
    roles: string[];
    permissions: string[];
    sessionId: string;
    tokenPayload: JwtPayload;
  };
  /** Raw JWT token */
  token?: string;
  /** Whether the request is authenticated */
  isAuthenticated: boolean;
}

/**
 * Authentication middleware options
 * Configuration for authentication middleware behavior
 */
export interface AuthMiddlewareOptions {
  /** Whether authentication is required (default: true) */
  required?: boolean;
  /** Required roles for access */
  roles?: string[];
  /** Required permissions for access */
  permissions?: string[];
  /** Custom authentication logic */
  custom?: (req: AuthenticatedRequest) => Promise<boolean> | boolean;
  /** Skip authentication for certain conditions */
  skip?: (req: unknown) => boolean;
  /** Error handling strategy */
  errorStrategy?: 'throw' | 'next' | 'custom';
  /** Custom error handler */
  onError?: (error: SecurityError, req: AuthenticatedRequest) => void;
}

/**
 * Session management types
 */
export interface SessionData {
  /** Session unique identifier */
  id: string;
  /** User ID associated with the session */
  userId: string;
  /** When the session was created */
  createdAt: Date;
  /** When the session was last accessed */
  lastAccessedAt: Date;
  /** When the session expires */
  expiresAt: Date;
  /** IP address of the session */
  ipAddress: string;
  /** User agent string */
  userAgent?: string;
  /** Whether the session is active */
  isActive: boolean;
  /** Session metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Session management result
 */
export interface SessionManagementResult {
  /** Whether the operation was successful */
  success: boolean;
  /** Session data if available */
  session?: SessionData;
  /** Error information if operation failed */
  error?: SecurityError;
  /** Security context for the operation */
  context: SecurityContext;
}

/**
 * Multi-factor authentication types
 */
export interface MfaSetupRequest {
  /** User ID */
  userId: string;
  /** MFA method type */
  method: 'totp' | 'sms' | 'email' | 'backup_codes';
  /** Phone number for SMS */
  phoneNumber?: string;
  /** Email address for email codes */
  email?: string;
  /** Security context */
  context: SecurityContext;
}

export interface MfaSetupResult {
  /** Whether setup was successful */
  success: boolean;
  /** Setup data (QR code, secret, backup codes, etc.) */
  setupData?: {
    secret?: string;
    qrCode?: string;
    backupCodes?: string[];
    verificationToken?: string;
  };
  /** Error information if setup failed */
  error?: SecurityError;
  /** Security context for the setup */
  context: SecurityContext;
}

export interface MfaVerificationRequest {
  /** User ID */
  userId: string;
  /** MFA method used */
  method: 'totp' | 'sms' | 'email' | 'backup_code';
  /** Verification code */
  code: string;
  /** Verification token from setup */
  verificationToken?: string;
  /** Security context */
  context: SecurityContext;
}

export interface MfaVerificationResult {
  /** Whether verification was successful */
  success: boolean;
  /** Whether this was the final verification step */
  isComplete?: boolean;
  /** Next step if verification is not complete */
  nextStep?: string;
  /** Error information if verification failed */
  error?: SecurityError;
  /** Security context for the verification */
  context: SecurityContext;
}

/**
 * Account security types
 */
export interface AccountSecurityStatus {
  /** Whether the account is locked */
  isLocked: boolean;
  /** Whether the account is suspended */
  isSuspended: boolean;
  /** Whether email is verified */
  emailVerified: boolean;
  /** Whether MFA is enabled */
  mfaEnabled: boolean;
  /** Available MFA methods */
  mfaMethods: string[];
  /** Failed login attempts count */
  failedLoginAttempts: number;
  /** When the account was last locked */
  lastLockedAt?: Date;
  /** When the account lock expires */
  lockExpiresAt?: Date;
  /** Password last changed date */
  passwordChangedAt?: Date;
  /** Whether password needs to be changed */
  passwordExpired: boolean;
}

/**
 * Password reset types
 */
export interface PasswordResetRequest {
  /** User identifier (email or username) */
  identifier: string;
  /** Security context */
  context: SecurityContext;
}

export interface PasswordResetResult {
  /** Whether the reset request was successful */
  success: boolean;
  /** Reset token if successful */
  resetToken?: string;
  /** When the reset token expires */
  expiresAt?: Date;
  /** Error information if request failed */
  error?: SecurityError;
  /** Security context for the request */
  context: SecurityContext;
}

export interface PasswordChangeRequest {
  /** User ID or reset token */
  userIdOrToken: string;
  /** New password */
  newPassword: string;
  /** Current password (for authenticated users) */
  currentPassword?: string;
  /** Whether this is a reset (using token) */
  isReset?: boolean;
  /** Security context */
  context: SecurityContext;
}

export interface PasswordChangeResult {
  /** Whether the password change was successful */
  success: boolean;
  /** Whether the user needs to re-authenticate */
  requiresReauth?: boolean;
  /** Error information if change failed */
  error?: SecurityError;
  /** Security context for the change */
  context: SecurityContext;
}
