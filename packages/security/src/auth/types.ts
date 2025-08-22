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
  /** Device information for security tracking */
  deviceInfo?: {
    userAgent?: string;
    ipAddress?: string;
  };
  /** Additional custom claims */
  [key: string]: unknown;
}

/**
 * Authentication tokens pair with metadata
 * Contains access token, refresh token, and expiration information
 * Simplified to match SUB-SEC-002-03 specification
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
 * Basic JWT configuration interface
 * Simplified configuration for JWT tokens - matches SUB-SEC-002-03 specification
 */
export interface JwtConfig {
  /** Secret key for signing JWT tokens */
  secret: string;
  /** Access token expiration time (e.g., '15m', '1h') */
  expiresIn: string;
  /** Refresh token expiration time (e.g., '7d', '30d') */
  refreshExpiresIn: string;
  /** JWT signing algorithm */
  algorithm: 'HS256' | 'RS256';
}

/**
 * JWT Manager configuration extending base JWT config
 * Provides comprehensive configuration for JWT token generation and validation
 */
export interface JwtManagerConfig {
  /** Secret key for signing JWT tokens (minimum 32 characters) */
  secret: string;
  /** Access token expiration time (e.g., '15m', '1h') */
  expiresIn: string;
  /** Refresh token expiration time (e.g., '7d', '30d') */
  refreshExpiresIn: string;
  /** JWT signing algorithm */
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  /** Token issuer identifier */
  issuer?: string;
  /** Token audience identifier */
  audience?: string;
  /** Clock tolerance in seconds for token validation */
  clockTolerance?: number;
}

/**
 * Options for generating JWT token pairs
 * Contains user information and context for token creation
 */
export interface JwtTokenGenerationOptions {
  /** User unique identifier */
  userId: string;
  /** User email address */
  email?: string;
  /** User display name */
  name?: string;
  /** User roles for access control */
  roles?: string[];
  /** User permissions for fine-grained access */
  permissions?: string[];
  /** Session identifier (auto-generated if not provided) */
  sessionId?: string;
  /** Security context for audit logging */
  context?: SecurityContext;
}

/**
 * JWT token generation result
 * Result of successful or failed token generation
 */
export interface JwtTokenGenerationResult {
  /** Whether token generation was successful */
  success: boolean;
  /** Generated token pair if successful */
  tokens?: AuthTokens;
  /** Error information if generation failed */
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  /** Security context for the generation */
  context: SecurityContext;
}

/**
 * JWT token refresh request
 * Request structure for refreshing access tokens
 */
export interface JwtTokenRefreshRequest {
  /** Valid refresh token */
  refreshToken: string;
  /** Security context for the refresh operation */
  context: SecurityContext;
}

/**
 * JWT token refresh result
 * Result of attempting to refresh tokens
 */
export interface JwtTokenRefreshResult {
  /** Whether refresh was successful */
  success: boolean;
  /** New token pair if successful */
  tokens?: AuthTokens;
  /** Error message if refresh failed */
  error?: string;
  /** Security context for the refresh */
  context: SecurityContext;
}

/**
 * Authenticated user interface
 * Represents a fully authenticated user with security context
 */
export interface AuthenticatedUser {
  /** User unique identifier */
  id: string;
  /** User email address */
  email: string;
  /** User roles for role-based access control */
  roles: string[];
  /** User permissions for fine-grained access control */
  permissions: string[];
  /** Current session identifier */
  sessionId: string;
  /** When the user last logged in */
  lastLoginAt: Date;
}

/**
 * Login credentials interface
 * Credentials required for user authentication
 */
export interface LoginCredentials {
  /** User email address */
  email: string;
  /** User password */
  password: string;
  /** Device information for security tracking */
  deviceInfo?: {
    userAgent?: string;
    ipAddress?: string;
  };
}

/**
 * Login result interface
 * Result of successful user authentication
 */
export interface LoginResult {
  /** Authenticated user information */
  user: AuthenticatedUser;
  /** Authentication tokens */
  tokens: AuthTokens;
  /** Whether this is the user's first login */
  isFirstLogin: boolean;
}

/**
 * Refresh token request interface
 * Request structure for token refresh operations
 */
export interface RefreshTokenRequest {
  /** Valid refresh token */
  refreshToken: string;
  /** Device information for security tracking */
  deviceInfo?: {
    userAgent?: string;
    ipAddress?: string;
  };
}

/**
 * Logout request interface
 * Request structure for logout operations
 */
export interface LogoutRequest {
  /** Refresh token to invalidate (optional) */
  refreshToken?: string;
  /** Whether to logout from all devices */
  logoutAllDevices?: boolean;
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

/**
 * Repository interfaces for database abstraction
 */

/**
 * User repository interface
 * Abstracts user data access operations
 */
export interface IUserRepository {
  /** Find user by email address */
  findByEmail(email: string): Promise<AuthenticatedUser | null>;
  /** Find user by unique identifier */
  findById(id: string): Promise<AuthenticatedUser | null>;
  /** Update user's last login timestamp */
  updateLastLogin(id: string): Promise<void>;
  /** Validate user password */
  validatePassword(email: string, password: string): Promise<boolean>;
  /** Update user password (for password change functionality) */
  updatePassword?(userId: string, hashedPassword: string): Promise<void>;
  /** Create new user (optional for admin features) */
  createUser?(userData: {
    email: string;
    password: string;
    roles?: string[];
    permissions?: string[];
  }): Promise<AuthenticatedUser>;
  /** List all users (optional for admin features) */
  listUsers?(): Promise<Omit<AuthenticatedUser, 'sessionId'>[]>;
}

/**
 * Session repository interface
 * Abstracts session data access operations
 */
export interface ISessionRepository {
  /** Create new user session */
  createSession(userId: string, refreshToken: string, deviceInfo?: any): Promise<string>;
  /** Find session by session identifier */
  findSession(sessionId: string): Promise<{ userId: string; refreshToken: string } | null>;
  /** Update session refresh token */
  updateSessionToken?(sessionId: string, newRefreshToken: string): Promise<void>;
  /** Revoke specific session */
  revokeSession(sessionId: string): Promise<void>;
  /** Revoke all user sessions */
  revokeAllUserSessions(userId: string): Promise<void>;
  /** Get user's active sessions */
  getUserActiveSessions?(userId: string): Promise<Array<{
    sessionId: string;
    deviceInfo?: any;
    createdAt: Date;
    lastAccessedAt: Date;
  }>>;
  /** Clean up expired sessions */
  cleanupExpiredSessions?(): Promise<number>;
  /** Check if token is blacklisted */
  isTokenBlacklisted(token: string): Promise<boolean>;
  /** Add token to blacklist */
  blacklistToken(token: string, expiresAt: Date): Promise<void>;
}

/**
 * Registration interfaces
 */

/**
 * User registration data interface
 * Data required for user registration
 */
export interface RegistrationData {
  /** User email address */
  email: string;
  /** User password */
  password: string;
  /** Password confirmation */
  confirmPassword: string;
  /** User first name (optional) */
  firstName?: string;
  /** User last name (optional) */
  lastName?: string;
  /** User roles (optional) */
  roles?: string[];
  /** User permissions (optional) */
  permissions?: string[];
}

/**
 * Registration result interface
 * Result of user registration operation
 */
export interface RegistrationResult {
  /** Created user information (without session) */
  user: Omit<AuthenticatedUser, 'sessionId'>;
  /** Whether email verification is required */
  requiresVerification: boolean;
}

/**
 * Extended authentication configuration interfaces
 * These support the full authentication setup as specified in SUB-SEC-002-03
 */

/**
 * Registration configuration options
 */
export interface RegistrationConfig {
  /** Whether email verification is required for new users */
  requireEmailVerification?: boolean;
  /** Default roles assigned to new users */
  defaultRoles?: string[];
  /** Default permissions assigned to new users */
  defaultPermissions?: string[];
  /** Allowed roles that can be assigned during registration */
  allowedRoles?: string[];
}

/**
 * Password reset configuration options
 */
export interface PasswordResetConfig {
  /** Token expiration time in minutes (default: 60) */
  tokenExpirationMinutes?: number;
  /** Whether to revoke all user sessions on password reset */
  revokeSessionsOnReset?: boolean;
}

/**
 * Configuration interfaces
 */

/**
 * Database configuration interface
 * Configuration for different database backends
 */
export interface DatabaseConfig {
  /** Database type */
  type: 'mock' | 'prisma' | 'custom';
  /** Prisma client instance (when available) */
  prismaClient?: any; // Will be properly typed when CORE-001 is available
  /** Custom repository implementations */
  customRepositories?: {
    userRepo: IUserRepository;
    sessionRepo: ISessionRepository;
  };
}

/**
 * Authentication setup configuration interface
 * Complete configuration for authentication setup - enhanced for SUB-SEC-002-03
 */
export interface AuthSetupConfig {
  /** JWT configuration */
  jwt: JwtConfig;
  /** Database configuration */
  database: DatabaseConfig;
  /** Registration configuration (optional) */
  registration?: RegistrationConfig;
  /** Password reset configuration (optional) */
  passwordReset?: PasswordResetConfig;
}

/**
 * Complete authentication setup result
 * Contains all services, middleware, and handlers for authentication
 */
export interface AuthSetup {
  /** Main authentication service */
  authService: any; // Will be properly typed when AuthService is implemented
  /** Authentication middleware functions */
  middleware: {
    auth: any; // Authentication middleware
    requireAuth: any; // Required auth middleware
    optionalAuth: any; // Optional auth middleware
  };
  /** Authentication route handlers */
  handlers: any; // Auth handlers
  /** Database repositories */
  repositories: {
    userRepo: IUserRepository;
    sessionRepo: ISessionRepository;
  };
}
