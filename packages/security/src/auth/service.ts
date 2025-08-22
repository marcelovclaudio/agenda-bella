/**
 * Main Authentication Service
 *
 * This module provides the primary authentication service that orchestrates 
 * JWT token management, user authentication, session handling, and security operations.
 * It integrates with JWT Manager and Token Blacklist Manager to provide comprehensive
 * authentication functionality with proper error handling and audit logging.
 *
 * @packageDocumentation
 */

import { JwtManager } from './jwt';
import { TokenBlacklistManager } from './blacklist';
import { RegistrationService, type RegistrationServiceConfig } from './registration';
import { PasswordResetService, type PasswordResetServiceConfig, type PasswordResetRequest, type PasswordResetConfirm } from './password-reset';
import { generateSecureUUID } from '../utils/crypto';
import { AuthenticationError } from '../types/errors.types';
import { auditLog, securityLogger } from '../utils';
import { hashPassword } from '../password/utils';
import type {
  JwtManagerConfig,
  LoginCredentials,
  LoginResult,
  RefreshTokenRequest,
  LogoutRequest,
  IUserRepository,
  ISessionRepository,
  AuthenticatedUser,
  JwtPayload,
  AuthTokens,
  RegistrationData,
  RegistrationResult,
} from './types';

/**
 * Main Authentication Service
 *
 * Provides comprehensive authentication functionality including:
 * - User login with credential validation
 * - Token refresh and management
 * - Secure logout with token blacklisting
 * - Access token validation
 * - Session management
 * - Security audit logging
 *
 * @example
 * ```typescript
 * const authService = new AuthService(
 *   jwtConfig,
 *   userRepository,
 *   sessionRepository
 * );
 *
 * // User login
 * const loginResult = await authService.login({
 *   email: 'user@example.com',
 *   password: 'securePassword123',
 *   deviceInfo: { userAgent: req.headers['user-agent'] }
 * });
 *
 * // Refresh tokens
 * const refreshResult = await authService.refresh({
 *   refreshToken: 'valid_refresh_token',
 *   deviceInfo: { userAgent: req.headers['user-agent'] }
 * });
 *
 * // Validate access token
 * const user = await authService.validateAccessToken('access_token');
 *
 * // Logout
 * await authService.logout({
 *   refreshToken: 'refresh_token',
 *   logoutAllDevices: false
 * });
 * ```
 */
export class AuthService {
  private jwtManager: JwtManager;
  private blacklistManager: TokenBlacklistManager;
  private registrationService: RegistrationService;
  private passwordResetService: PasswordResetService;

  /**
   * Initialize Authentication Service with required dependencies
   *
   * @param config - JWT configuration for token management
   * @param userRepo - User repository for authentication and user data
   * @param sessionRepo - Session repository for session management
   * @param registrationConfig - Optional registration configuration
   * @param passwordResetConfig - Optional password reset configuration
   */
  constructor(
    config: JwtManagerConfig,
    private userRepo: IUserRepository,
    private sessionRepo: ISessionRepository,
    registrationConfig: RegistrationServiceConfig = {},
    passwordResetConfig: PasswordResetServiceConfig = {}
  ) {
    this.jwtManager = new JwtManager(config);
    this.blacklistManager = new TokenBlacklistManager(sessionRepo);
    this.registrationService = new RegistrationService(userRepo, registrationConfig);
    this.passwordResetService = new PasswordResetService(userRepo, sessionRepo, passwordResetConfig);

    securityLogger.info('AuthService initialized', {
      hasJwtManager: !!this.jwtManager,
      hasBlacklistManager: !!this.blacklistManager,
      hasRegistrationService: !!this.registrationService,
      hasPasswordResetService: !!this.passwordResetService,
      hasUserRepo: !!this.userRepo,
      hasSessionRepo: !!this.sessionRepo,
      jwtConfig: {
        algorithm: config.algorithm,
        expiresIn: config.expiresIn,
        refreshExpiresIn: config.refreshExpiresIn,
        hasSecret: !!config.secret,
        hasIssuer: !!config.issuer,
        hasAudience: !!config.audience,
      },
    });
  }

  /**
   * Authenticate user with email and password
   *
   * Validates user credentials, checks account status, generates session and tokens,
   * and logs authentication events for security monitoring.
   *
   * @param credentials - User login credentials with optional device information
   * @returns Promise resolving to login result with user data and tokens
   * @throws {AuthenticationError} When credentials are invalid or account has issues
   */
  async login(credentials: LoginCredentials): Promise<LoginResult> {
    const { email, password, deviceInfo } = credentials;

    try {
      securityLogger.info('Login attempt started', {
        email,
        hasDeviceInfo: !!deviceInfo,
        userAgent: deviceInfo?.userAgent,
        ipAddress: deviceInfo?.ipAddress,
      });

      // Validate credentials format
      if (!email || !password) {
        auditLog('login_failed', { 
          email, 
          reason: 'missing_credentials', 
          deviceInfo 
        });
        throw new AuthenticationError('Email and password are required');
      }

      // Find user by email
      const user = await this.userRepo.findByEmail(email);
      if (!user) {
        auditLog('login_failed', { 
          email, 
          reason: 'user_not_found', 
          deviceInfo 
        });
        
        securityLogger.warn('Login failed - user not found', {
          email,
          deviceInfo,
        });
        
        throw new AuthenticationError('Invalid credentials');
      }

      // Validate password
      const isPasswordValid = await this.userRepo.validatePassword(email, password);
      if (!isPasswordValid) {
        auditLog('login_failed', { 
          userId: user.id, 
          email,
          reason: 'invalid_password', 
          deviceInfo 
        });
        
        securityLogger.warn('Login failed - invalid password', {
          userId: user.id,
          email,
          deviceInfo,
        });
        
        throw new AuthenticationError('Invalid credentials');
      }

      // Generate session and tokens
      const sessionId = generateSecureUUID();
      const tokens = await this.jwtManager.generateTokens({
        userId: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        sessionId,
      });

      // Store session in repository
      await this.sessionRepo.createSession(user.id, tokens.refreshToken, deviceInfo);

      // Update user's last login timestamp
      await this.userRepo.updateLastLogin(user.id);

      // Create authenticated user object
      const authenticatedUser: AuthenticatedUser = {
        id: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        sessionId,
        lastLoginAt: new Date(),
      };

      // Determine if this is the user's first login
      const isFirstLogin = !user.lastLoginAt || 
        Math.abs(new Date().getTime() - user.lastLoginAt.getTime()) < 5000; // Within 5 seconds

      const loginResult: LoginResult = {
        user: authenticatedUser,
        tokens,
        isFirstLogin,
      };

      // Log successful login
      auditLog('login_success', {
        userId: user.id,
        email: user.email,
        sessionId,
        deviceInfo,
        isFirstLogin,
        tokenExpiresAt: tokens.expiresAt.toISOString(),
        roles: user.roles,
        permissions: user.permissions,
      });

      securityLogger.info('Login successful', {
        userId: user.id,
        email: user.email,
        sessionId,
        isFirstLogin,
        roles: user.roles,
        permissionsCount: user.permissions.length,
        deviceInfo,
      });

      return loginResult;

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      // Log unexpected errors
      securityLogger.error('Unexpected error during login', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        deviceInfo,
      });

      auditLog('login_error', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
        deviceInfo,
      });

      throw new AuthenticationError('Login failed due to system error');
    }
  }

  /**
   * Refresh access token using valid refresh token
   *
   * Validates refresh token, checks if it's blacklisted, generates new token pair,
   * and updates session information. Implements proper token rotation for security.
   *
   * @param request - Refresh token request with device information
   * @returns Promise resolving to new authentication tokens
   * @throws {AuthenticationError} When refresh token is invalid or expired
   */
  async refresh(request: RefreshTokenRequest): Promise<AuthTokens> {
    const { refreshToken, deviceInfo } = request;

    try {
      securityLogger.info('Token refresh attempt started', {
        hasRefreshToken: !!refreshToken,
        hasDeviceInfo: !!deviceInfo,
        userAgent: deviceInfo?.userAgent,
        ipAddress: deviceInfo?.ipAddress,
      });

      // Validate refresh token format
      if (!refreshToken) {
        throw new AuthenticationError('Refresh token is required');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.blacklistManager.isTokenBlacklisted(refreshToken);
      if (isBlacklisted) {
        auditLog('token_refresh_failed', {
          reason: 'token_blacklisted',
          deviceInfo,
        });
        
        securityLogger.warn('Refresh failed - token is blacklisted', {
          deviceInfo,
        });
        
        throw new AuthenticationError('Refresh token is invalid');
      }

      // Verify and decode refresh token
      const refreshPayload = this.jwtManager.verifyRefreshToken(refreshToken);
      const userId = refreshPayload.sub;

      // Get current user data to ensure account is still valid
      const user = await this.userRepo.findById(userId);
      if (!user) {
        auditLog('token_refresh_failed', {
          userId,
          reason: 'user_not_found',
          deviceInfo,
        });
        
        securityLogger.warn('Refresh failed - user not found', {
          userId,
          deviceInfo,
        });
        
        throw new AuthenticationError('User account not found');
      }

      // Generate new token pair using current user data
      const tokens = await this.jwtManager.generateTokens({
        userId: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        sessionId: user.sessionId,
      });

      // Update session with new refresh token (if repository supports it)
      if (this.sessionRepo.updateSessionToken) {
        await this.sessionRepo.updateSessionToken(user.sessionId, tokens.refreshToken);
      }

      // Blacklist the old refresh token to prevent reuse
      await this.blacklistManager.blacklistToken(refreshToken, new Date(Date.now() + 24 * 60 * 60 * 1000));

      // Log successful token refresh
      auditLog('token_refresh_success', {
        userId: user.id,
        sessionId: user.sessionId,
        deviceInfo,
        newTokenExpiresAt: tokens.expiresAt.toISOString(),
      });

      securityLogger.info('Token refresh successful', {
        userId: user.id,
        sessionId: user.sessionId,
        deviceInfo,
        newAccessTokenExists: !!tokens.accessToken,
        newRefreshTokenExists: !!tokens.refreshToken,
      });

      return tokens;

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      // Log unexpected errors
      securityLogger.error('Unexpected error during token refresh', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        deviceInfo,
      });

      auditLog('token_refresh_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        deviceInfo,
      });

      throw new AuthenticationError('Token refresh failed due to system error');
    }
  }

  /**
   * Logout user and invalidate tokens
   *
   * Revokes user session(s), blacklists refresh token, and logs logout event.
   * Supports both single device logout and logout from all devices.
   *
   * @param request - Logout request with optional refresh token and logout options
   * @returns Promise resolving when logout is complete
   */
  async logout(request: LogoutRequest): Promise<void> {
    const { refreshToken, logoutAllDevices = false } = request;

    try {
      securityLogger.info('Logout attempt started', {
        hasRefreshToken: !!refreshToken,
        logoutAllDevices,
      });

      let userId: string | undefined;
      let sessionId: string | undefined;

      // If refresh token is provided, extract user information
      if (refreshToken) {
        try {
          const payload = this.jwtManager.verifyRefreshToken(refreshToken);
          userId = payload.sub;

          // Get session ID from token payload if available
          const fullPayload = this.jwtManager.verifyAccessToken(refreshToken) as JwtPayload;
          sessionId = fullPayload.sessionId;

          // Blacklist the refresh token
          await this.blacklistManager.blacklistToken(
            refreshToken, 
            new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
          );

          securityLogger.info('Refresh token blacklisted during logout', {
            userId,
            sessionId,
          });

        } catch (error) {
          // Token might be expired or invalid, but we still want to proceed with logout
          securityLogger.warn('Invalid refresh token during logout', {
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      // Revoke sessions
      if (userId) {
        if (logoutAllDevices) {
          // Revoke all user sessions
          await this.sessionRepo.revokeAllUserSessions(userId);
          
          auditLog('logout_all_devices', {
            userId,
            sessionId,
          });
          
          securityLogger.info('All user sessions revoked', {
            userId,
          });
        } else if (sessionId) {
          // Revoke specific session
          await this.sessionRepo.revokeSession(sessionId);
          
          auditLog('logout_single_device', {
            userId,
            sessionId,
          });
          
          securityLogger.info('Single session revoked', {
            userId,
            sessionId,
          });
        }
      }

      // Log successful logout
      auditLog('logout_success', {
        userId,
        sessionId,
        logoutAllDevices,
        hadRefreshToken: !!refreshToken,
      });

      securityLogger.info('Logout successful', {
        userId,
        sessionId,
        logoutAllDevices,
      });

    } catch (error) {
      // Log logout errors but don't throw - logout should be tolerant
      securityLogger.error('Error during logout', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        logoutAllDevices,
        hadRefreshToken: !!refreshToken,
      });

      auditLog('logout_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        logoutAllDevices,
        hadRefreshToken: !!refreshToken,
      });

      // Don't throw errors during logout - it should be tolerant of failures
    }
  }

  /**
   * Validate access token and return authenticated user
   *
   * Verifies JWT access token, checks if it's blacklisted, and returns user information.
   * Used by authentication middleware to validate requests.
   *
   * @param accessToken - JWT access token to validate
   * @returns Promise resolving to authenticated user information
   * @throws {AuthenticationError} When token is invalid, expired, or blacklisted
   */
  async validateAccessToken(accessToken: string): Promise<AuthenticatedUser> {
    try {
      securityLogger.debug('Access token validation started', {
        hasToken: !!accessToken,
      });

      // Validate token format
      if (!accessToken) {
        throw new AuthenticationError('Access token is required');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.blacklistManager.isTokenBlacklisted(accessToken);
      if (isBlacklisted) {
        securityLogger.warn('Access token validation failed - token is blacklisted');
        throw new AuthenticationError('Access token is invalid');
      }

      // Verify and decode access token
      const payload = this.jwtManager.verifyAccessToken(accessToken);

      // Get current user data to ensure account is still valid
      const user = await this.userRepo.findById(payload.sub);
      if (!user) {
        securityLogger.warn('Access token validation failed - user not found', {
          userId: payload.sub,
        });
        throw new AuthenticationError('User account not found');
      }

      // Create authenticated user object
      const authenticatedUser: AuthenticatedUser = {
        id: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        sessionId: payload.sessionId || generateSecureUUID(),
        lastLoginAt: user.lastLoginAt,
      };

      securityLogger.debug('Access token validation successful', {
        userId: user.id,
        sessionId: authenticatedUser.sessionId,
        roles: user.roles,
        permissionsCount: user.permissions.length,
      });

      return authenticatedUser;

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      // Log unexpected errors
      securityLogger.error('Unexpected error during access token validation', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw new AuthenticationError('Token validation failed due to system error');
    }
  }

  /**
   * Register a new user account
   *
   * Handles user registration with comprehensive validation, security checks,
   * and optional email verification setup.
   *
   * @param data - User registration data
   * @returns Promise resolving to registration result with user data
   * @throws {AuthenticationError} When registration fails due to validation or system errors
   */
  async register(data: RegistrationData): Promise<RegistrationResult> {
    return await this.registrationService.registerUser(data);
  }

  /**
   * Initiate email verification process for a user
   *
   * Generates verification token and sets up email verification workflow.
   *
   * @param userId - User ID for verification
   * @returns Promise resolving to verification token
   */
  async initiateEmailVerification(userId: string): Promise<string> {
    return await this.registrationService.initiateEmailVerification(userId);
  }

  /**
   * Verify user email with verification token
   *
   * Validates verification token and marks user email as verified.
   *
   * @param userId - User ID to verify
   * @param token - Verification token
   * @returns Promise resolving to verification success status
   */
  async verifyEmail(userId: string, token: string): Promise<boolean> {
    return await this.registrationService.verifyEmail(userId, token);
  }

  /**
   * Resend email verification for user
   *
   * Safely handles verification email resending without revealing user existence.
   *
   * @param email - Email address for verification resend
   * @returns Promise resolving to operation success status
   */
  async resendVerificationEmail(email: string): Promise<boolean> {
    return await this.registrationService.resendVerificationEmail(email);
  }

  // Password reset methods
  async initiatePasswordReset(request: PasswordResetRequest): Promise<boolean> {
    return await this.passwordResetService.initiatePasswordReset(request);
  }

  async confirmPasswordReset(confirm: PasswordResetConfirm): Promise<boolean> {
    return await this.passwordResetService.confirmPasswordReset(confirm);
  }

  async validateResetToken(token: string): Promise<boolean> {
    return await this.passwordResetService.validateResetToken(token);
  }

  /**
   * Get active sessions for a user
   *
   * Retrieves list of active sessions for security monitoring and management.
   *
   * @param userId - User ID to get sessions for
   * @returns Promise resolving to list of active sessions
   */
  async getUserActiveSessions(userId: string): Promise<Array<{
    sessionId: string;
    deviceInfo?: unknown;
    createdAt: Date;
    lastAccessedAt: Date;
  }>> {
    if (this.sessionRepo.getUserActiveSessions) {
      return await this.sessionRepo.getUserActiveSessions(userId);
    }
    return [];
  }

  /**
   * Revoke a specific user session
   *
   * Revokes a specific session and logs the security event.
   *
   * @param userId - User ID owning the session
   * @param sessionId - Session ID to revoke
   * @returns Promise resolving when session is revoked
   */
  async revokeUserSession(userId: string, sessionId: string): Promise<void> {
    await this.sessionRepo.revokeSession(sessionId);
    
    auditLog('session_revoked', {
      userId,
      sessionId,
      revokedBy: 'user',
    });

    securityLogger.info('User session revoked', {
      userId,
      sessionId,
    });
  }

  /**
   * Get JWT Manager instance for advanced token operations
   * 
   * @returns JWT Manager instance
   */
  getJwtManager(): JwtManager {
    return this.jwtManager;
  }

  /**
   * Get Token Blacklist Manager instance for advanced blacklist operations
   * 
   * @returns Token Blacklist Manager instance
   */
  getBlacklistManager(): TokenBlacklistManager {
    return this.blacklistManager;
  }

  /**
   * Change user password
   *
   * Changes the password for an authenticated user after verifying their current password.
   *
   * @param userId - User ID whose password should be changed
   * @param currentPassword - Current password for verification
   * @param newPassword - New password to set
   * @returns Promise resolving when password is changed
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
    // Find user by ID
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AuthenticationError('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.userRepo.validatePassword(user.email, currentPassword);
    if (!isCurrentPasswordValid) {
      auditLog('password_change_failed', {
        userId,
        reason: 'invalid_current_password',
      });

      securityLogger.warn('Password change failed - invalid current password', {
        userId,
        email: user.email,
      });

      throw new AuthenticationError('Current password is invalid');
    }

    // Hash new password
    const hashedNewPassword = await hashPassword(newPassword);

    // Update password in repository (assuming the userRepo has an updatePassword method)
    // Note: This would need to be implemented in the actual repository
    if (this.userRepo.updatePassword) {
      await this.userRepo.updatePassword(userId, hashedNewPassword);
    } else {
      throw new Error('Password update functionality not available in user repository');
    }

    // Log successful password change
    auditLog('password_change_success', {
      userId,
      email: user.email,
    });

    securityLogger.info('Password changed successfully', {
      userId,
      email: user.email,
    });

    // Optionally revoke all user sessions for security
    // This forces the user to log in again with the new password
    await this.sessionRepo.revokeAllUserSessions(userId);
  }
}

/**
 * Create AuthService instance with validated configuration
 *
 * @param config - JWT configuration
 * @param userRepo - User repository implementation
 * @param sessionRepo - Session repository implementation
 * @param registrationConfig - Optional registration configuration
 * @returns Configured AuthService instance
 *
 * @example
 * ```typescript
 * const authService = createAuthService(
 *   {
 *     secret: process.env.JWT_SECRET!,
 *     expiresIn: '15m',
 *     refreshExpiresIn: '7d',
 *     algorithm: 'HS256',
 *     issuer: 'agenda-bella',
 *     audience: 'api'
 *   },
 *   userRepository,
 *   sessionRepository,
 *   {
 *     requireEmailVerification: true,
 *     defaultRoles: ['user'],
 *     allowedRoles: ['user', 'customer']
 *   }
 * );
 * ```
 */
export const createAuthService = (
  config: JwtManagerConfig,
  userRepo: IUserRepository,
  sessionRepo: ISessionRepository,
  registrationConfig: RegistrationServiceConfig = {},
  passwordResetConfig: PasswordResetServiceConfig = {}
): AuthService => {
  return new AuthService(config, userRepo, sessionRepo, registrationConfig, passwordResetConfig);
};