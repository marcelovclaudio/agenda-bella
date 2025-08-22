/**
 * Password Reset Service
 *
 * This module provides secure password reset functionality with token-based validation,
 * rate limiting, audit logging, and protection against email enumeration attacks.
 *
 * Security features:
 * - Email enumeration prevention (always returns success)
 * - Timing attack protection with random delays
 * - Secure token generation and expiration
 * - Rate limiting and abuse prevention
 * - Comprehensive audit logging
 * - Session revocation on password reset
 *
 * @packageDocumentation
 */

import { generateSecureUUID } from '../utils/crypto';
import { isValidPassword } from '../utils/validation';
import { hashPassword } from '../password/utils';
import { AuthenticationError } from '../types/errors.types';
import { auditLog, securityLogger } from '../utils';
import type { IUserRepository, ISessionRepository } from './types';

/**
 * Password reset initiation request interface
 * Contains email and optional security context information
 */
export interface PasswordResetRequest {
  /** User email address */
  email: string;
  /** Client IP address for security logging */
  ipAddress?: string;
  /** User agent string for security logging */
  userAgent?: string;
}

/**
 * Password reset confirmation request interface
 * Contains token and new password information
 */
export interface PasswordResetConfirm {
  /** Reset token received via email */
  token: string;
  /** New password to set */
  newPassword: string;
  /** Confirmation of new password */
  confirmPassword: string;
}

/**
 * Password reset token data interface
 * Internal structure for storing reset token information
 */
interface PasswordResetTokenData {
  /** User ID associated with the token */
  userId: string;
  /** User email address */
  email: string;
  /** When the token expires */
  expiresAt: Date;
  /** Whether the token has been used */
  used: boolean;
  /** When the token was created */
  createdAt: Date;
  /** Client information when token was requested */
  clientInfo?: {
    ipAddress?: string;
    userAgent?: string;
  };
}

/**
 * Password Reset Service configuration interface
 */
export interface PasswordResetServiceConfig {
  /** Token expiration time in minutes (default: 30) */
  tokenExpirationMinutes?: number;
  /** Whether to revoke all user sessions on password reset (default: true) */
  revokeSessionsOnReset?: boolean;
  /** Maximum reset attempts per hour per email (default: 5) */
  maxAttemptsPerHour?: number;
  /** Cooldown period in minutes after max attempts (default: 60) */
  cooldownMinutes?: number;
}

/**
 * Password Reset Service
 *
 * Provides secure password reset functionality with comprehensive security measures.
 * Implements email enumeration protection, timing attack prevention, rate limiting,
 * and comprehensive audit logging.
 *
 * @example
 * ```typescript
 * const passwordResetService = new PasswordResetService(
 *   userRepository,
 *   sessionRepository,
 *   {
 *     tokenExpirationMinutes: 30,
 *     revokeSessionsOnReset: true,
 *     maxAttemptsPerHour: 5
 *   }
 * );
 *
 * // Initiate password reset
 * const success = await passwordResetService.initiatePasswordReset({
 *   email: 'user@example.com',
 *   ipAddress: '192.168.1.1',
 *   userAgent: 'Mozilla/5.0...'
 * });
 *
 * // Confirm password reset
 * const resetSuccess = await passwordResetService.confirmPasswordReset({
 *   token: 'reset-token',
 *   newPassword: 'NewSecurePass123!',
 *   confirmPassword: 'NewSecurePass123!'
 * });
 * ```
 */
export class PasswordResetService {
  /** In-memory storage for reset tokens (in production, use Redis or database) */
  private resetTokens = new Map<string, PasswordResetTokenData>();
  
  /** Rate limiting tracking per email */
  private rateLimitTracker = new Map<string, { count: number; resetTime: Date }>();

  /** Default configuration values */
  private readonly defaultConfig: Required<PasswordResetServiceConfig> = {
    tokenExpirationMinutes: 30,
    revokeSessionsOnReset: true,
    maxAttemptsPerHour: 5,
    cooldownMinutes: 60,
  };

  /** Service configuration */
  private readonly config: Required<PasswordResetServiceConfig>;

  /**
   * Initialize the Password Reset Service
   *
   * @param userRepo - User repository for database operations
   * @param sessionRepo - Session repository for session management
   * @param config - Service configuration options
   */
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly sessionRepo: ISessionRepository,
    config: PasswordResetServiceConfig = {}
  ) {
    this.config = { ...this.defaultConfig, ...config };
    
    securityLogger.info('Password Reset Service initialized', {
      tokenExpirationMinutes: this.config.tokenExpirationMinutes,
      revokeSessionsOnReset: this.config.revokeSessionsOnReset,
      maxAttemptsPerHour: this.config.maxAttemptsPerHour,
      cooldownMinutes: this.config.cooldownMinutes,
    });
  }

  /**
   * Initiate password reset process
   *
   * Always returns true to prevent email enumeration attacks.
   * Only sends actual reset email if user exists in the system.
   * Implements rate limiting and timing attack protection.
   *
   * @param request - Password reset request with email and optional context
   * @returns Promise resolving to true (always, for security)
   *
   * @security
   * - Email enumeration prevention: Always returns true
   * - Timing attack protection: Random delays for non-existent users
   * - Rate limiting: Limits attempts per email address
   * - Audit logging: All attempts are logged
   */
  async initiatePasswordReset(request: PasswordResetRequest): Promise<boolean> {
    const { email, ipAddress, userAgent } = request;
    const startTime = Date.now();

    try {
      // Check rate limiting first
      if (this.isRateLimited(email)) {
        auditLog('password_reset_rate_limited', {
          email,
          ipAddress,
          userAgent,
          reason: 'too_many_attempts',
        });
        
        // Still return true to prevent enumeration
        await this.addTimingDelay(startTime);
        return true;
      }

      // Track this attempt for rate limiting
      this.trackResetAttempt(email);

      // Look up user (this is the only place we differentiate)
      const user = await this.userRepo.findByEmail(email);
      
      auditLog('password_reset_requested', {
        email,
        userExists: !!user,
        ipAddress,
        userAgent,
        timestamp: new Date().toISOString(),
      });

      if (!user) {
        securityLogger.debug('Password reset requested for non-existent user', {
          email,
          ipAddress,
          userAgent,
        });
        
        // Add random delay to prevent timing attacks
        await this.addTimingDelay(startTime, true);
        return true;
      }

      // Generate reset token
      const token = generateSecureUUID();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + this.config.tokenExpirationMinutes);

      // Store reset token
      this.resetTokens.set(token, {
        userId: user.id,
        email: user.email,
        expiresAt,
        used: false,
        createdAt: new Date(),
        clientInfo: {
          ...(ipAddress && { ipAddress }),
          ...(userAgent && { userAgent }),
        },
      });

      securityLogger.info('Password reset token generated', {
        userId: user.id,
        email: user.email,
        tokenId: token.substring(0, 8) + '...', // Only log first 8 chars for security
        expiresAt: expiresAt.toISOString(),
        ipAddress,
        userAgent,
      });

      // TODO: In a real implementation, send email with reset link here
      // await this.emailService.sendPasswordResetEmail(user.email, token);

      await this.addTimingDelay(startTime);
      return true;

    } catch (error) {
      securityLogger.error('Password reset initiation failed', {
        email,
        ipAddress,
        userAgent,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      // Even on error, return true to prevent enumeration
      await this.addTimingDelay(startTime);
      return true;
    }
  }

  /**
   * Confirm password reset with token and new password
   *
   * Validates the token, password requirements, and updates the user's password.
   * Optionally revokes all user sessions for security.
   *
   * @param confirm - Password reset confirmation with token and new password
   * @returns Promise resolving to true if reset was successful
   *
   * @throws {AuthenticationError} When token is invalid, expired, or already used
   * @throws {AuthenticationError} When passwords don't match or are invalid
   *
   * @security
   * - Token validation with expiration checking
   * - Password strength validation
   * - Session revocation option
   * - Token cleanup after use
   */
  async confirmPasswordReset(confirm: PasswordResetConfirm): Promise<boolean> {
    const { token, newPassword, confirmPassword } = confirm;

    try {
      // Validate passwords match
      if (newPassword !== confirmPassword) {
        throw new AuthenticationError('Password confirmation does not match', undefined, {
          code: 'PASSWORD_MISMATCH',
        });
      }

      // Validate password strength
      if (!isValidPassword(newPassword)) {
        throw new AuthenticationError('Password does not meet security requirements', undefined, {
          code: 'WEAK_PASSWORD',
        });
      }

      // Validate token
      const resetData = this.resetTokens.get(token);
      
      if (!resetData) {
        auditLog('password_reset_invalid_token', {
          token: token.substring(0, 8) + '...',
          reason: 'token_not_found',
        });
        throw new AuthenticationError('Invalid or expired reset token', undefined, {
          code: 'INVALID_RESET_TOKEN',
        });
      }

      if (resetData.used) {
        auditLog('password_reset_token_reuse', {
          userId: resetData.userId,
          email: resetData.email,
          token: token.substring(0, 8) + '...',
          originalCreatedAt: resetData.createdAt.toISOString(),
        });
        throw new AuthenticationError('Reset token has already been used', undefined, {
          code: 'TOKEN_ALREADY_USED',
        });
      }

      if (resetData.expiresAt <= new Date()) {
        auditLog('password_reset_token_expired', {
          userId: resetData.userId,
          email: resetData.email,
          token: token.substring(0, 8) + '...',
          expiresAt: resetData.expiresAt.toISOString(),
        });
        
        // Clean up expired token
        this.resetTokens.delete(token);
        
        throw new AuthenticationError('Reset token has expired', undefined, {
          code: 'TOKEN_EXPIRED',
        });
      }

      // Get user to update password
      const user = await this.userRepo.findById(resetData.userId);
      if (!user) {
        securityLogger.error('User not found during password reset confirmation', {
          userId: resetData.userId,
          email: resetData.email,
        });
        throw new AuthenticationError('User not found', undefined, {
          code: 'USER_NOT_FOUND',
        });
      }

      // Hash and update password in database
      const hashedPassword = await hashPassword(newPassword);
      
      if (this.userRepo.updatePassword) {
        await this.userRepo.updatePassword(user.id, hashedPassword);
      } else {
        throw new AuthenticationError('Password update functionality not available in user repository', undefined, {
          code: 'UPDATE_NOT_SUPPORTED',
        });
      }
      
      // Mark token as used
      resetData.used = true;
      
      // Revoke user sessions if configured
      if (this.config.revokeSessionsOnReset) {
        await this.sessionRepo.revokeAllUserSessions(user.id);
        
        auditLog('password_reset_sessions_revoked', {
          userId: user.id,
          email: user.email,
          reason: 'password_reset',
        });
      }

      auditLog('password_reset_confirmed', {
        userId: user.id,
        email: user.email,
        token: token.substring(0, 8) + '...',
        sessionsRevoked: this.config.revokeSessionsOnReset,
        timestamp: new Date().toISOString(),
      });

      securityLogger.info('Password reset completed successfully', {
        userId: user.id,
        email: user.email,
        sessionsRevoked: this.config.revokeSessionsOnReset,
      });

      // Clean up used token after a short delay (for audit purposes)
      setTimeout(() => {
        this.resetTokens.delete(token);
      }, 60000); // 1 minute delay

      return true;

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      securityLogger.error('Password reset confirmation failed', {
        token: token.substring(0, 8) + '...',
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw new AuthenticationError('Password reset failed', undefined, {
        code: 'RESET_FAILED',
      }, error instanceof Error ? error : undefined);
    }
  }

  /**
   * Validate if a reset token is valid and not expired
   *
   * @param token - Reset token to validate
   * @returns Promise resolving to true if token is valid
   */
  async validateResetToken(token: string): Promise<boolean> {
    try {
      const resetData = this.resetTokens.get(token);
      
      if (!resetData || resetData.used || resetData.expiresAt <= new Date()) {
        return Promise.resolve(false);
      }

      return Promise.resolve(true);
    } catch (error) {
      securityLogger.error('Token validation failed', {
        token: token.substring(0, 8) + '...',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return Promise.resolve(false);
    }
  }

  /**
   * Clean up expired reset tokens
   *
   * This method should be called periodically to remove expired tokens
   * and prevent memory leaks in production environments.
   *
   * @returns Promise resolving to the number of tokens cleaned up
   */
  async cleanupExpiredTokens(): Promise<number> {
    try {
      const now = new Date();
      let cleanupCount = 0;

      for (const [token, data] of this.resetTokens.entries()) {
        if (data.expiresAt <= now || data.used) {
          this.resetTokens.delete(token);
          cleanupCount++;
        }
      }

      if (cleanupCount > 0) {
        securityLogger.debug('Cleaned up expired reset tokens', { 
          cleanupCount,
          timestamp: now.toISOString(),
        });
      }

      return Promise.resolve(cleanupCount);
    } catch (error) {
      securityLogger.error('Token cleanup failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return Promise.resolve(0);
    }
  }

  /**
   * Revoke a specific reset token (useful for security)
   *
   * @param token - Reset token to revoke
   * @returns Promise resolving to true if token was found and revoked
   */
  async revokeResetToken(token: string): Promise<boolean> {
    try {
      const resetData = this.resetTokens.get(token);
      
      if (!resetData) {
        return Promise.resolve(false);
      }

      auditLog('password_reset_token_revoked', {
        userId: resetData.userId,
        email: resetData.email,
        token: token.substring(0, 8) + '...',
        reason: 'manual_revocation',
      });

      this.resetTokens.delete(token);
      
      securityLogger.info('Reset token revoked', {
        userId: resetData.userId,
        email: resetData.email,
        token: token.substring(0, 8) + '...',
      });

      return Promise.resolve(true);
    } catch (error) {
      securityLogger.error('Token revocation failed', {
        token: token.substring(0, 8) + '...',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return Promise.resolve(false);
    }
  }

  /**
   * Get statistics about current reset tokens (for monitoring)
   *
   * @returns Object with token statistics
   */
  getTokenStatistics(): {
    totalTokens: number;
    activeTokens: number;
    expiredTokens: number;
    usedTokens: number;
  } {
    const now = new Date();
    let activeTokens = 0;
    let expiredTokens = 0;
    let usedTokens = 0;

    for (const data of this.resetTokens.values()) {
      if (data.used) {
        usedTokens++;
      } else if (data.expiresAt <= now) {
        expiredTokens++;
      } else {
        activeTokens++;
      }
    }

    return {
      totalTokens: this.resetTokens.size,
      activeTokens,
      expiredTokens,
      usedTokens,
    };
  }

  /**
   * Check if an email is rate limited for password resets
   *
   * @param email - Email address to check
   * @returns True if the email is currently rate limited
   */
  private isRateLimited(email: string): boolean {
    const now = new Date();
    const rateLimitData = this.rateLimitTracker.get(email);

    if (!rateLimitData) {
      return false;
    }

    // Reset count if cooldown period has passed
    if (now >= rateLimitData.resetTime) {
      this.rateLimitTracker.delete(email);
      return false;
    }

    return rateLimitData.count >= this.config.maxAttemptsPerHour;
  }

  /**
   * Track a password reset attempt for rate limiting
   *
   * @param email - Email address to track
   */
  private trackResetAttempt(email: string): void {
    const now = new Date();
    const resetTime = new Date(now.getTime() + (this.config.cooldownMinutes * 60 * 1000));
    const rateLimitData = this.rateLimitTracker.get(email);

    if (!rateLimitData || now >= rateLimitData.resetTime) {
      // Start new tracking window
      this.rateLimitTracker.set(email, {
        count: 1,
        resetTime,
      });
    } else {
      // Increment existing count
      rateLimitData.count++;
    }
  }

  /**
   * Add timing delay to prevent timing attacks
   *
   * @param startTime - When the operation started
   * @param isNonExistentUser - Whether this is for a non-existent user (adds random delay)
   */
  private async addTimingDelay(startTime: number, isNonExistentUser: boolean = false): Promise<void> {
    const elapsed = Date.now() - startTime;
    const baseDelay = 100; // Minimum 100ms delay
    const randomDelay = isNonExistentUser ? Math.random() * 200 : 0; // 0-200ms random for non-existent users
    const totalDelay = baseDelay + randomDelay;
    
    if (elapsed < totalDelay) {
      await new Promise(resolve => setTimeout(resolve, totalDelay - elapsed));
    }
  }
}

/**
 * Factory function to create a Password Reset Service instance
 *
 * @param userRepo - User repository implementation
 * @param sessionRepo - Session repository implementation
 * @param config - Service configuration options
 * @returns Configured PasswordResetService instance
 *
 * @example
 * ```typescript
 * const passwordResetService = createPasswordResetService(
 *   userRepository,
 *   sessionRepository,
 *   {
 *     tokenExpirationMinutes: 15, // Shorter expiration for high security
 *     maxAttemptsPerHour: 3,      // Stricter rate limiting
 *   }
 * );
 * ```
 */
export function createPasswordResetService(
  userRepo: IUserRepository,
  sessionRepo: ISessionRepository,
  config?: PasswordResetServiceConfig
): PasswordResetService {
  return new PasswordResetService(userRepo, sessionRepo, config);
}

/**
 * Default export for the PasswordResetService class
 */
export default PasswordResetService;