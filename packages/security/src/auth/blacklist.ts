/**
 * Token Blacklist System
 *
 * This module provides comprehensive token blacklisting functionality for JWT tokens
 * with secure storage, automatic cleanup, and audit logging following security best practices.
 *
 * Key features:
 * - Integration with ISessionRepository for persistent storage
 * - In-memory fallback implementation for development
 * - Automatic cleanup of expired tokens
 * - Comprehensive audit logging
 * - Secure token hashing for logging purposes
 *
 * @packageDocumentation
 */

import { createChildLogger, auditLog, logSecurityError } from '../utils';
import { AuthenticationError } from '../types';
import type { ISessionRepository } from './types';
import type { SecurityContext } from '../types';

const logger = createChildLogger({ 
  component: 'token-blacklist',
  package: '@agenda-bella/security'
});

/**
 * Token Blacklist Manager class
 *
 * Manages token blacklisting with integration to session repository.
 * Provides secure token invalidation with proper audit trails and logging.
 *
 * @example
 * ```typescript
 * const blacklistManager = new TokenBlacklistManager(sessionRepository);
 * 
 * // Blacklist a token
 * await blacklistManager.blacklistToken('token123', new Date('2024-12-31'));
 * 
 * // Check if token is blacklisted
 * const isBlacklisted = await blacklistManager.isTokenBlacklisted('token123');
 * ```
 */
export class TokenBlacklistManager {
  /**
   * Initialize Token Blacklist Manager
   *
   * @param sessionRepo - Session repository implementing blacklist methods
   */
  constructor(private sessionRepo: ISessionRepository) {
    logger.info('TokenBlacklistManager initialized', {
      hasSessionRepo: !!sessionRepo,
      sessionRepoType: sessionRepo.constructor.name,
    });
  }

  /**
   * Add token to blacklist with expiration
   *
   * Adds the specified token to the blacklist with an expiration date.
   * The token will be considered invalid until the expiration date.
   *
   * @param token - JWT token to blacklist
   * @param expiresAt - When the blacklist entry expires
   * @param context - Security context for audit logging
   * @throws {AuthenticationError} When blacklisting fails
   */
  async blacklistToken(token: string, expiresAt: Date, context?: SecurityContext): Promise<void> {
    try {
      if (!token || typeof token !== 'string') {
        throw new AuthenticationError('Invalid token provided for blacklisting', undefined, {
          code: 'INVALID_TOKEN_FORMAT',
          provided: typeof token
        });
      }

      if (!expiresAt || !(expiresAt instanceof Date)) {
        throw new AuthenticationError('Invalid expiration date for token blacklisting', undefined, {
          code: 'INVALID_EXPIRATION_DATE',
          provided: typeof expiresAt
        });
      }

      if (expiresAt <= new Date()) {
        throw new AuthenticationError('Token expiration date must be in the future', undefined, {
          code: 'EXPIRED_EXPIRATION_DATE',
          expiresAt: expiresAt.toISOString()
        });
      }

      // Blacklist the token using session repository
      await this.sessionRepo.blacklistToken(token, expiresAt);

      // Log successful blacklisting with secure token hash
      const tokenHash = this.hashToken(token);
      
      auditLog('TOKEN_BLACKLISTED', {
        tokenHash,
        expiresAt: expiresAt.toISOString(),
        timestamp: new Date().toISOString(),
        context,
      });

      logger.info('Token blacklisted successfully', {
        tokenHash,
        expiresAt: expiresAt.toISOString(),
        hasContext: !!context,
      });

    } catch (error) {
      const errorDetails = {
        tokenHash: token ? this.hashToken(token) : 'invalid',
        expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : 'invalid',
        context,
      };

      if (error instanceof AuthenticationError) {
        logSecurityError(error, errorDetails);
        throw error;
      }

      const authError = new AuthenticationError(
        'Failed to blacklist token',
        undefined,
        {
          code: 'TOKEN_BLACKLIST_FAILED',
          originalError: error instanceof Error ? error.message : 'Unknown error',
          ...errorDetails
        }
      );

      logSecurityError(authError, errorDetails);
      throw authError;
    }
  }

  /**
   * Check if token is blacklisted
   *
   * Verifies whether the specified token is currently blacklisted.
   * Returns false for expired blacklist entries.
   *
   * @param token - JWT token to check
   * @param context - Security context for audit logging
   * @returns Promise resolving to true if token is blacklisted
   * @throws {AuthenticationError} When check fails
   */
  async isTokenBlacklisted(token: string, context?: SecurityContext): Promise<boolean> {
    try {
      if (!token || typeof token !== 'string') {
        throw new AuthenticationError('Invalid token provided for blacklist check', undefined, {
          code: 'INVALID_TOKEN_FORMAT',
          provided: typeof token
        });
      }

      const isBlacklisted = await this.sessionRepo.isTokenBlacklisted(token);

      // Log blacklist check for security monitoring
      const tokenHash = this.hashToken(token);
      
      logger.debug('Token blacklist check performed', {
        tokenHash,
        isBlacklisted,
        hasContext: !!context,
      });

      // Only audit positive results to avoid log spam
      if (isBlacklisted) {
        auditLog('TOKEN_BLACKLIST_CHECK', {
          tokenHash,
          result: 'blacklisted',
          timestamp: new Date().toISOString(),
          context,
        });
      }

      return isBlacklisted;

    } catch (error) {
      const errorDetails = {
        tokenHash: token ? this.hashToken(token) : 'invalid',
        context,
      };

      if (error instanceof AuthenticationError) {
        logSecurityError(error, errorDetails);
        throw error;
      }

      const authError = new AuthenticationError(
        'Failed to check token blacklist status',
        undefined,
        {
          code: 'TOKEN_BLACKLIST_CHECK_FAILED',
          originalError: error instanceof Error ? error.message : 'Unknown error',
          ...errorDetails
        }
      );

      logSecurityError(authError, errorDetails);
      throw authError;
    }
  }

  /**
   * Blacklist refresh token with standard expiration
   *
   * Convenience method for blacklisting refresh tokens with a default
   * expiration period (7 days) suitable for refresh token lifecycles.
   *
   * @param refreshToken - Refresh token to blacklist
   * @param context - Security context for audit logging
   * @throws {AuthenticationError} When blacklisting fails
   */
  async blacklistRefreshToken(refreshToken: string, context?: SecurityContext): Promise<void> {
    try {
      // Refresh tokens typically have longer expiration periods
      // Set blacklist expiration to 7 days to ensure security
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await this.blacklistToken(refreshToken, expiresAt, context);

      auditLog('REFRESH_TOKEN_BLACKLISTED', {
        tokenHash: this.hashToken(refreshToken),
        expiresAt: expiresAt.toISOString(),
        defaultExpiration: '7 days',
        context,
      });

      logger.info('Refresh token blacklisted with default expiration', {
        tokenHash: this.hashToken(refreshToken),
        expiresAt: expiresAt.toISOString(),
      });

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      const authError = new AuthenticationError(
        'Failed to blacklist refresh token',
        undefined,
        {
          code: 'REFRESH_TOKEN_BLACKLIST_FAILED',
          originalError: error instanceof Error ? error.message : 'Unknown error',
        }
      );

      logSecurityError(authError, { 
        tokenHash: refreshToken ? this.hashToken(refreshToken) : 'invalid',
        context 
      });
      throw authError;
    }
  }

  /**
   * Get blacklist statistics for monitoring
   *
   * Returns statistical information about the blacklist for monitoring
   * and security analysis purposes.
   *
   * @returns Promise resolving to blacklist statistics
   */
  async getBlacklistStats(): Promise<{
    totalEntries: number;
    cleanupNeeded: boolean;
    lastCleanup?: Date;
  }> {
    try {
      // This would require additional methods in ISessionRepository
      // For now, return basic stats
      logger.debug('Blacklist statistics requested');
      
      return {
        totalEntries: 0, // Would be implemented with repository support
        cleanupNeeded: false,
      };
    } catch (error) {
      logger.warn('Failed to get blacklist statistics', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        totalEntries: 0,
        cleanupNeeded: true,
      };
    }
  }

  /**
   * Hash token for secure logging
   *
   * Creates a non-reversible hash of the token for logging purposes.
   * Only returns the first 8 characters plus ellipsis for identification.
   *
   * @private
   * @param token - Token to hash
   * @returns Secure hash for logging
   */
  private hashToken(token: string): string {
    if (!token || token.length < 8) {
      return 'invalid_token';
    }

    // Return first 8 chars for identification in logs (non-sensitive)
    return token.substring(0, 8) + '...';
  }
}

/**
 * In-memory Token Blacklist implementation
 *
 * Provides a fallback implementation for development and testing environments
 * where persistent storage is not available. Includes automatic cleanup
 * of expired tokens to prevent memory leaks.
 *
 * @example
 * ```typescript
 * const memoryBlacklist = new MemoryTokenBlacklist();
 * 
 * // Use as session repository partial implementation
 * const tokenManager = new TokenBlacklistManager(memoryBlacklist);
 * ```
 */
export class MemoryTokenBlacklist implements Pick<ISessionRepository, 'blacklistToken' | 'isTokenBlacklisted'> {
  private blacklistedTokens = new Map<string, Date>();
  private cleanupInterval: NodeJS.Timeout | undefined = undefined;
  private readonly CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  /**
   * Initialize memory-based token blacklist with automatic cleanup
   */
  constructor() {
    logger.info('MemoryTokenBlacklist initialized', {
      cleanupInterval: `${this.CLEANUP_INTERVAL_MS / 1000}s`,
    });

    // Start automatic cleanup timer
    this.startPeriodicCleanup();
  }

  /**
   * Add token to in-memory blacklist
   *
   * @param token - Token to blacklist
   * @param expiresAt - When the blacklist entry expires
   */
  async blacklistToken(token: string, expiresAt: Date): Promise<void> {
    try {
      if (!token || typeof token !== 'string') {
        throw new Error('Invalid token provided');
      }

      if (!expiresAt || !(expiresAt instanceof Date)) {
        throw new Error('Invalid expiration date provided');
      }

      this.blacklistedTokens.set(token, expiresAt);

      logger.debug('Token added to memory blacklist', {
        tokenHash: token.substring(0, 8) + '...',
        expiresAt: expiresAt.toISOString(),
        totalEntries: this.blacklistedTokens.size,
      });

      // Trigger immediate cleanup if map is getting large
      if (this.blacklistedTokens.size > 1000) {
        this.cleanupExpiredTokens();
      }

    } catch (error) {
      logger.error('Failed to blacklist token in memory', {
        error: error instanceof Error ? error.message : 'Unknown error',
        tokenHash: token ? token.substring(0, 8) + '...' : 'invalid',
      });
      throw error;
    }
  }

  /**
   * Check if token exists in in-memory blacklist
   *
   * @param token - Token to check
   * @returns Promise resolving to true if token is blacklisted
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    try {
      if (!token || typeof token !== 'string') {
        return false;
      }

      const expiry = this.blacklistedTokens.get(token);
      if (!expiry) {
        return false;
      }

      // Check if token blacklist entry has expired
      if (expiry <= new Date()) {
        this.blacklistedTokens.delete(token);
        logger.debug('Expired token removed from blacklist', {
          tokenHash: token.substring(0, 8) + '...',
          expiredAt: expiry.toISOString(),
        });
        return false;
      }

      return true;

    } catch (error) {
      logger.error('Failed to check token blacklist status in memory', {
        error: error instanceof Error ? error.message : 'Unknown error',
        tokenHash: token ? token.substring(0, 8) + '...' : 'invalid',
      });
      return false;
    }
  }

  /**
   * Get current blacklist size for monitoring
   */
  getBlacklistSize(): number {
    return this.blacklistedTokens.size;
  }

  /**
   * Manually trigger cleanup of expired tokens
   */
  cleanupExpiredTokens(): number {
    const now = new Date();
    let cleanedCount = 0;

    for (const [token, expiry] of this.blacklistedTokens.entries()) {
      if (expiry <= now) {
        this.blacklistedTokens.delete(token);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.info('Expired tokens cleaned up from memory blacklist', {
        cleanedCount,
        remainingEntries: this.blacklistedTokens.size,
      });
    }

    return cleanedCount;
  }

  /**
   * Clear all blacklisted tokens (for testing)
   */
  clearAll(): void {
    const previousSize = this.blacklistedTokens.size;
    this.blacklistedTokens.clear();
    
    logger.info('All tokens cleared from memory blacklist', {
      previousSize,
    });
  }

  /**
   * Stop automatic cleanup and release resources
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }

    this.blacklistedTokens.clear();
    
    logger.info('MemoryTokenBlacklist destroyed', {
      finalSize: this.blacklistedTokens.size,
    });
  }

  /**
   * Start periodic cleanup of expired tokens
   *
   * @private
   */
  private startPeriodicCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredTokens();
    }, this.CLEANUP_INTERVAL_MS);

    logger.debug('Periodic cleanup started for memory blacklist', {
      intervalMs: this.CLEANUP_INTERVAL_MS,
    });
  }
}

/**
 * Create a production-ready token blacklist manager
 *
 * Factory function to create a token blacklist manager with proper
 * repository integration and configuration validation.
 *
 * @param sessionRepo - Session repository implementing blacklist methods
 * @returns Configured TokenBlacklistManager instance
 */
export const createTokenBlacklistManager = (sessionRepo: ISessionRepository): TokenBlacklistManager => {
  if (!sessionRepo) {
    throw new AuthenticationError('Session repository is required for token blacklist', undefined, {
      code: 'MISSING_SESSION_REPOSITORY'
    });
  }

  return new TokenBlacklistManager(sessionRepo);
};

/**
 * Create a development token blacklist manager
 *
 * Factory function to create an in-memory token blacklist manager
 * suitable for development and testing environments.
 *
 * @returns Configured TokenBlacklistManager with memory-based storage
 */
export const createMemoryTokenBlacklistManager = (): TokenBlacklistManager => {
  const memoryRepo = new MemoryTokenBlacklist();
  return new TokenBlacklistManager(memoryRepo as Pick<ISessionRepository, 'blacklistToken' | 'isTokenBlacklisted'> as ISessionRepository);
};