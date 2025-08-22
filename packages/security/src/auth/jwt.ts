/**
 * JWT Token Management
 *
 * This module provides secure JWT token generation and management functionality
 * with comprehensive validation, logging, and error handling following security best practices.
 *
 * @packageDocumentation
 */

import jwt from 'jsonwebtoken';
import { generateSecureSecret, generateSecureUUID } from '../utils/crypto';
import { securityLogger, auditLog, createSecurityError } from '../utils';
import { AuthenticationError } from '../types';
import type {
  JwtPayload,
  AuthTokens,
  TokenValidationResult,
  JwtTokenGenerationOptions,
  JwtManagerConfig,
} from './types';
import type { SecurityContext } from '../types';

/**
 * JWT Manager class for secure token generation and validation
 *
 * Provides comprehensive JWT functionality with:
 * - Secure token generation with configurable expiration
 * - Secret key validation and rotation support
 * - Comprehensive logging and audit trails
 * - TypeScript strict mode compliance
 *
 * @example
 * ```typescript
 * const jwtManager = new JwtManager({
 *   secret: process.env.JWT_SECRET!,
 *   expiresIn: '15m',
 *   refreshExpiresIn: '7d',
 *   issuer: 'agenda-bella',
 *   audience: 'api'
 * });
 *
 * const tokens = await jwtManager.generateTokens({
 *   userId: 'user123',
 *   email: 'user@example.com',
 *   roles: ['user']
 * });
 * ```
 */
export class JwtManager {
  private config: JwtManagerConfig;

  /**
   * Initialize JWT Manager with configuration validation
   *
   * @param config - JWT configuration with required security parameters
   * @throws {SecurityError} When configuration is invalid
   */
  constructor(config: JwtManagerConfig) {
    this.validateConfig(config);
    this.config = config;

    securityLogger.info('JWT Manager initialized', {
      issuer: config.issuer,
      audience: config.audience,
      algorithm: config.algorithm,
      hasSecret: !!config.secret,
      secretLength: config.secret.length,
    });
  }

  /**
   * Generate access and refresh token pair
   *
   * Creates both access and refresh tokens with proper payload structure,
   * expiration times, and security claims following JWT best practices.
   *
   * @param options - Token generation options including user data and context
   * @returns Promise resolving to generated token pair with metadata
   * @throws {SecurityError} When token generation fails
   */
  async generateTokens(options: JwtTokenGenerationOptions): Promise<AuthTokens> {
    const { userId, email, name, roles = [], permissions = [], sessionId, context } = options;

    try {
      // Generate unique session ID if not provided
      const finalSessionId = sessionId || generateSecureUUID();
      const issuedAt = Math.floor(Date.now() / 1000);
      const jti = generateSecureUUID();

      // Calculate expiration times
      const accessTokenExp = this.calculateExpiration(this.config.expiresIn);
      const refreshTokenExp = this.calculateExpiration(this.config.refreshExpiresIn);

      // Generate access token
      const accessPayload: JwtPayload = {
        sub: userId,
        iat: issuedAt,
        exp: Math.floor(accessTokenExp.getTime() / 1000),
        jti,
        ...(this.config.audience && { aud: this.config.audience }),
        ...(this.config.issuer && { iss: this.config.issuer }),
        ...(email && { email }),
        ...(name && { name }),
        ...(roles && roles.length > 0 && { roles }),
        ...(permissions && permissions.length > 0 && { permissions }),
        sessionId: finalSessionId,
        tokenType: 'access',
      };

      const accessToken = jwt.sign(accessPayload, this.config.secret, {
        algorithm: this.config.algorithm,
        ...(this.config.issuer && !accessPayload.iss && { issuer: this.config.issuer }),
        ...(this.config.audience && !accessPayload.aud && { audience: this.config.audience }),
      });

      // Generate refresh token with minimal payload for security
      const refreshPayload: JwtPayload = {
        sub: userId,
        iat: issuedAt,
        exp: Math.floor(refreshTokenExp.getTime() / 1000),
        jti: generateSecureUUID(), // Different JTI for refresh token
        ...(this.config.audience && { aud: this.config.audience }),
        ...(this.config.issuer && { iss: this.config.issuer }),
        sessionId: finalSessionId,
        tokenType: 'refresh',
      };

      const refreshToken = jwt.sign(refreshPayload, this.config.secret, {
        algorithm: this.config.algorithm,
        ...(this.config.issuer && !refreshPayload.iss && { issuer: this.config.issuer }),
        ...(this.config.audience && !refreshPayload.aud && { audience: this.config.audience }),
      });

      const tokens: AuthTokens = {
        accessToken,
        refreshToken,
        expiresAt: accessTokenExp,
        refreshExpiresAt: refreshTokenExp,
        tokenType: 'Bearer',
        scope: permissions,
      };

      // Log successful token generation
      auditLog('JWT_TOKENS_GENERATED', {
        userId,
        sessionId: finalSessionId,
        accessTokenJti: jti,
        refreshTokenJti: refreshPayload.jti,
        expiresAt: accessTokenExp.toISOString(),
        refreshExpiresAt: refreshTokenExp.toISOString(),
        context,
      });

      securityLogger.info('JWT tokens generated successfully', {
        userId,
        sessionId: finalSessionId,
        hasAccessToken: !!tokens.accessToken,
        hasRefreshToken: !!tokens.refreshToken,
        expiresIn: this.config.expiresIn,
        refreshExpiresIn: this.config.refreshExpiresIn,
      });

      return tokens;
    } catch (error) {
      const securityError = createSecurityError(
        'SECURITY_CONFIG_ERROR',
        'Failed to generate JWT tokens',
        { 
          details: { originalError: error, userId },
          ...(context && { context })
        }
      );

      securityLogger.error('JWT token generation failed', {
        error: securityError.message,
        userId,
        context,
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw securityError;
    }
  }

  /**
   * Validate JWT token and return payload
   *
   * @param token - JWT token to validate
   * @param context - Security context for validation
   * @returns Token validation result with payload or error details
   */
  async validateToken(token: string, context: SecurityContext): Promise<TokenValidationResult> {
    try {
      const payload = jwt.verify(token, this.config.secret, {
        algorithms: [this.config.algorithm],
        ...(this.config.issuer && { issuer: this.config.issuer }),
        ...(this.config.audience && { audience: this.config.audience }),
        clockTolerance: this.config.clockTolerance,
      }) as JwtPayload;

      securityLogger.debug('JWT token validated successfully', {
        userId: payload.sub,
        sessionId: payload.sessionId,
        tokenType: payload.tokenType,
        jti: payload.jti,
      });

      return {
        valid: true,
        payload,
        context,
      };
    } catch (error) {
      let errorType: NonNullable<TokenValidationResult['error']>['type'] = 'invalid';
      let errorMessage = 'Token validation failed';

      if (error instanceof jwt.TokenExpiredError) {
        errorType = 'expired';
        errorMessage = 'Token has expired';
      } else if (error instanceof jwt.JsonWebTokenError) {
        errorType = 'malformed';
        errorMessage = 'Token is malformed';
      } else if (error instanceof jwt.NotBeforeError) {
        errorType = 'not_before';
        errorMessage = 'Token not active yet';
      }

      securityLogger.warn('JWT token validation failed', {
        error: errorMessage,
        errorType,
        context,
        stack: error instanceof Error ? error.stack : undefined,
      });

      return {
        valid: false,
        error: {
          code: 'JWT_VALIDATION_FAILED',
          message: errorMessage,
          type: errorType,
        },
        context,
      };
    }
  }

  /**
   * Refresh access token using refresh token with security context
   *
   * @param refreshToken - Valid refresh token
   * @param context - Security context
   * @returns New token pair if refresh is successful
   */
  async refreshTokensWithContext(
    refreshToken: string,
    context: SecurityContext
  ): Promise<{ success: boolean; tokens?: AuthTokens; error?: string }> {
    try {
      const validation = await this.validateToken(refreshToken, context);

      if (!validation.valid || !validation.payload) {
        return {
          success: false,
          error: validation.error?.message || 'Invalid refresh token',
        };
      }

      if (validation.payload.tokenType !== 'refresh') {
        return {
          success: false,
          error: 'Token is not a refresh token',
        };
      }

      // Generate new tokens using existing payload data
      const tokens = await this.generateTokens({
        userId: validation.payload.sub,
        ...(validation.payload.email && { email: validation.payload.email }),
        ...(validation.payload.name && { name: validation.payload.name }),
        ...(validation.payload.roles && { roles: validation.payload.roles }),
        ...(validation.payload.permissions && { permissions: validation.payload.permissions }),
        ...(validation.payload.sessionId && { sessionId: validation.payload.sessionId }),
        ...(context && { context }),
      });

      auditLog('JWT_TOKENS_REFRESHED', {
        userId: validation.payload.sub,
        sessionId: validation.payload.sessionId,
        context,
      });

      return { success: true, tokens };
    } catch (error) {
      securityLogger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        context,
      });

      return {
        success: false,
        error: 'Token refresh failed',
      };
    }
  }

  /**
   * Verify and validate access token
   *
   * Validates JWT access token specifically, ensuring it's an access token type
   * and not a refresh token. Provides detailed error handling with specific
   * error codes for different failure scenarios.
   *
   * @param token - JWT access token to verify
   * @returns Decoded JWT payload for valid access tokens
   * @throws {AuthenticationError} When token is invalid, expired, or wrong type
   */
  verifyAccessToken(token: string): JwtPayload {
    try {
      const payload = jwt.verify(token, this.config.secret, {
        algorithms: [this.config.algorithm],
        ...(this.config.issuer && { issuer: this.config.issuer }),
        ...(this.config.audience && { audience: this.config.audience }),
        clockTolerance: this.config.clockTolerance,
      }) as JwtPayload;

      if (typeof payload === 'string') {
        throw new AuthenticationError('Invalid token format');
      }

      // Ensure this is an access token, not a refresh token
      if (payload.tokenType && payload.tokenType !== 'access') {
        throw new AuthenticationError('Token is not an access token', undefined, { 
          code: 'INVALID_TOKEN_TYPE',
          tokenType: payload.tokenType, 
          expected: 'access' 
        });
      }

      securityLogger.debug('Access token verified successfully', {
        userId: payload.sub,
        sessionId: payload.sessionId,
        jti: payload.jti,
        tokenType: payload.tokenType,
      });

      return payload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        securityLogger.warn('Access token expired', {
          expiredAt: error.expiredAt,
        });
        throw new AuthenticationError('Token expired', undefined, {
          code: 'TOKEN_EXPIRED',
          expiredAt: error.expiredAt
        });
      }

      if (error instanceof jwt.JsonWebTokenError) {
        securityLogger.warn('Invalid access token', {
          error: error.message,
        });
        throw new AuthenticationError('Invalid token', undefined, {
          code: 'INVALID_TOKEN',
          reason: error.message
        });
      }

      if (error instanceof AuthenticationError) {
        throw error;
      }

      securityLogger.error('Unexpected error during access token verification', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw error;
    }
  }

  /**
   * Verify and validate refresh token
   *
   * Validates JWT refresh token specifically, ensuring it's a refresh token type
   * and extracting minimal payload for security. Only returns essential claims.
   *
   * @param token - JWT refresh token to verify
   * @returns Minimal payload with user ID and token type
   * @throws {AuthenticationError} When token is invalid, expired, or wrong type
   */
  verifyRefreshToken(token: string): { sub: string; type: string } {
    try {
      const payload = jwt.verify(token, this.config.secret, {
        algorithms: [this.config.algorithm],
        ...(this.config.issuer && { issuer: this.config.issuer }),
        ...(this.config.audience && { audience: this.config.audience }),
        clockTolerance: this.config.clockTolerance,
      }) as JwtPayload;

      if (typeof payload === 'string') {
        throw new AuthenticationError('Invalid refresh token format');
      }

      if (!payload.tokenType || payload.tokenType !== 'refresh') {
        throw new AuthenticationError('Invalid refresh token type', undefined, {
          code: 'INVALID_TOKEN_TYPE',
          tokenType: payload.tokenType, 
          expected: 'refresh'
        });
      }

      securityLogger.debug('Refresh token verified successfully', {
        userId: payload.sub,
        sessionId: payload.sessionId,
        jti: payload.jti,
      });

      return { sub: payload.sub, type: payload.tokenType };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        securityLogger.warn('Refresh token expired', {
          expiredAt: error.expiredAt,
        });
        throw new AuthenticationError('Refresh token expired', undefined, {
          code: 'REFRESH_TOKEN_EXPIRED',
          expiredAt: error.expiredAt
        });
      }

      if (error instanceof jwt.JsonWebTokenError) {
        securityLogger.warn('Invalid refresh token', {
          error: error.message,
        });
        throw new AuthenticationError('Invalid refresh token', undefined, {
          code: 'INVALID_REFRESH_TOKEN',
          reason: error.message
        });
      }

      if (error instanceof AuthenticationError) {
        throw error;
      }

      securityLogger.error('Unexpected error during refresh token verification', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw error;
    }
  }

  /**
   * Refresh access token using valid refresh token and new payload
   *
   * Validates refresh token and generates new token pair using the provided
   * user payload. This implements the specific refresh mechanism described
   * in SUB-SEC-002-02.
   *
   * @param refreshToken - Valid refresh token
   * @param newPayload - New payload for the access token (without iat/exp)
   * @returns New authentication token pair
   * @throws {AuthenticationError} When refresh token is invalid
   */
  refreshTokens(
    refreshToken: string, 
    newPayload: {
      sub: string;
      roles?: string[];
      permissions?: string[];
      email?: string;
      name?: string;
      sessionId?: string;
      aud?: string;
      iss?: string;
      jti?: string;
      nbf?: number;
      tokenType?: 'access' | 'refresh';
    }
  ): AuthTokens {
    try {
      // Verify the refresh token first
      this.verifyRefreshToken(refreshToken);

      // Generate new tokens
      const issuedAt = Math.floor(Date.now() / 1000);
      const jti = generateSecureUUID();

      // Calculate expiration times
      const accessTokenExp = this.calculateExpiration(this.config.expiresIn);
      const refreshTokenExp = this.calculateExpiration(this.config.refreshExpiresIn);

      // Generate new access token
      const accessPayload: JwtPayload = {
        sub: newPayload.sub,
        iat: issuedAt,
        exp: Math.floor(accessTokenExp.getTime() / 1000),
        jti,
        ...(this.config.audience && { aud: this.config.audience }),
        ...(this.config.issuer && { iss: this.config.issuer }),
        ...(newPayload.roles && { roles: newPayload.roles }),
        ...(newPayload.permissions && { permissions: newPayload.permissions }),
        ...(newPayload.email && { email: newPayload.email }),
        ...(newPayload.name && { name: newPayload.name }),
        ...(newPayload.sessionId && { sessionId: newPayload.sessionId }),
        tokenType: 'access',
      };

      const accessToken = jwt.sign(accessPayload, this.config.secret, {
        algorithm: this.config.algorithm,
        ...(this.config.issuer && !accessPayload.iss && { issuer: this.config.issuer }),
        ...(this.config.audience && !accessPayload.aud && { audience: this.config.audience }),
      });

      // Generate new refresh token
      const refreshPayload: JwtPayload = {
        sub: newPayload.sub,
        iat: issuedAt,
        exp: Math.floor(refreshTokenExp.getTime() / 1000),
        jti: generateSecureUUID(),
        ...(this.config.audience && { aud: this.config.audience }),
        ...(this.config.issuer && { iss: this.config.issuer }),
        ...(newPayload.sessionId && { sessionId: newPayload.sessionId }),
        tokenType: 'refresh',
      };

      const newRefreshToken = jwt.sign(refreshPayload, this.config.secret, {
        algorithm: this.config.algorithm,
        ...(this.config.issuer && !refreshPayload.iss && { issuer: this.config.issuer }),
        ...(this.config.audience && !refreshPayload.aud && { audience: this.config.audience }),
      });

      const tokens: AuthTokens = {
        accessToken,
        refreshToken: newRefreshToken,
        expiresAt: accessTokenExp,
        refreshExpiresAt: refreshTokenExp,
        tokenType: 'Bearer',
        scope: newPayload.permissions ?? [],
      };

      securityLogger.info('JWT tokens refreshed', {
        userId: newPayload.sub,
        sessionId: newPayload.sessionId,
        hasNewAccessToken: !!tokens.accessToken,
        hasNewRefreshToken: !!tokens.refreshToken,
      });

      auditLog('JWT_TOKENS_REFRESHED', {
        userId: newPayload.sub,
        sessionId: newPayload.sessionId,
        newAccessTokenJti: jti,
        newRefreshTokenJti: refreshPayload.jti,
      });

      return tokens;
    } catch (error) {
      securityLogger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: newPayload.sub,
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw error;
    }
  }

  /**
   * Validate JWT configuration for security compliance
   *
   * @private
   * @param config - Configuration to validate
   * @throws {SecurityError} When configuration is invalid
   */
  private validateConfig(config: JwtManagerConfig): void {
    // Validate secret key strength
    if (!config.secret || typeof config.secret !== 'string') {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        'JWT secret is required and must be a string',
        { details: { hasSecret: !!config.secret } }
      );
    }

    // Enforce minimum secret length for security
    if (config.secret.length < 32) {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        'JWT secret must be at least 32 characters long for security',
        { details: { secretLength: config.secret.length, minimumLength: 32 } }
      );
    }

    // Validate expiration times
    if (!config.expiresIn) {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        'JWT expiresIn is required',
        { details: { config: { expiresIn: config.expiresIn } } }
      );
    }

    if (!config.refreshExpiresIn) {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        'JWT refreshExpiresIn is required',
        { details: { config: { refreshExpiresIn: config.refreshExpiresIn } } }
      );
    }

    // Validate algorithm
    const supportedAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];
    if (!supportedAlgorithms.includes(config.algorithm)) {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        `Unsupported JWT algorithm: ${config.algorithm}`,
        { details: { algorithm: config.algorithm, supportedAlgorithms } }
      );
    }

    securityLogger.info('JWT configuration validated successfully', {
      secretLength: config.secret.length,
      algorithm: config.algorithm,
      expiresIn: config.expiresIn,
      refreshExpiresIn: config.refreshExpiresIn,
      hasIssuer: !!config.issuer,
      hasAudience: !!config.audience,
    });
  }

  /**
   * Calculate expiration time from duration string
   *
   * @private
   * @param duration - Duration string (e.g., '15m', '1h', '7d')
   * @returns Calculated expiration Date
   */
  private calculateExpiration(duration: string): Date {
    const now = Date.now();
    const match = duration.match(/^(\d+)([smhd])$/);

    if (!match) {
      throw createSecurityError(
        'SECURITY_CONFIG_ERROR',
        `Invalid duration format: ${duration}. Use format like '15m', '1h', '7d'`,
        { details: { duration } }
      );
    }

    const value = parseInt(match[1]!, 10);
    const unit = match[2]!;

    let milliseconds = 0;
    switch (unit) {
      case 's':
        milliseconds = value * 1000;
        break;
      case 'm':
        milliseconds = value * 60 * 1000;
        break;
      case 'h':
        milliseconds = value * 60 * 60 * 1000;
        break;
      case 'd':
        milliseconds = value * 24 * 60 * 60 * 1000;
        break;
      default:
        throw createSecurityError(
          'SECURITY_CONFIG_ERROR',
          `Invalid duration unit: ${unit}. Use 's', 'm', 'h', or 'd'`,
          { details: { unit, duration } }
        );
    }

    return new Date(now + milliseconds);
  }

  /**
   * Generate secure JWT secret
   *
   * @param length - Byte length for the secret (default: 64)
   * @returns Base64URL-encoded secure random secret
   *
   * @example
   * ```typescript
   * const secret = JwtManager.generateSecret(64);
   * // Use this secret in your JWT configuration
   * ```
   */
  static generateSecret(length: number = 64): string {
    return generateSecureSecret(length);
  }
}

/**
 * Create JWT Manager instance with configuration validation
 *
 * @param config - JWT configuration
 * @returns Configured JWT Manager instance
 *
 * @example
 * ```typescript
 * const jwtManager = createJwtManager({
 *   secret: process.env.JWT_SECRET!,
 *   expiresIn: '15m',
 *   refreshExpiresIn: '7d'
 * });
 * ```
 */
export const createJwtManager = (config: JwtManagerConfig): JwtManager => {
  return new JwtManager(config);
};

/**
 * Default JWT configuration for development
 * WARNING: Do not use in production
 */
export const getDefaultJwtConfig = (): JwtManagerConfig => {
  if (process.env['NODE_ENV'] === 'production') {
    throw createSecurityError(
      'SECURITY_CONFIG_ERROR',
      'Default JWT configuration cannot be used in production',
      { details: { environment: process.env['NODE_ENV'] } }
    );
  }

  return {
    secret: JwtManager.generateSecret(64),
    expiresIn: '15m',
    refreshExpiresIn: '7d',
    algorithm: 'HS256',
    issuer: 'agenda-bella-dev',
    audience: 'api',
    clockTolerance: 30,
  };
};