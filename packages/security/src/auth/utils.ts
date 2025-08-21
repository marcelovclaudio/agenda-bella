/**
 * Authentication utilities and constants
 *
 * This module provides authentication-related constants, helper functions,
 * and utility methods for JWT token management, validation, and security operations.
 *
 * @packageDocumentation
 */

import * as crypto from 'crypto';
import type { JwtPayload } from './types';

/**
 * Authentication constants
 * Standard values and defaults for JWT authentication
 */
export const AUTH_CONSTANTS = {
  // Token expiration defaults
  /** Default access token expiration time */
  DEFAULT_EXPIRES_IN: '15m',
  /** Default refresh token expiration time */
  REFRESH_EXPIRES_IN: '7d',
  /** Default password reset token expiration */
  PASSWORD_RESET_EXPIRES_IN: '1h',
  /** Default email verification token expiration */
  EMAIL_VERIFICATION_EXPIRES_IN: '24h',

  // JWT algorithm and security
  /** Default JWT signing algorithm */
  ALGORITHM: 'HS256' as const,
  /** Supported JWT algorithms */
  SUPPORTED_ALGORITHMS: ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'] as const,
  /** Clock tolerance in seconds for token validation */
  CLOCK_TOLERANCE: 30,

  // Token types
  /** Token type identifiers */
  TOKEN_TYPES: {
    ACCESS: 'access',
    REFRESH: 'refresh',
    RESET: 'reset',
    VERIFICATION: 'verification',
  } as const,

  // Authorization header
  /** Bearer token prefix */
  BEARER_PREFIX: 'Bearer ',
  /** Authorization header name */
  AUTH_HEADER: 'Authorization',

  // Session and security
  /** Default session duration in milliseconds */
  DEFAULT_SESSION_DURATION: 24 * 60 * 60 * 1000, // 24 hours
  /** Maximum failed login attempts before lockout */
  MAX_LOGIN_ATTEMPTS: 5,
  /** Account lockout duration in milliseconds */
  LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
  /** Password reset attempt limit */
  MAX_RESET_ATTEMPTS: 3,

  // MFA constants
  /** TOTP window tolerance */
  TOTP_WINDOW: 1,
  /** TOTP step size in seconds */
  TOTP_STEP: 30,
  /** SMS code length */
  SMS_CODE_LENGTH: 6,
  /** Email verification code length */
  EMAIL_CODE_LENGTH: 8,
  /** Backup codes count */
  BACKUP_CODES_COUNT: 10,
  /** Backup code length */
  BACKUP_CODE_LENGTH: 8,

  // Security headers
  /** Security header names */
  SECURITY_HEADERS: {
    CONTENT_TYPE: 'Content-Type',
    X_FRAME_OPTIONS: 'X-Frame-Options',
    X_CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',
    X_XSS_PROTECTION: 'X-XSS-Protection',
    STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',
    CONTENT_SECURITY_POLICY: 'Content-Security-Policy',
  } as const,

  // Error codes
  /** Authentication error codes */
  ERROR_CODES: {
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    INVALID_TOKEN: 'INVALID_TOKEN',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    TOKEN_NOT_BEFORE: 'TOKEN_NOT_BEFORE',
    INVALID_REFRESH_TOKEN: 'INVALID_REFRESH_TOKEN',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
    EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
    MFA_REQUIRED: 'MFA_REQUIRED',
    INVALID_MFA_CODE: 'INVALID_MFA_CODE',
    SESSION_EXPIRED: 'SESSION_EXPIRED',
    INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  } as const,
} as const;

/**
 * JWT utility functions
 */
export const JwtUtils = {
  /**
   * Extracts token from Authorization header
   * @param authHeader - Authorization header value
   * @returns JWT token without Bearer prefix or null if invalid
   */
  extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader) return null;

    if (!authHeader.startsWith(AUTH_CONSTANTS.BEARER_PREFIX)) {
      return null;
    }

    const token = authHeader.substring(AUTH_CONSTANTS.BEARER_PREFIX.length).trim();
    return token || null;
  },

  /**
   * Creates Authorization header value
   * @param token - JWT token
   * @returns Authorization header value with Bearer prefix
   */
  createAuthHeader(token: string): string {
    return `${AUTH_CONSTANTS.BEARER_PREFIX}${token}`;
  },

  /**
   * Validates JWT payload structure
   * @param payload - JWT payload to validate
   * @returns True if payload has required fields
   */
  validatePayloadStructure(payload: unknown): payload is JwtPayload {
    if (!payload || typeof payload !== 'object') return false;

    const p = payload as Record<string, unknown>;

    // Check required standard claims
    return (
      typeof p['sub'] === 'string' &&
      typeof p['iat'] === 'number' &&
      typeof p['exp'] === 'number' &&
      typeof p['exp'] === 'number' &&
      typeof p['iat'] === 'number' &&
      p['exp'] > p['iat'] // Expiration must be after issued at
    );
  },

  /**
   * Checks if token is expired based on payload
   * @param payload - JWT payload
   * @param clockTolerance - Clock tolerance in seconds (default: 30)
   * @returns True if token is expired
   */
  isTokenExpired(payload: JwtPayload, clockTolerance = AUTH_CONSTANTS.CLOCK_TOLERANCE): boolean {
    const now = Math.floor(Date.now() / 1000);
    return payload.exp <= now - clockTolerance;
  },

  /**
   * Checks if token is not yet valid based on nbf claim
   * @param payload - JWT payload
   * @param clockTolerance - Clock tolerance in seconds (default: 30)
   * @returns True if token is not yet valid
   */
  isTokenNotBefore(payload: JwtPayload, clockTolerance = AUTH_CONSTANTS.CLOCK_TOLERANCE): boolean {
    if (!payload.nbf) return false;

    const now = Math.floor(Date.now() / 1000);
    return payload.nbf > now + clockTolerance;
  },

  /**
   * Gets token expiration date
   * @param payload - JWT payload
   * @returns Date when token expires
   */
  getTokenExpirationDate(payload: JwtPayload): Date {
    return new Date(payload.exp * 1000);
  },

  /**
   * Gets remaining token lifetime in seconds
   * @param payload - JWT payload
   * @returns Remaining seconds until expiration (negative if expired)
   */
  getRemainingLifetime(payload: JwtPayload): number {
    const now = Math.floor(Date.now() / 1000);
    return payload.exp - now;
  },

  /**
   * Validates audience claim
   * @param payload - JWT payload
   * @param expectedAudience - Expected audience value
   * @returns True if audience matches or is not specified
   */
  validateAudience(payload: JwtPayload, expectedAudience?: string): boolean {
    if (!expectedAudience || !payload.aud) return true;

    if (Array.isArray(payload.aud)) {
      return payload.aud.includes(expectedAudience);
    }

    return payload.aud === expectedAudience;
  },

  /**
   * Validates issuer claim
   * @param payload - JWT payload
   * @param expectedIssuer - Expected issuer value
   * @returns True if issuer matches or is not specified
   */
  validateIssuer(payload: JwtPayload, expectedIssuer?: string): boolean {
    if (!expectedIssuer || !payload.iss) return true;
    return payload.iss === expectedIssuer;
  },
};

/**
 * Security utility functions
 */
export const SecurityUtils = {
  /**
   * Generates a secure random string
   * @param length - Length of the string to generate
   * @param charset - Character set to use (default: alphanumeric)
   * @returns Random string
   */
  generateSecureToken(
    length = 32,
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  ): string {
    let result = '';
    const charactersLength = charset.length;

    // Use crypto.randomBytes if available (Node.js), otherwise fallback
    try {
      const randomBytes = crypto.randomBytes(length);

      for (let i = 0; i < length; i++) {
        result += charset.charAt(randomBytes[i]! % charactersLength);
      }

      return result;
    } catch {
      // Fallback to Math.random if crypto is not available
      for (let i = 0; i < length; i++) {
        result += charset.charAt(Math.floor(Math.random() * charactersLength));
      }
      return result;
    }
  },

  /**
   * Generates a numeric code
   * @param length - Length of the code
   * @returns Numeric code as string
   */
  generateNumericCode(length = 6): string {
    return SecurityUtils.generateSecureToken(length, '0123456789');
  },

  /**
   * Generates backup codes for MFA
   * @param count - Number of codes to generate
   * @param length - Length of each code
   * @returns Array of backup codes
   */
  generateBackupCodes(
    count = AUTH_CONSTANTS.BACKUP_CODES_COUNT,
    length = AUTH_CONSTANTS.BACKUP_CODE_LENGTH
  ): string[] {
    const codes: string[] = [];
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    for (let i = 0; i < count; i++) {
      codes.push(SecurityUtils.generateSecureToken(length, charset));
    }

    return codes;
  },

  /**
   * Validates email format
   * @param email - Email address to validate
   * @returns True if email format is valid
   */
  isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  /**
   * Sanitizes user input by removing potentially dangerous characters
   * @param input - Input string to sanitize
   * @returns Sanitized string
   */
  sanitizeInput(input: string): string {
    return input
      .replace(/[<>]/g, '') // Remove angle brackets
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  },

  /**
   * Validates password strength
   * @param password - Password to validate
   * @param requirements - Password requirements
   * @returns Validation result with score and feedback
   */
  validatePasswordStrength(
    password: string,
    requirements = {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSymbols: true,
    }
  ): {
    isValid: boolean;
    score: number; // 0-100
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length < requirements.minLength) {
      feedback.push(`Senha deve ter pelo menos ${requirements.minLength} caracteres`);
    } else {
      score += 25;
    }

    // Character type checks
    if (requirements.requireUppercase && !/[A-Z]/.test(password)) {
      feedback.push('Senha deve conter pelo menos uma letra maiúscula');
    } else if (requirements.requireUppercase) {
      score += 20;
    }

    if (requirements.requireLowercase && !/[a-z]/.test(password)) {
      feedback.push('Senha deve conter pelo menos uma letra minúscula');
    } else if (requirements.requireLowercase) {
      score += 20;
    }

    if (requirements.requireNumbers && !/\d/.test(password)) {
      feedback.push('Senha deve conter pelo menos um número');
    } else if (requirements.requireNumbers) {
      score += 20;
    }

    if (requirements.requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      feedback.push('Senha deve conter pelo menos um símbolo');
    } else if (requirements.requireSymbols) {
      score += 15;
    }

    return {
      isValid: feedback.length === 0,
      score,
      feedback,
    };
  },

  /**
   * Creates a secure hash of sensitive data
   * @param data - Data to hash
   * @returns Base64 encoded hash
   */
  createSecureHash(data: string): string {
    // This is a simple implementation - in production, use proper crypto library
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }

    return btoa(hash.toString(16));
  },
};

/**
 * Time utility functions for authentication
 */
export const TimeUtils = {
  /**
   * Converts duration string to milliseconds
   * @param duration - Duration string (e.g., '15m', '1h', '7d')
   * @returns Duration in milliseconds
   */
  durationToMs(duration: string): number {
    const units: Record<string, number> = {
      ms: 1,
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
      w: 7 * 24 * 60 * 60 * 1000,
    };

    const match = duration.match(/^(\d+)([smhdw]?)$/);
    if (!match) {
      throw new Error(`Invalid duration format: ${duration}`);
    }

    const [, value, unit] = match;
    const multiplier = units[unit || 'ms'];

    if (!multiplier) {
      throw new Error(`Invalid duration unit: ${unit}`);
    }

    if (!value) {
      throw new Error(`Invalid duration value: ${value}`);
    }

    return parseInt(value, 10) * multiplier;
  },

  /**
   * Converts duration string to seconds
   * @param duration - Duration string (e.g., '15m', '1h', '7d')
   * @returns Duration in seconds
   */
  durationToSeconds(duration: string): number {
    return Math.floor(TimeUtils.durationToMs(duration) / 1000);
  },

  /**
   * Creates expiration date from duration
   * @param duration - Duration string or milliseconds
   * @param fromDate - Base date (default: now)
   * @returns Expiration date
   */
  createExpirationDate(duration: string | number, fromDate: Date = new Date()): Date {
    const ms = typeof duration === 'string' ? TimeUtils.durationToMs(duration) : duration;
    return new Date(fromDate.getTime() + ms);
  },

  /**
   * Checks if a date is expired
   * @param expirationDate - Date to check
   * @param tolerance - Tolerance in milliseconds
   * @returns True if expired
   */
  isExpired(expirationDate: Date, tolerance = 0): boolean {
    return Date.now() > expirationDate.getTime() + tolerance;
  },

  /**
   * Gets remaining time until expiration
   * @param expirationDate - Expiration date
   * @returns Remaining milliseconds (negative if expired)
   */
  getRemainingTime(expirationDate: Date): number {
    return expirationDate.getTime() - Date.now();
  },
};

/**
 * Role and permission utility functions
 */
export const AuthorizationUtils = {
  /**
   * Checks if user has required role
   * @param userRoles - User's roles
   * @param requiredRole - Required role
   * @returns True if user has the required role
   */
  hasRole(userRoles: string[] = [], requiredRole: string): boolean {
    return userRoles.includes(requiredRole);
  },

  /**
   * Checks if user has any of the required roles
   * @param userRoles - User's roles
   * @param requiredRoles - Required roles (any of them)
   * @returns True if user has at least one required role
   */
  hasAnyRole(userRoles: string[] = [], requiredRoles: string[] = []): boolean {
    return requiredRoles.some((role) => userRoles.includes(role));
  },

  /**
   * Checks if user has all required roles
   * @param userRoles - User's roles
   * @param requiredRoles - Required roles (all of them)
   * @returns True if user has all required roles
   */
  hasAllRoles(userRoles: string[] = [], requiredRoles: string[] = []): boolean {
    return requiredRoles.every((role) => userRoles.includes(role));
  },

  /**
   * Checks if user has required permission
   * @param userPermissions - User's permissions
   * @param requiredPermission - Required permission
   * @returns True if user has the required permission
   */
  hasPermission(userPermissions: string[] = [], requiredPermission: string): boolean {
    return userPermissions.includes(requiredPermission);
  },

  /**
   * Checks if user has any of the required permissions
   * @param userPermissions - User's permissions
   * @param requiredPermissions - Required permissions (any of them)
   * @returns True if user has at least one required permission
   */
  hasAnyPermission(userPermissions: string[] = [], requiredPermissions: string[] = []): boolean {
    return requiredPermissions.some((permission) => userPermissions.includes(permission));
  },

  /**
   * Checks if user has all required permissions
   * @param userPermissions - User's permissions
   * @param requiredPermissions - Required permissions (all of them)
   * @returns True if user has all required permissions
   */
  hasAllPermissions(userPermissions: string[] = [], requiredPermissions: string[] = []): boolean {
    return requiredPermissions.every((permission) => userPermissions.includes(permission));
  },

  /**
   * Combines role and permission checks
   * @param user - User object with roles and permissions
   * @param requirements - Authorization requirements
   * @returns True if user meets all requirements
   */
  isAuthorized(
    user: { roles?: string[]; permissions?: string[] },
    requirements: {
      roles?: { any?: string[]; all?: string[] };
      permissions?: { any?: string[]; all?: string[] };
      custom?: (user: { roles?: string[]; permissions?: string[] }) => boolean;
    }
  ): boolean {
    const { roles = [], permissions = [] } = user;
    const { roles: roleReq, permissions: permReq, custom } = requirements;

    // Check role requirements
    if (roleReq?.any && !AuthorizationUtils.hasAnyRole(roles, roleReq.any)) {
      return false;
    }

    if (roleReq?.all && !AuthorizationUtils.hasAllRoles(roles, roleReq.all)) {
      return false;
    }

    // Check permission requirements
    if (permReq?.any && !AuthorizationUtils.hasAnyPermission(permissions, permReq.any)) {
      return false;
    }

    if (permReq?.all && !AuthorizationUtils.hasAllPermissions(permissions, permReq.all)) {
      return false;
    }

    // Check custom requirements
    if (custom && !custom(user)) {
      return false;
    }

    return true;
  },
};

/**
 * Validation utility functions
 */
export const ValidationUtils = {
  /**
   * Validates JWT token format (basic structure check)
   * @param token - Token to validate
   * @returns True if token has valid JWT format
   */
  isValidJwtFormat(token: string): boolean {
    if (!token || typeof token !== 'string') return false;

    const parts = token.split('.');
    if (parts.length !== 3) return false;

    // Check if each part is valid base64
    try {
      parts.forEach((part) => {
        if (!part) throw new Error('Empty part');
        atob(part.replace(/-/g, '+').replace(/_/g, '/'));
      });
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Validates session ID format
   * @param sessionId - Session ID to validate
   * @returns True if session ID is valid
   */
  isValidSessionId(sessionId: string): boolean {
    if (!sessionId || typeof sessionId !== 'string') return false;

    // Session ID should be alphanumeric with minimum length
    const sessionIdRegex = /^[a-zA-Z0-9]{16,}$/;
    return sessionIdRegex.test(sessionId);
  },

  /**
   * Validates user ID format
   * @param userId - User ID to validate
   * @returns True if user ID is valid
   */
  isValidUserId(userId: string): boolean {
    if (!userId || typeof userId !== 'string') return false;

    // User ID should be non-empty and reasonable length
    return userId.trim().length > 0 && userId.length <= 255;
  },

  /**
   * Validates IP address format
   * @param ipAddress - IP address to validate
   * @returns True if IP address is valid
   */
  isValidIpAddress(ipAddress: string): boolean {
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    // Basic IPv4 and IPv6 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    return ipv4Regex.test(ipAddress) || ipv6Regex.test(ipAddress);
  },
};
