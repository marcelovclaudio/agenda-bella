/**
 * Authentication Route Handlers
 *
 * This module provides Express route handlers for authentication endpoints including
 * login, token refresh, logout, and user profile retrieval. Implements structured 
 * responses, comprehensive error handling, and security logging.
 *
 * @packageDocumentation
 */

import type { Request, Response, NextFunction } from 'express';
import { AuthService } from './service';
import { securityLogger, auditLog } from '../utils';
import { AuthenticationError } from '../types/errors.types';
import type { LoginCredentials, RefreshTokenRequest, AuthenticatedRequest, RegistrationData } from './types';

/**
 * Safe client IP extraction from Express request
 * @param req - Express request object
 * @returns Client IP address
 */
function getClientIP(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const firstIP = forwarded.split(',')[0];
    return firstIP ? firstIP.trim() : 'unknown';
  }
  if (Array.isArray(forwarded) && forwarded.length > 0 && forwarded[0]) {
    return forwarded[0].trim();
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

/**
 * Authentication route handlers factory
 *
 * Creates a set of route handlers for authentication operations that can be 
 * integrated with Express routers. All handlers follow consistent response 
 * patterns and comprehensive error handling.
 *
 * @param authService - Authentication service instance
 * @returns Object containing all authentication route handlers
 *
 * @example
 * ```typescript
 * const authHandlers = createAuthHandlers(authService);
 * 
 * // Use in Express router
 * router.post('/login', authHandlers.login);
 * router.post('/refresh', authHandlers.refresh);
 * router.post('/logout', authMiddleware, authHandlers.logout);
 * router.get('/me', authMiddleware, authHandlers.me);
 * ```
 */
export function createAuthHandlers(authService: AuthService) {
  
  /**
   * User login handler
   *
   * Authenticates user with email and password, returns user information and tokens.
   * Tracks device information and logs authentication events for security monitoring.
   *
   * @param req - Express request with login credentials in body
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email, password } = req.body;
      
      // Validate required fields
      if (!email || !password) {
        auditLog('login_validation_failed', {
          reason: 'missing_credentials',
          email,
          ipAddress: getClientIP(req),
        });

        res.status(400).json({
          error: {
            code: 'MISSING_CREDENTIALS',
            message: 'Email and password are required',
          },
        });
        return;
      }

      // Prepare login credentials with device information
      const userAgent = req.get('User-Agent');
      const credentials: LoginCredentials = {
        email,
        password,
        deviceInfo: {
          ...(userAgent && { userAgent }),
          ipAddress: getClientIP(req),
        },
      };

      securityLogger.info('Login handler processing request', {
        email,
        hasPassword: !!password,
        deviceInfo: credentials.deviceInfo,
      });

      // Authenticate user
      const result = await authService.login(credentials);

      // Log successful login
      securityLogger.info('User login successful', {
        userId: result.user.id,
        isFirstLogin: result.isFirstLogin,
        deviceInfo: credentials.deviceInfo,
      });

      // Return structured success response
      res.status(200).json({
        success: true,
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            roles: result.user.roles,
          },
          tokens: result.tokens,
          isFirstLogin: result.isFirstLogin,
        },
      });

    } catch (error) {
      // Log authentication errors
      if (error instanceof AuthenticationError) {
        securityLogger.warn('Login failed', {
          email: req.body?.email,
          error: error.message,
          code: error.code,
          ipAddress: getClientIP(req),
        });
      }
      
      next(error);
    }
  };

  /**
   * Token refresh handler
   *
   * Refreshes access token using valid refresh token. Implements token rotation
   * for enhanced security and tracks device information.
   *
   * @param req - Express request with refresh token in body
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const refresh = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { refreshToken } = req.body;
      
      // Validate refresh token presence
      if (!refreshToken) {
        auditLog('token_refresh_validation_failed', {
          reason: 'missing_refresh_token',
          ipAddress: getClientIP(req),
        });

        res.status(400).json({
          error: {
            code: 'MISSING_REFRESH_TOKEN',
            message: 'Refresh token is required',
          },
        });
        return;
      }

      // Prepare refresh request with device information
      const userAgent = req.get('User-Agent');
      const refreshRequest: RefreshTokenRequest = {
        refreshToken,
        deviceInfo: {
          ...(userAgent && { userAgent }),
          ipAddress: getClientIP(req),
        },
      };

      securityLogger.info('Token refresh handler processing request', {
        hasRefreshToken: !!refreshToken,
        deviceInfo: refreshRequest.deviceInfo,
      });

      // Refresh tokens
      const tokens = await authService.refresh(refreshRequest);

      // Note: The refresh method only returns tokens, not user data
      // We would need to get user data separately if needed for the response
      // For now, returning just the tokens as per the service contract
      res.status(200).json({
        success: true,
        data: {
          tokens,
        },
      });

    } catch (error) {
      // Log refresh errors
      if (error instanceof AuthenticationError) {
        securityLogger.warn('Token refresh failed', {
          error: error.message,
          code: error.code,
          ipAddress: getClientIP(req),
        });
      }
      
      next(error);
    }
  };

  /**
   * User logout handler
   *
   * Logs out user by invalidating tokens and revoking sessions. Supports both
   * single device logout and logout from all devices.
   *
   * @param req - Express request with optional refresh token and logout options
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const logout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check if user is authenticated (should be ensured by middleware)
      const authReq = req as unknown as AuthenticatedRequest;
      if (!authReq.user) {
        auditLog('logout_failed', {
          reason: 'unauthenticated_request',
          ipAddress: getClientIP(req),
        });

        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
        return;
      }

      const { refreshToken, logoutAllDevices = false } = req.body;

      securityLogger.info('Logout handler processing request', {
        userId: authReq.user.id,
        hasRefreshToken: !!refreshToken,
        logoutAllDevices,
      });

      // Execute logout operation
      const logoutRequest = {
        refreshToken,
        logoutAllDevices,
      };
      await authService.logout(logoutRequest);

      // Log successful logout
      auditLog('logout_success', {
        userId: authReq.user.id,
        logoutAllDevices,
        hadRefreshToken: !!refreshToken,
        ipAddress: getClientIP(req),
      });

      // Return structured success response
      res.status(200).json({
        success: true,
        message: 'Logged out successfully',
      });

    } catch (error) {
      // Log logout errors but be tolerant of failures
      securityLogger.warn('Logout error occurred', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: (req as unknown as AuthenticatedRequest).user?.id,
        ipAddress: getClientIP(req),
      });
      
      next(error);
    }
  };

  /**
   * Current user profile handler
   *
   * Returns authenticated user's profile information and session details.
   * Requires valid authentication (enforced by middleware).
   *
   * @param req - Express request with authenticated user information
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const me = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check if user is authenticated (should be ensured by middleware)
      const authReq = req as unknown as AuthenticatedRequest;
      if (!authReq.user) {
        auditLog('profile_access_failed', {
          reason: 'unauthenticated_request',
          ipAddress: getClientIP(req),
        });

        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
        return;
      }

      securityLogger.debug('Profile handler processing request', {
        userId: authReq.user.id,
        sessionId: authReq.user.sessionId,
      });

      // Return user profile information
      res.status(200).json({
        success: true,
        data: {
          user: {
            id: authReq.user.id,
            email: authReq.user.email,
            roles: authReq.user.roles,
            permissions: authReq.user.permissions,
            lastLoginAt: new Date(), // Note: lastLoginAt not available in AuthenticatedRequest.user
          },
          session: {
            sessionId: authReq.user.sessionId,
            isAuthenticated: authReq.isAuthenticated || true,
          },
        },
      });

    } catch (error) {
      // Log profile access errors
      securityLogger.error('Profile handler error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: (req as unknown as AuthenticatedRequest).user?.id,
        ipAddress: getClientIP(req),
      });
      
      next(error);
    }
  };

  // Password reset handlers
  const initiatePasswordReset = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email } = req.body;
      
      if (!email) {
        res.status(400).json({
          error: {
            code: 'MISSING_EMAIL',
            message: 'Email is required',
          },
        });
        return;
      }

      const userAgent = req.get('User-Agent');
      await authService.initiatePasswordReset({
        email,
        ipAddress: getClientIP(req),
        ...(userAgent && { userAgent }),
      });

      // Always return success to prevent email enumeration
      res.status(200).json({
        success: true,
        message: 'If the email exists, a password reset link has been sent',
      });

    } catch (error) {
      next(error);
    }
  };

  const confirmPasswordReset = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token, newPassword, confirmPassword } = req.body;
      
      if (!token || !newPassword || !confirmPassword) {
        res.status(400).json({
          error: {
            code: 'MISSING_FIELDS',
            message: 'Token, new password, and confirm password are required',
          },
        });
        return;
      }

      await authService.confirmPasswordReset({
        token,
        newPassword,
        confirmPassword,
      });

      res.status(200).json({
        success: true,
        message: 'Password has been reset successfully',
      });

    } catch (error) {
      next(error);
    }
  };

  const validateResetToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { token } = req.params;
      
      if (!token) {
        res.status(400).json({
          error: {
            code: 'MISSING_TOKEN',
            message: 'Reset token is required',
          },
        });
        return;
      }

      const isValid = await authService.validateResetToken(token);

      res.status(200).json({
        success: true,
        data: {
          valid: isValid,
        },
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * User registration handler
   *
   * Creates a new user account with email and password. Validates required fields
   * and handles email verification requirements.
   *
   * @param req - Express request with registration data in body
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email, password, confirmPassword, firstName, lastName } = req.body;
      
      if (!email || !password || !confirmPassword) {
        auditLog('registration_validation_failed', {
          reason: 'missing_fields',
          email,
          ipAddress: getClientIP(req),
        });

        res.status(400).json({
          error: {
            code: 'MISSING_FIELDS',
            message: 'Email, password, and confirm password are required',
          },
        });
        return;
      }

      const registrationData: RegistrationData = {
        email,
        password,
        confirmPassword,
        firstName,
        lastName,
      };

      securityLogger.info('Registration handler processing request', {
        email,
        hasPassword: !!password,
        hasConfirmPassword: !!confirmPassword,
        ipAddress: getClientIP(req),
      });

      const result = await authService.register(registrationData);

      auditLog('user_registration_success', {
        userId: result.user.id,
        email: result.user.email,
        requiresVerification: result.requiresVerification,
        ipAddress: getClientIP(req),
      });

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            roles: result.user.roles,
          },
          requiresVerification: result.requiresVerification,
        },
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * Email verification handler
   *
   * Verifies user's email address using verification token.
   *
   * @param req - Express request with userId and token in body
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const verifyEmail = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { userId, token } = req.body;
      
      if (!userId || !token) {
        res.status(400).json({
          error: {
            code: 'MISSING_FIELDS',
            message: 'User ID and verification token are required',
          },
        });
        return;
      }

      securityLogger.info('Email verification handler processing request', {
        userId,
        hasToken: !!token,
        ipAddress: getClientIP(req),
      });

      const verified = await authService.verifyEmail(userId, token);

      if (verified) {
        auditLog('email_verification_success', {
          userId,
          ipAddress: getClientIP(req),
        });
      }

      res.status(200).json({
        success: true,
        data: {
          verified,
        },
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * Resend verification email handler
   *
   * Resends verification email to user. Returns success regardless of email existence
   * to prevent email enumeration attacks.
   *
   * @param req - Express request with email in body
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const resendVerification = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email } = req.body;
      
      if (!email) {
        res.status(400).json({
          error: {
            code: 'MISSING_EMAIL',
            message: 'Email is required',
          },
        });
        return;
      }

      securityLogger.info('Resend verification handler processing request', {
        email,
        ipAddress: getClientIP(req),
      });

      await authService.resendVerificationEmail(email);

      // Always return success to prevent email enumeration
      res.status(200).json({
        success: true,
        message: 'If the email exists, a verification email has been sent',
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * Get user sessions handler
   *
   * Returns all active sessions for the authenticated user.
   *
   * @param req - Express request with authenticated user
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const getUserSessions = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as unknown as AuthenticatedRequest;
      if (!authReq.user) {
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
        return;
      }

      securityLogger.info('Get user sessions handler processing request', {
        userId: authReq.user.id,
        currentSessionId: authReq.user.sessionId,
      });

      const sessions = await authService.getUserActiveSessions(authReq.user.id);

      res.status(200).json({
        success: true,
        data: {
          sessions: sessions.map(session => ({
            sessionId: session.sessionId,
            deviceInfo: session.deviceInfo,
            createdAt: session.createdAt,
            lastAccessedAt: session.lastAccessedAt,
            isCurrent: session.sessionId === authReq.user?.sessionId,
          })),
        },
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * Revoke session handler
   *
   * Revokes a specific session for the authenticated user.
   *
   * @param req - Express request with sessionId in params
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const revokeSession = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as unknown as AuthenticatedRequest;
      if (!authReq.user) {
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
        return;
      }

      const { sessionId } = req.params;
      
      if (!sessionId) {
        res.status(400).json({
          error: {
            code: 'MISSING_SESSION_ID',
            message: 'Session ID is required',
          },
        });
        return;
      }

      securityLogger.info('Revoke session handler processing request', {
        userId: authReq.user.id,
        sessionIdToRevoke: sessionId,
        currentSessionId: authReq.user.sessionId,
      });

      await authService.revokeUserSession(authReq.user.id, sessionId);

      auditLog('session_revocation_success', {
        userId: authReq.user.id,
        revokedSessionId: sessionId,
        ipAddress: getClientIP(req),
      });

      res.status(200).json({
        success: true,
        message: 'Session revoked successfully',
      });

    } catch (error) {
      next(error);
    }
  };

  /**
   * Change password handler
   *
   * Allows authenticated user to change their password.
   *
   * @param req - Express request with current and new passwords
   * @param res - Express response object
   * @param next - Express next function for error handling
   */
  const changePassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authReq = req as unknown as AuthenticatedRequest;
      if (!authReq.user) {
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
        return;
      }

      const { currentPassword, newPassword } = req.body;
      
      if (!currentPassword || !newPassword) {
        res.status(400).json({
          error: {
            code: 'MISSING_FIELDS',
            message: 'Current password and new password are required',
          },
        });
        return;
      }

      securityLogger.info('Change password handler processing request', {
        userId: authReq.user.id,
        hasCurrentPassword: !!currentPassword,
        hasNewPassword: !!newPassword,
      });

      await authService.changePassword(authReq.user.id, currentPassword, newPassword);

      auditLog('password_change_success', {
        userId: authReq.user.id,
        ipAddress: getClientIP(req),
      });

      res.status(200).json({
        success: true,
        message: 'Password changed successfully',
      });

    } catch (error) {
      next(error);
    }
  };

  // Return all handlers
  return {
    // Core auth
    login,
    refresh,
    logout,
    me,
    
    // Registration
    register,
    verifyEmail,
    resendVerification,
    
    // Password reset
    initiatePasswordReset,
    confirmPasswordReset,
    validateResetToken,
    
    // Session management
    getUserSessions,
    revokeSession,
    changePassword,
  };
}

/**
 * Authentication handlers interface
 * Defines the structure of authentication route handlers
 */
export interface AuthHandlers {
  // Core auth
  /** User login handler */
  login: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Token refresh handler */
  refresh: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** User logout handler */
  logout: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Current user profile handler */
  me: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  
  // Registration
  /** User registration handler */
  register: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Email verification handler */
  verifyEmail: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Resend verification email handler */
  resendVerification: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  
  // Password reset
  /** Password reset initiation handler */
  initiatePasswordReset: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Password reset confirmation handler */
  confirmPasswordReset: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Password reset token validation handler */
  validateResetToken: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  
  // Session management
  /** Get user active sessions handler */
  getUserSessions: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Revoke specific session handler */
  revokeSession: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  /** Change password handler */
  changePassword: (req: Request, res: Response, next: NextFunction) => Promise<void>;
}

/**
 * Default export for convenience
 */
export default createAuthHandlers;