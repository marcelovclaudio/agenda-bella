/**
 * Express Authentication Middleware
 *
 * This module provides Express middleware for JWT-based authentication with comprehensive
 * error handling, security logging, and audit trails. It integrates with the AuthService
 * and extends Express Request types for type safety.
 *
 * @packageDocumentation
 */

import type { Request, Response, NextFunction } from 'express';
import { AuthService } from './service';
import { extractBearerToken } from '../middleware/utils';
import { AuthenticationError } from '../types/errors.types';
import { securityLogger } from '../utils';
import type { AuthenticatedUser } from './types';
import type { SecurityContext } from '../types';

/**
 * Create security context from Express request
 * @param req - Express request object
 * @returns Security context object
 */
function createRequestSecurityContext(req: Request): SecurityContext {
  const userAgent = req.headers['user-agent'];
  // Use req.session?.id if available (from express-session), otherwise generate a default
  const sessionId = (req as any).sessionID || (req as any).session?.id || 'anonymous';
  
  const context: SecurityContext = {
    sessionId,
    ipAddress: req.ip || 'unknown',
    timestamp: new Date(),
  };

  if (typeof userAgent === 'string') {
    context.userAgent = userAgent;
  }

  return context;
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      authContext?: {
        token: string;
        isAuthenticated: boolean;
        sessionId?: string;
      };
    }
  }
}

/**
 * Creates an Express authentication middleware that validates JWT tokens
 * and attaches user information to the request object.
 *
 * This middleware:
 * - Extracts Bearer tokens from Authorization headers
 * - Validates tokens using the AuthService
 * - Attaches authenticated user data to req.user
 * - Provides comprehensive error handling and logging
 * - Supports audit trails for security monitoring
 *
 * @param authService - Configured AuthService instance for token validation
 * @returns Express middleware function for authentication
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createAuthMiddleware, createAuthService } from '@agenda-bella/security';
 *
 * const app = express();
 * const authService = createAuthService(jwtConfig, userRepo, sessionRepo);
 * const authMiddleware = createAuthMiddleware(authService);
 *
 * // Protect all routes after this middleware
 * app.use('/api/protected', authMiddleware);
 *
 * // Or protect specific routes
 * app.get('/api/profile', authMiddleware, (req, res) => {
 *   // req.user is now available with authenticated user data
 *   res.json({ user: req.user });
 * });
 * ```
 */
export function createAuthMiddleware(authService: AuthService) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req.headers.authorization);
      
      if (!token) {
        req.authContext = { token: '', isAuthenticated: false };
        
        securityLogger.warn('Authentication failed - no token provided', {
          path: req.path,
          method: req.method,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
        
        throw new AuthenticationError('No authentication token provided', 
          createRequestSecurityContext(req), 
          {
            code: 'MISSING_TOKEN',
          }
        );
      }

      // Validate token and get user
      const user = await authService.validateAccessToken(token);
      
      // Attach user and context to request
      req.user = user;
      req.authContext = {
        token,
        isAuthenticated: true,
        sessionId: user.sessionId,
      };

      securityLogger.debug('Authentication successful', {
        userId: user.id,
        path: req.path,
        method: req.method,
        sessionId: user.sessionId,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        roles: user.roles,
        permissionsCount: user.permissions.length,
      });

      next();
    } catch (error) {
      if (error instanceof AuthenticationError) {
        securityLogger.warn('Authentication failed', {
          path: req.path,
          method: req.method,
          error: error.message,
          code: error.code,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          timestamp: error.timestamp.toISOString(),
        });

        res.status(error.statusCode).json({
          error: {
            code: error.code,
            message: error.message,
            timestamp: error.timestamp.toISOString(),
          },
        });
        return;
      }

      securityLogger.error('Authentication middleware error', {
        path: req.path,
        method: req.method,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      res.status(500).json({
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Authentication failed',
          timestamp: new Date().toISOString(),
        },
      });
    }
  };
}

/**
 * Creates an optional authentication middleware that allows requests to proceed
 * even if authentication fails, but still attaches user information when available.
 *
 * This middleware:
 * - Does not throw errors for missing or invalid tokens
 * - Sets req.user when valid authentication is present
 * - Sets req.authContext.isAuthenticated appropriately
 * - Useful for endpoints that work for both authenticated and anonymous users
 *
 * @param authService - Configured AuthService instance for token validation
 * @returns Express middleware function for optional authentication
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createOptionalAuthMiddleware, createAuthService } from '@agenda-bella/security';
 *
 * const app = express();
 * const authService = createAuthService(jwtConfig, userRepo, sessionRepo);
 * const optionalAuth = createOptionalAuthMiddleware(authService);
 *
 * // Allow both authenticated and anonymous access
 * app.get('/api/public', optionalAuth, (req, res) => {
 *   if (req.authContext?.isAuthenticated && req.user) {
 *     res.json({ message: 'Hello authenticated user', user: req.user });
 *   } else {
 *     res.json({ message: 'Hello anonymous user' });
 *   }
 * });
 * ```
 */
export function createOptionalAuthMiddleware(authService: AuthService) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req.headers.authorization);
      
      if (!token) {
        req.authContext = { token: '', isAuthenticated: false };
        
        securityLogger.debug('Optional authentication - no token provided', {
          path: req.path,
          method: req.method,
          ipAddress: req.ip,
        });
        
        next();
        return;
      }

      // Attempt to validate token and get user
      const user = await authService.validateAccessToken(token);
      
      // Attach user and context to request
      req.user = user;
      req.authContext = {
        token,
        isAuthenticated: true,
        sessionId: user.sessionId,
      };

      securityLogger.debug('Optional authentication successful', {
        userId: user.id,
        path: req.path,
        method: req.method,
        sessionId: user.sessionId,
        ipAddress: req.ip,
      });

      next();
    } catch (error) {
      // For optional auth, we don't throw errors - just set as unauthenticated
      req.authContext = { token: '', isAuthenticated: false };
      
      if (error instanceof AuthenticationError) {
        securityLogger.debug('Optional authentication failed', {
          path: req.path,
          method: req.method,
          error: error.message,
          code: error.code,
          ipAddress: req.ip,
        });
      } else {
        securityLogger.warn('Optional authentication middleware error', {
          path: req.path,
          method: req.method,
          error: error instanceof Error ? error.message : 'Unknown error',
          ipAddress: req.ip,
        });
      }

      next();
    }
  };
}

/**
 * Creates a role-based authentication middleware that requires specific roles
 * in addition to valid authentication.
 *
 * This middleware:
 * - First validates authentication like createAuthMiddleware
 * - Then checks if the user has any of the required roles
 * - Returns 403 Forbidden if user lacks required roles
 * - Supports multiple roles (user needs at least one)
 *
 * @param authService - Configured AuthService instance for token validation
 * @param requiredRoles - Array of roles, user must have at least one
 * @returns Express middleware function for role-based authentication
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createRoleAuthMiddleware, createAuthService } from '@agenda-bella/security';
 *
 * const app = express();
 * const authService = createAuthService(jwtConfig, userRepo, sessionRepo);
 * const adminAuth = createRoleAuthMiddleware(authService, ['admin']);
 * const moderatorAuth = createRoleAuthMiddleware(authService, ['admin', 'moderator']);
 *
 * // Only admin users can access
 * app.delete('/api/admin/users/:id', adminAuth, deleteUserHandler);
 *
 * // Admin or moderator users can access
 * app.post('/api/moderate/content', moderatorAuth, moderateContentHandler);
 * ```
 */
export function createRoleAuthMiddleware(authService: AuthService, requiredRoles: string[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req.headers.authorization);
      
      if (!token) {
        req.authContext = { token: '', isAuthenticated: false };
        
        securityLogger.warn('Role-based authentication failed - no token provided', {
          path: req.path,
          method: req.method,
          requiredRoles,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
        
        throw new AuthenticationError('No authentication token provided', 
          createRequestSecurityContext(req), 
          {
            code: 'MISSING_TOKEN',
          }
        );
      }

      // Validate token and get user
      const user = await authService.validateAccessToken(token);
      
      // Check if user has any of the required roles
      const hasRequiredRole = requiredRoles.some(role => user.roles.includes(role));
      
      if (!hasRequiredRole) {
        securityLogger.warn('Role-based authentication failed - insufficient roles', {
          userId: user.id,
          path: req.path,
          method: req.method,
          userRoles: user.roles,
          requiredRoles,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        });
        
        res.status(403).json({
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Access denied: insufficient permissions',
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }
      
      // Attach user and context to request
      req.user = user;
      req.authContext = {
        token,
        isAuthenticated: true,
        sessionId: user.sessionId,
      };

      securityLogger.debug('Role-based authentication successful', {
        userId: user.id,
        path: req.path,
        method: req.method,
        sessionId: user.sessionId,
        userRoles: user.roles,
        requiredRoles,
        ipAddress: req.ip,
      });

      next();
    } catch (error) {
      if (error instanceof AuthenticationError) {
        securityLogger.warn('Role-based authentication failed', {
          path: req.path,
          method: req.method,
          error: error.message,
          code: error.code,
          requiredRoles,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          timestamp: error.timestamp.toISOString(),
        });

        res.status(error.statusCode).json({
          error: {
            code: error.code,
            message: error.message,
            timestamp: error.timestamp.toISOString(),
          },
        });
        return;
      }

      securityLogger.error('Role-based authentication middleware error', {
        path: req.path,
        method: req.method,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        requiredRoles,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      res.status(500).json({
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Authentication failed',
          timestamp: new Date().toISOString(),
        },
      });
    }
  };
}

/**
 * Default export for the main authentication middleware creator
 */
export default createAuthMiddleware;