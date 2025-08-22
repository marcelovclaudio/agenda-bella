/**
 * Route Protection Helpers
 *
 * This module provides comprehensive route protection middleware functions for
 * Express.js applications, including role-based access control, permission-based
 * authorization, and resource ownership validation.
 *
 * @packageDocumentation
 */

import type { Request, Response, NextFunction } from 'express';
import { AuthorizationError, AuthenticationError } from '../types/errors.types';
import { securityLogger, auditLog } from '../utils';
import type { AuthenticatedUser } from './types';

/**
 * Extended Request interface with authenticated user for route guards
 * Extends Express Request with authentication information
 */
export interface GuardAuthenticatedRequest extends Request {
  /** Authenticated user information */
  user?: AuthenticatedUser;
}

/**
 * Resource ownership checker function type
 * Function that determines if a user owns/can access a specific resource
 */
export type OwnershipChecker = (
  req: GuardAuthenticatedRequest
) => Promise<string | boolean> | string | boolean;

/**
 * Role-based access control middleware
 *
 * Ensures that the authenticated user has the specified role before allowing
 * access to a protected route. Provides comprehensive security logging.
 *
 * @param requiredRole - Role that the user must have
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * app.get('/admin', requireAuth(authService), requireRole('admin'), handler);
 * ```
 */
export function requireRole(requiredRole: string) {
  return (req: GuardAuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      securityLogger.warn('Authorization failed - no authenticated user', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requiredRole,
      });

      return next(
        new AuthenticationError('Authentication required', undefined, {
          code: 'AUTH_REQUIRED',
          requiredRole,
          path: req.path,
        })
      );
    }

    if (!req.user.roles.includes(requiredRole)) {
      securityLogger.warn('Role authorization failed', {
        userId: req.user.id,
        requiredRole,
        userRoles: req.user.roles,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      auditLog('ROLE_AUTHORIZATION_FAILED', {
        userId: req.user.id,
        requiredRole,
        userRoles: req.user.roles,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });

      return next(
        new AuthorizationError(`Role '${requiredRole}' required`, undefined, {
          code: 'INSUFFICIENT_ROLE',
          requiredRole,
          userRoles: req.user.roles,
          path: req.path,
        })
      );
    }

    securityLogger.debug('Role authorization successful', {
      userId: req.user.id,
      requiredRole,
      path: req.path,
      method: req.method,
    });

    auditLog('ROLE_AUTHORIZATION_SUCCESS', {
      userId: req.user.id,
      requiredRole,
      path: req.path,
      method: req.method,
    });

    next();
  };
}

/**
 * Multiple role-based access control middleware
 *
 * Ensures that the authenticated user has at least one of the specified roles
 * before allowing access to a protected route. Useful for routes that can be
 * accessed by multiple role types.
 *
 * @param requiredRoles - Array of roles, user must have at least one
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * app.get('/content', requireAuth(authService), requireAnyRole(['admin', 'editor']), handler);
 * ```
 */
export function requireAnyRole(requiredRoles: string[]) {
  return (req: GuardAuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      securityLogger.warn('Authorization failed - no authenticated user', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requiredRoles,
      });

      return next(
        new AuthenticationError('Authentication required', undefined, {
          code: 'AUTH_REQUIRED',
          requiredRoles,
          path: req.path,
        })
      );
    }

    const hasRole = requiredRoles.some(role => req.user!.roles.includes(role));

    if (!hasRole) {
      securityLogger.warn('Multiple role authorization failed', {
        userId: req.user.id,
        requiredRoles,
        userRoles: req.user.roles,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      auditLog('MULTI_ROLE_AUTHORIZATION_FAILED', {
        userId: req.user.id,
        requiredRoles,
        userRoles: req.user.roles,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });

      return next(
        new AuthorizationError(`One of roles [${requiredRoles.join(', ')}] required`, undefined, {
          code: 'INSUFFICIENT_ROLES',
          requiredRoles,
          userRoles: req.user.roles,
          path: req.path,
        })
      );
    }

    securityLogger.debug('Multiple role authorization successful', {
      userId: req.user.id,
      requiredRoles,
      matchedRoles: req.user.roles.filter((role: string) => requiredRoles.includes(role)),
      path: req.path,
      method: req.method,
    });

    auditLog('MULTI_ROLE_AUTHORIZATION_SUCCESS', {
      userId: req.user.id,
      requiredRoles,
      matchedRoles: req.user.roles.filter((role: string) => requiredRoles.includes(role)),
      path: req.path,
      method: req.method,
    });

    next();
  };
}

/**
 * Permission-based access control middleware
 *
 * Ensures that the authenticated user has the specified permission before
 * allowing access to a protected route. Provides fine-grained access control
 * beyond role-based authorization.
 *
 * @param requiredPermission - Permission that the user must have
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * app.post('/users', requireAuth(authService), requirePermission('user:create'), handler);
 * ```
 */
export function requirePermission(requiredPermission: string) {
  return (req: GuardAuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      securityLogger.warn('Authorization failed - no authenticated user', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requiredPermission,
      });

      return next(
        new AuthenticationError('Authentication required', undefined, {
          code: 'AUTH_REQUIRED',
          requiredPermission,
          path: req.path,
        })
      );
    }

    if (!req.user.permissions.includes(requiredPermission)) {
      securityLogger.warn('Permission authorization failed', {
        userId: req.user.id,
        requiredPermission,
        userPermissions: req.user.permissions,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      auditLog('PERMISSION_AUTHORIZATION_FAILED', {
        userId: req.user.id,
        requiredPermission,
        userPermissions: req.user.permissions,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });

      return next(
        new AuthorizationError(`Permission '${requiredPermission}' required`, undefined, {
          code: 'INSUFFICIENT_PERMISSION',
          requiredPermission,
          userPermissions: req.user.permissions,
          path: req.path,
        })
      );
    }

    securityLogger.debug('Permission authorization successful', {
      userId: req.user.id,
      requiredPermission,
      path: req.path,
      method: req.method,
    });

    auditLog('PERMISSION_AUTHORIZATION_SUCCESS', {
      userId: req.user.id,
      requiredPermission,
      path: req.path,
      method: req.method,
    });

    next();
  };
}

/**
 * Resource ownership validation middleware
 *
 * Ensures that the authenticated user owns or has access to the specific resource
 * being requested. Uses a custom ownership checker function to determine access.
 *
 * @param ownershipChecker - Function that checks if user owns the resource
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * app.get('/users/:id', requireAuth(authService), requireOwnership((req) => {
 *   return req.params.id === req.user.id;
 * }), handler);
 * 
 * // Or with async database checks
 * app.get('/posts/:id', requireAuth(authService), requireOwnership(async (req) => {
 *   const post = await getPost(req.params.id);
 *   return post.authorId === req.user.id;
 * }), handler);
 * ```
 */
export function requireOwnership(ownershipChecker: OwnershipChecker) {
  return async (req: GuardAuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      securityLogger.warn('Ownership check failed - no authenticated user', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      return next(
        new AuthenticationError('Authentication required', undefined, {
          code: 'AUTH_REQUIRED',
          path: req.path,
        })
      );
    }

    try {
      const ownershipResult = await ownershipChecker(req);

      if (!ownershipResult) {
        securityLogger.warn('Resource ownership validation failed', {
          userId: req.user.id,
          path: req.path,
          method: req.method,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          resourceParams: req.params,
        });

        auditLog('OWNERSHIP_AUTHORIZATION_FAILED', {
          userId: req.user.id,
          path: req.path,
          method: req.method,
          ip: req.ip,
          resourceParams: req.params,
        });

        return next(
          new AuthorizationError('Access denied - insufficient ownership', undefined, {
            code: 'INSUFFICIENT_OWNERSHIP',
            path: req.path,
            resourceParams: req.params,
          })
        );
      }

      securityLogger.debug('Resource ownership validation successful', {
        userId: req.user.id,
        path: req.path,
        method: req.method,
        ownershipResult: typeof ownershipResult === 'string' ? 'owner_id_match' : 'boolean_true',
      });

      auditLog('OWNERSHIP_AUTHORIZATION_SUCCESS', {
        userId: req.user.id,
        path: req.path,
        method: req.method,
        resourceParams: req.params,
      });

      next();
    } catch (error) {
      securityLogger.error('Ownership check error', {
        userId: req.user.id,
        path: req.path,
        method: req.method,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      return next(
        new AuthorizationError('Ownership validation failed', undefined, {
          code: 'OWNERSHIP_CHECK_ERROR',
          originalError: error instanceof Error ? error.message : 'Unknown error',
          path: req.path,
        })
      );
    }
  };
}

/**
 * Check if user has specific capability or permission
 *
 * Utility function to check if an authenticated user has a specific permission
 * or role. Can be used within route handlers for conditional logic.
 *
 * @param user - Authenticated user object
 * @param capability - Role or permission to check
 * @returns True if user has the capability
 *
 * @example
 * ```typescript
 * app.get('/data', requireAuth(authService), (req, res) => {
 *   const data = getData();
 *   
 *   if (canUser(req.user, 'admin')) {
 *     // Include sensitive admin data
 *     data.adminInfo = getAdminData();
 *   }
 *   
 *   res.json(data);
 * });
 * ```
 */
export function canUser(user: AuthenticatedUser | undefined, capability: string): boolean {
  if (!user) {
    return false;
  }

  const hasRole = user.roles.includes(capability);
  const hasPermission = user.permissions.includes(capability);

  securityLogger.debug('User capability check', {
    userId: user.id,
    capability,
    hasRole,
    hasPermission,
    result: hasRole || hasPermission,
  });

  return hasRole || hasPermission;
}

/**
 * Check if user has specific role
 *
 * Utility function to check if an authenticated user has a specific role.
 * More explicit than canUser when specifically checking for roles.
 *
 * @param user - Authenticated user object
 * @param role - Role to check
 * @returns True if user has the role
 *
 * @example
 * ```typescript
 * app.get('/dashboard', requireAuth(authService), (req, res) => {
 *   if (hasRole(req.user, 'admin')) {
 *     return res.render('admin-dashboard');
 *   }
 *   
 *   res.render('user-dashboard');
 * });
 * ```
 */
export function hasRole(user: AuthenticatedUser | undefined, role: string): boolean {
  if (!user) {
    return false;
  }

  const result = user.roles.includes(role);

  securityLogger.debug('User role check', {
    userId: user.id,
    role,
    userRoles: user.roles,
    result,
  });

  return result;
}

/**
 * Check if user has any of the specified roles
 *
 * Utility function to check if an authenticated user has at least one of the
 * specified roles. Useful for conditional logic within route handlers.
 *
 * @param user - Authenticated user object
 * @param roles - Array of roles to check
 * @returns True if user has at least one of the roles
 *
 * @example
 * ```typescript
 * app.get('/content', requireAuth(authService), (req, res) => {
 *   if (hasAnyRole(req.user, ['admin', 'editor', 'moderator'])) {
 *     return res.json(getFullContent());
 *   }
 *   
 *   res.json(getPublicContent());
 * });
 * ```
 */
export function hasAnyRole(user: AuthenticatedUser | undefined, roles: string[]): boolean {
  if (!user) {
    return false;
  }

  const matchedRoles = user.roles.filter((role: string) => roles.includes(role));
  const result = matchedRoles.length > 0;

  securityLogger.debug('User multiple role check', {
    userId: user.id,
    requiredRoles: roles,
    userRoles: user.roles,
    matchedRoles,
    result,
  });

  return result;
}

/**
 * Check if user has specific permission
 *
 * Utility function to check if an authenticated user has a specific permission.
 * More explicit than canUser when specifically checking for permissions.
 *
 * @param user - Authenticated user object
 * @param permission - Permission to check
 * @returns True if user has the permission
 *
 * @example
 * ```typescript
 * app.get('/users', requireAuth(authService), (req, res) => {
 *   const users = getUsers();
 *   
 *   if (hasPermission(req.user, 'user:read_sensitive')) {
 *     // Include sensitive user data
 *     users.forEach(user => {
 *       user.sensitiveData = getSensitiveData(user.id);
 *     });
 *   }
 *   
 *   res.json(users);
 * });
 * ```
 */
export function hasPermission(user: AuthenticatedUser | undefined, permission: string): boolean {
  if (!user) {
    return false;
  }

  const result = user.permissions.includes(permission);

  securityLogger.debug('User permission check', {
    userId: user.id,
    permission,
    userPermissions: user.permissions,
    result,
  });

  return result;
}

/**
 * Create combined role and permission middleware
 *
 * Factory function that creates middleware requiring both a specific role
 * and permission. Useful for highly sensitive operations.
 *
 * @param role - Required role
 * @param permission - Required permission
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * app.delete('/users/:id', requireAuth(authService), requireRoleAndPermission('admin', 'user:delete'), handler);
 * ```
 */
export function requireRoleAndPermission(role: string, permission: string) {
  return (req: GuardAuthenticatedRequest, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(
        new AuthenticationError('Authentication required', undefined, {
          code: 'AUTH_REQUIRED',
          requiredRole: role,
          requiredPermission: permission,
          path: req.path,
        })
      );
    }

    const hasRequiredRole = req.user.roles.includes(role);
    const hasRequiredPermission = req.user.permissions.includes(permission);

    if (!hasRequiredRole || !hasRequiredPermission) {
      securityLogger.warn('Combined role and permission authorization failed', {
        userId: req.user.id,
        requiredRole: role,
        requiredPermission: permission,
        hasRole: hasRequiredRole,
        hasPermission: hasRequiredPermission,
        userRoles: req.user.roles,
        userPermissions: req.user.permissions,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });

      auditLog('COMBINED_AUTHORIZATION_FAILED', {
        userId: req.user.id,
        requiredRole: role,
        requiredPermission: permission,
        hasRole: hasRequiredRole,
        hasPermission: hasRequiredPermission,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });

      return next(
        new AuthorizationError(
          `Both role '${role}' and permission '${permission}' required`,
          undefined,
          {
            code: 'INSUFFICIENT_ROLE_AND_PERMISSION',
            requiredRole: role,
            requiredPermission: permission,
            hasRole: hasRequiredRole,
            hasPermission: hasRequiredPermission,
            path: req.path,
          }
        )
      );
    }

    securityLogger.debug('Combined role and permission authorization successful', {
      userId: req.user.id,
      requiredRole: role,
      requiredPermission: permission,
      path: req.path,
      method: req.method,
    });

    auditLog('COMBINED_AUTHORIZATION_SUCCESS', {
      userId: req.user.id,
      requiredRole: role,
      requiredPermission: permission,
      path: req.path,
      method: req.method,
    });

    next();
  };
}