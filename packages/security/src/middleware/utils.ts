/**
 * Middleware utilities for the security package
 *
 * This module provides utility functions and default configurations for middleware
 * as specified in SUB-SEC-001-09.
 *
 * @packageDocumentation
 */

import type { SecurityContext } from '../types';
import { isSecurityError } from '../types';
import type {
  ExpressErrorMiddleware,
  ExpressNextFunction,
  ExpressRequest,
  ExpressResponse,
  HelmetConfig,
} from './types';

/**
 * Default Helmet configuration with recommended security settings
 */
export const DEFAULT_HELMET_CONFIG: HelmetConfig = {
  contentSecurityPolicy: true,
  crossOriginEmbedderPolicy: true,
  dnsPrefetchControl: true,
  frameguard: true,
  hidePoweredBy: true,
  hsts: true,
  ieNoOpen: true,
  noSniff: true,
  xssFilter: true,
};

/**
 * Extract Bearer token from Authorization header
 * @param authHeader - Authorization header value
 * @returns Bearer token or null if not found
 */
export const extractBearerToken = (authHeader?: string): string | null => {
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
};

/**
 * Extract client IP address from request
 * @param req - Express request object
 * @returns Client IP address
 */
export const getClientIP = (req: ExpressRequest): string => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const firstIP = forwarded.split(',')[0];
    return firstIP ? firstIP.trim() : 'unknown';
  }
  return req.socket?.remoteAddress ?? 'unknown';
};

/**
 * Create security context from Express request
 * @param req - Express request object
 * @returns Security context object
 */
export const createSecurityContext = (req: ExpressRequest): SecurityContext => {
  const userAgent = req.headers['user-agent'];
  const context: SecurityContext = {
    sessionId: req.sessionID ?? 'anonymous',
    ipAddress: getClientIP(req),
    timestamp: new Date(),
  };

  if (typeof userAgent === 'string') {
    context.userAgent = userAgent;
  }

  return context;
};

/**
 * Create error handler middleware using SecurityError classes
 * @returns Express error middleware
 */
export const createErrorHandler = (): ExpressErrorMiddleware => {
  return (err: Error, _req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
    if (isSecurityError(err)) {
      res.status(err.statusCode).json({
        error: {
          code: err.code,
          message: err.message,
          timestamp: err.timestamp,
        },
      });
      return;
    }

    next(err);
  };
};
