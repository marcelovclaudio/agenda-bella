/**
 * Middleware module for the @agenda-bella/security package
 *
 * This module provides basic middleware types and utilities for Express applications
 * as specified in SUB-SEC-001-09.
 *
 * @packageDocumentation
 */

// Export all types and interfaces
export type {
  SecurityMiddlewareConfig,
  ExpressMiddleware,
  ExpressErrorMiddleware,
  SecurityMiddleware,
} from './types';

// Export all utility functions and constants
export {
  DEFAULT_HELMET_CONFIG,
  extractBearerToken,
  getClientIP,
  createErrorHandler,
} from './utils';
