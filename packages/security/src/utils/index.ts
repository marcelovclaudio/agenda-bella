/**
 * Security utility functions
 * @packageDocumentation
 */

// Re-export utilities from shared package
import { createChildLogger, type Logger } from '@agenda-bella/shared';
import type { SecurityError } from '../types/errors.types';

export const securityLogger: Logger = createChildLogger({
  component: 'security',
  package: '@agenda-bella/security',
});

// Audit logging utility
export const auditLog = (action: string, context: Record<string, unknown>): void => {
  securityLogger.info('AUDIT', {
    action,
    timestamp: new Date().toISOString(),
    ...context,
  });
};

// Error logging utility
export const logSecurityError = (error: SecurityError, context?: Record<string, unknown>): void => {
  securityLogger.error('SECURITY_ERROR', {
    code: error.code,
    message: error.message,
    statusCode: error.statusCode,
    stack: error.stack,
    timestamp: error.timestamp.toISOString(),
    context: error.context,
    ...context,
  });
};

// Security metrics
export const trackSecurityMetric = (
  metric: string,
  value: number,
  tags?: Record<string, string>
): void => {
  securityLogger.info('SECURITY_METRIC', {
    metric,
    value,
    tags,
    timestamp: new Date().toISOString(),
  });
};

// Export error handling utilities (from errors.ts)
export * from './errors';

// Export cryptographic utilities (from crypto.ts)
export * from './crypto';

// Export validation utilities (from validation.ts)
export * from './validation';
