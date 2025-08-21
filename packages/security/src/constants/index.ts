/**
 * Security constants module for the @agenda-bella/security package
 *
 * This module provides security-related constants that are used across
 * the security package modules, organized by category for easy access.
 *
 * @packageDocumentation
 */

// Error codes and messages
export * from './errors';
export type { ErrorCode } from './errors';

// System permissions and roles
export * from './permissions';
export type { SystemPermission, RoleIdentifier } from './permissions';

// Security configuration defaults
export * from './security';
export type { CryptoAlgorithm } from './security';

// Re-export main constants for convenience
export { ERROR_CODES, ERROR_MESSAGES } from './errors';
export {
  SYSTEM_PERMISSIONS,
  ROLE_IDENTIFIERS,
  PERMISSION_GROUPS,
  DEFAULT_ROLE_PERMISSIONS,
} from './permissions';
export {
  SECURITY_DEFAULTS,
  SECURITY_HEADERS,
  CRYPTO_ALGORITHMS,
  ENVIRONMENT_SECURITY,
} from './security';
