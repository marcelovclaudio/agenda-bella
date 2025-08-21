/**
 * Authorization and ACL module for CASL-based access control
 *
 * This module provides comprehensive authorization utilities including:
 * - Type definitions for permissions, roles, and abilities
 * - Utility functions for permission evaluation and management
 * - Constants and patterns for common authorization scenarios
 * - Integration with CASL ability system
 *
 * @packageDocumentation
 */

// Export all types and interfaces
export type {
  Action,
  Subject,
  Permission,
  Role,
  UserAbilities,
  ClinicAssociation,
  AuthorizationRequest,
  AuthorizationCheckResult,
  BulkAuthorizationRequest,
  BulkAuthorizationResult,
  PermissionContext,
  PermissionResolver,
  AuthorizationCacheEntry,
  AuthorizationMiddlewareOptions,
  RoleManagementOptions,
  PermissionQueryOptions,
  AuthorizationAuditEvent,
  ResourceAccessPolicy,
  ConditionalPermission,
  PermissionInheritanceConfig,
  AuthorizationMetrics,
} from './types';

// Export utility functions and constants
export {
  ACTIONS,
  SUBJECTS,
  SYSTEM_ROLES,
  PERMISSION_PATTERNS,
  PERMISSION_PRIORITY,
  CACHE_CONFIG,
  PermissionUtils,
  AUTH_ERROR_MESSAGES,
  AUTH_EVENT_TYPES,
  DEFAULT_CONFIGS,
} from './utils';
