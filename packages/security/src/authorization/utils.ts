/**
 * Authorization utilities and constants for CASL-based ACL system
 *
 * This module provides constants, utility functions, and helper methods
 * for working with permissions, roles, and authorization checks.
 *
 * @packageDocumentation
 */

import type {
  Action,
  AuthorizationCheckResult,
  Permission,
  Role,
  Subject,
  UserAbilities,
} from './types';

/**
 * Standard CRUD actions with additional business-specific actions
 */
export const ACTIONS = {
  // Core CRUD operations
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  MANAGE: 'manage',

  // List and view operations
  LIST: 'list',
  VIEW: 'view',
  EDIT: 'edit',

  // Publishing and content management
  PUBLISH: 'publish',
  ARCHIVE: 'archive',

  // Approval workflows
  APPROVE: 'approve',
  REJECT: 'reject',

  // Appointment-specific actions
  SCHEDULE: 'schedule',
  CANCEL: 'cancel',
  COMPLETE: 'complete',

  // Review and moderation
  REVIEW: 'review',
  MODERATE: 'moderate',

  // Data operations
  EXPORT: 'export',
  IMPORT: 'import',

  // System administration
  CONFIGURE: 'configure',
  ADMINISTER: 'administer',
} as const;

/**
 * Business domain subjects representing main entities
 */
export const SUBJECTS = {
  // Core entities
  USER: 'User',
  CLINIC: 'Clinic',
  PROFESSIONAL: 'Professional',

  // Appointment system
  APPOINTMENT: 'Appointment',
  PROCEDURE: 'Procedure',
  SCHEDULE: 'Schedule',

  // Reviews and feedback
  REVIEW: 'Review',

  // Financial
  PAYMENT: 'Payment',

  // Communication
  NOTIFICATION: 'Notification',

  // Reporting and analytics
  REPORT: 'Report',

  // System management
  SETTINGS: 'Settings',
  SYSTEM: 'System',

  // Special subject for global permissions
  ALL: 'all',
} as const;

/**
 * Standard role definitions for the system
 */
export const SYSTEM_ROLES = {
  // Super admin with full system access
  SUPER_ADMIN: {
    id: 'super_admin',
    name: 'Super Administrator',
    description: 'Full system access for platform management',
    isSystem: true,
    scope: 'global',
  },

  // Clinic owner with full clinic management
  CLINIC_OWNER: {
    id: 'clinic_owner',
    name: 'Clinic Owner',
    description: 'Full access to clinic management and settings',
    isSystem: true,
    scope: 'clinic',
  },

  // Clinic administrator
  CLINIC_ADMIN: {
    id: 'clinic_admin',
    name: 'Clinic Administrator',
    description: 'Administrative access to clinic operations',
    isSystem: true,
    scope: 'clinic',
  },

  // Healthcare professional
  PROFESSIONAL: {
    id: 'professional',
    name: 'Healthcare Professional',
    description: 'Access to manage appointments and procedures',
    isSystem: true,
    scope: 'clinic',
  },

  // Clinic receptionist/staff
  RECEPTIONIST: {
    id: 'receptionist',
    name: 'Receptionist',
    description: 'Access to appointment scheduling and basic management',
    isSystem: true,
    scope: 'clinic',
  },

  // Regular consumer/patient
  CONSUMER: {
    id: 'consumer',
    name: 'Consumer',
    description: 'Basic access for booking appointments and managing profile',
    isSystem: true,
    scope: 'global',
  },

  // Guest user (limited access)
  GUEST: {
    id: 'guest',
    name: 'Guest',
    description: 'Limited access for browsing public content',
    isSystem: true,
    scope: 'global',
  },
} as const;

/**
 * Common permission patterns for reuse
 */
export const PERMISSION_PATTERNS = {
  // Full CRUD access to a subject
  FULL_ACCESS: (subject: Subject): Permission[] => [{ action: ACTIONS.MANAGE, subject }],

  // Read-only access to a subject
  READ_ONLY: (subject: Subject): Permission[] => [
    { action: [ACTIONS.READ, ACTIONS.VIEW, ACTIONS.LIST], subject },
  ],

  // Basic CRUD without delete
  BASIC_CRUD: (subject: Subject): Permission[] => [
    { action: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.UPDATE], subject },
  ],

  // Appointment management permissions
  APPOINTMENT_MANAGEMENT: (): Permission[] => [
    {
      action: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.SCHEDULE],
      subject: SUBJECTS.APPOINTMENT,
    },
    { action: [ACTIONS.CANCEL, ACTIONS.COMPLETE], subject: SUBJECTS.APPOINTMENT },
    { action: ACTIONS.READ, subject: SUBJECTS.SCHEDULE },
  ],

  // Own resource access (user can only access their own resources)
  OWN_RESOURCE: (subject: Subject, userIdField = 'userId'): Permission[] => [
    {
      action: [ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.DELETE],
      subject,
      conditions: { [userIdField]: '{{ user.id }}' },
    },
  ],

  // Clinic-scoped access (user can only access resources within their clinic)
  CLINIC_SCOPED: (subject: Subject, clinicIdField = 'clinicId'): Permission[] => [
    {
      action: [ACTIONS.READ, ACTIONS.CREATE, ACTIONS.UPDATE],
      subject,
      conditions: { [clinicIdField]: '{{ user.clinicId }}' },
    },
  ],
} as const;

/**
 * Priority levels for permission resolution
 */
export const PERMISSION_PRIORITY = {
  SYSTEM: 1000,
  ROLE_INHERITED: 800,
  ROLE_DIRECT: 600,
  USER_DIRECT: 400,
  CONDITIONAL: 200,
  DEFAULT: 100,
} as const;

/**
 * Cache configuration constants
 */
export const CACHE_CONFIG = {
  DEFAULT_TTL: 300, // 5 minutes
  MAX_ENTRIES: 10000,
  CLEANUP_INTERVAL: 60000, // 1 minute
  USER_ABILITIES_PREFIX: 'auth:abilities:',
  ROLE_PERMISSIONS_PREFIX: 'auth:role:',
  PERMISSION_CHECK_PREFIX: 'auth:check:',
} as const;

/**
 * Utility functions for working with permissions
 */
export const PermissionUtils = {
  /**
   * Check if an action implies another action
   * For example, 'manage' implies all other actions
   */
  actionImplies(requiredAction: Action, userAction: Action): boolean {
    if (userAction === ACTIONS.MANAGE) {
      return true; // 'manage' implies all actions
    }

    if (userAction === requiredAction) {
      return true; // Exact match
    }

    // Define action hierarchies
    const actionHierarchy: Record<string, string[]> = {
      [ACTIONS.UPDATE]: [ACTIONS.EDIT],
      [ACTIONS.READ]: [ACTIONS.VIEW, ACTIONS.LIST],
      [ACTIONS.DELETE]: [ACTIONS.ARCHIVE],
    };

    return actionHierarchy[userAction]?.includes(requiredAction) ?? false;
  },

  /**
   * Check if a subject matches another subject
   * Handles 'all' subject and exact matches
   */
  subjectMatches(requiredSubject: Subject, permissionSubject: Subject): boolean {
    if (permissionSubject === SUBJECTS.ALL) {
      return true; // 'all' matches any subject
    }

    return permissionSubject === requiredSubject;
  },

  /**
   * Evaluate conditions against a context
   * Simple implementation - can be extended with JSON Logic or other engines
   */
  evaluateConditions(
    conditions: Record<string, unknown> | undefined,
    context: Record<string, unknown>
  ): boolean {
    if (!conditions) {
      return true; // No conditions means always true
    }

    // Simple equality check implementation
    // In production, this could use MongoDB query syntax or JSON Logic
    for (const [key, expectedValue] of Object.entries(conditions)) {
      const actualValue = this.getNestedValue(context, key);

      // Handle template values like '{{ user.id }}'
      const processedExpectedValue = this.processTemplate(expectedValue, context);

      if (actualValue !== processedExpectedValue) {
        return false;
      }
    }

    return true;
  },

  /**
   * Get nested value from object using dot notation
   */
  getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    return path.split('.').reduce((current: unknown, key: string): unknown => {
      return current && typeof current === 'object'
        ? (current as Record<string, unknown>)[key]
        : undefined;
    }, obj as unknown);
  },

  /**
   * Process template strings like '{{ user.id }}'
   */
  processTemplate(value: unknown, context: Record<string, unknown>): unknown {
    if (typeof value !== 'string') {
      return value;
    }

    const templateMatch = value.match(/^\{\{\s*(.+?)\s*\}\}$/);
    if (templateMatch && templateMatch[1]) {
      return this.getNestedValue(context, templateMatch[1]);
    }

    return value;
  },

  /**
   * Merge multiple permission arrays, removing duplicates
   */
  mergePermissions(permissionArrays: Permission[][]): Permission[] {
    const merged = permissionArrays.flat();

    // Remove duplicates based on action and subject
    const unique = merged.filter((permission, index, array) => {
      return (
        array.findIndex(
          (p) =>
            JSON.stringify([p.action, p.subject]) ===
            JSON.stringify([permission.action, permission.subject])
        ) === index
      );
    });

    // Sort by priority (higher priority first)
    return unique.sort((a, b) => (b.priority || 0) - (a.priority || 0));
  },

  /**
   * Flatten role hierarchy to get all inherited permissions
   */
  flattenRoleHierarchy(
    roles: Role[],
    targetRoleIds: string[],
    visited: Set<string> = new Set()
  ): Permission[] {
    const permissions: Permission[] = [];

    for (const roleId of targetRoleIds) {
      if (visited.has(roleId)) {
        continue; // Avoid circular dependencies
      }

      visited.add(roleId);
      const role = roles.find((r) => r.id === roleId);

      if (!role) {
        continue; // Role not found
      }

      // Add role's direct permissions
      permissions.push(...role.permissions);

      // Add inherited permissions
      if (role.inherits && role.inherits.length > 0) {
        const inheritedPermissions = this.flattenRoleHierarchy(
          roles,
          role.inherits,
          new Set(visited)
        );
        permissions.push(...inheritedPermissions);
      }
    }

    return this.mergePermissions([permissions]);
  },

  /**
   * Create a cache key for authorization checks
   */
  createCacheKey(
    userId: string,
    action: Action,
    subject: Subject,
    context?: Record<string, unknown>
  ): string {
    const contextHash = context ? this.hashObject(context) : 'no-ctx';
    return `${CACHE_CONFIG.PERMISSION_CHECK_PREFIX}${userId}:${action}:${subject}:${contextHash}`;
  },

  /**
   * Create a simple hash of an object (for cache keys)
   */
  hashObject(obj: Record<string, unknown>): string {
    return Buffer.from(JSON.stringify(obj)).toString('base64').replace(/[+/=]/g, '').slice(0, 16);
  },

  /**
   * Validate permission structure
   */
  validatePermission(permission: Permission): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!permission.action) {
      errors.push('Permission must have an action');
    }

    if (!permission.subject) {
      errors.push('Permission must have a subject');
    }

    if (permission.fields && !Array.isArray(permission.fields)) {
      errors.push('Permission fields must be an array');
    }

    if (permission.priority !== undefined && typeof permission.priority !== 'number') {
      errors.push('Permission priority must be a number');
    }

    return { valid: errors.length === 0, errors };
  },

  /**
   * Validate role structure
   */
  validateRole(role: Role): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!role.id) {
      errors.push('Role must have an id');
    }

    if (!role.name) {
      errors.push('Role must have a name');
    }

    if (!Array.isArray(role.permissions)) {
      errors.push('Role permissions must be an array');
    } else {
      role.permissions.forEach((permission, index) => {
        const validation = this.validatePermission(permission);
        if (!validation.valid) {
          errors.push(`Permission ${index}: ${validation.errors.join(', ')}`);
        }
      });
    }

    if (role.inherits && !Array.isArray(role.inherits)) {
      errors.push('Role inherits must be an array');
    }

    return { valid: errors.length === 0, errors };
  },

  /**
   * Create a successful authorization result
   */
  createSuccessResult(
    abilities: UserAbilities,
    matchedRule?: Permission & { sourceRole?: string },
    reason?: string,
    duration?: number,
    fromCache = false
  ): AuthorizationCheckResult {
    const result: AuthorizationCheckResult = {
      allowed: true,
      abilities,
      context: {
        sessionId: 'auth-check',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { source: 'authorization-check', duration, fromCache },
      },
    };

    if (matchedRule !== undefined) result.matchedRule = matchedRule;
    if (reason !== undefined) result.reason = reason;
    if (duration !== undefined) result.duration = duration;
    if (fromCache !== undefined) result.fromCache = fromCache;

    return result;
  },

  /**
   * Create a failed authorization result
   */
  createFailureResult(
    reason: string,
    abilities?: UserAbilities,
    duration?: number,
    fromCache = false
  ): AuthorizationCheckResult {
    const result: AuthorizationCheckResult = {
      allowed: false,
      reason,
      context: {
        sessionId: 'auth-check',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { source: 'authorization-check', duration, fromCache },
      },
    };

    if (abilities !== undefined) result.abilities = abilities;
    if (duration !== undefined) result.duration = duration;
    if (fromCache !== undefined) result.fromCache = fromCache;

    return result;
  },
};

/**
 * Common authorization error messages
 */
export const AUTH_ERROR_MESSAGES = {
  INSUFFICIENT_PERMISSIONS: 'Insufficient permissions to perform this action',
  INVALID_USER: 'User not found or invalid',
  INVALID_ROLE: 'Role not found or invalid',
  INVALID_PERMISSION: 'Permission structure is invalid',
  CACHE_ERROR: 'Error accessing authorization cache',
  ABILITY_COMPUTATION_ERROR: 'Error computing user abilities',
  CONDITION_EVALUATION_ERROR: 'Error evaluating permission conditions',
  CIRCULAR_ROLE_DEPENDENCY: 'Circular dependency detected in role hierarchy',
  MAX_INHERITANCE_DEPTH: 'Maximum role inheritance depth exceeded',
} as const;

/**
 * Authorization event types for auditing
 */
export const AUTH_EVENT_TYPES = {
  PERMISSION_GRANTED: 'permission_granted',
  PERMISSION_DENIED: 'permission_denied',
  ROLE_ASSIGNED: 'role_assigned',
  ROLE_REVOKED: 'role_revoked',
  PERMISSION_ADDED: 'permission_added',
  PERMISSION_REMOVED: 'permission_removed',
  CACHE_HIT: 'cache_hit',
  CACHE_MISS: 'cache_miss',
  ABILITY_COMPUTED: 'ability_computed',
  ERROR_OCCURRED: 'error_occurred',
} as const;

/**
 * Default permission configurations for different environments
 */
export const DEFAULT_CONFIGS = {
  DEVELOPMENT: {
    cacheTtl: 60, // 1 minute for faster testing
    enableAudit: true,
    strictMode: false,
    maxInheritanceDepth: 10,
  },
  PRODUCTION: {
    cacheTtl: 300, // 5 minutes
    enableAudit: true,
    strictMode: true,
    maxInheritanceDepth: 5,
  },
  TEST: {
    cacheTtl: 0, // No caching for tests
    enableAudit: false,
    strictMode: true,
    maxInheritanceDepth: 3,
  },
} as const;
