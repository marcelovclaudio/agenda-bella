/**
 * System permissions and role constants for the @agenda-bella/security package
 *
 * This module defines standardized permissions used in the authorization system
 * following a resource:action pattern for clear permission management.
 *
 * @packageDocumentation
 */

/**
 * System-wide permissions following resource:action pattern
 *
 * These permissions are used in the authorization system to control
 * access to different resources and operations within the application.
 */
export const SYSTEM_PERMISSIONS = {
  // User management permissions
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',

  // Appointment management permissions
  APPOINTMENT_CREATE: 'appointment:create',
  APPOINTMENT_READ: 'appointment:read',
  APPOINTMENT_UPDATE: 'appointment:update',
  APPOINTMENT_DELETE: 'appointment:delete',

  // Clinic management permissions
  CLINIC_MANAGE: 'clinic:manage',

  // System administration permissions
  SYSTEM_ADMIN: 'system:admin',
} as const;

/**
 * Type for permission values
 */
export type SystemPermission = (typeof SYSTEM_PERMISSIONS)[keyof typeof SYSTEM_PERMISSIONS];

/**
 * Standard role identifiers as strings
 *
 * Simple string constants for role identification,
 * corresponding to the detailed role objects in authorization module
 */
export const ROLE_IDENTIFIERS = {
  SUPER_ADMIN: 'super_admin',
  CLINIC_OWNER: 'clinic_owner',
  CLINIC_ADMIN: 'clinic_admin',
  PROFESSIONAL: 'professional',
  RECEPTIONIST: 'receptionist',
  CONSUMER: 'consumer',
  GUEST: 'guest',
} as const;

/**
 * Type for role identifier values
 */
export type RoleIdentifier = (typeof ROLE_IDENTIFIERS)[keyof typeof ROLE_IDENTIFIERS];

/**
 * Permission groups for easier management
 *
 * Groups related permissions together for role assignment and validation
 */
export const PERMISSION_GROUPS = {
  USER_MANAGEMENT: [
    SYSTEM_PERMISSIONS.USER_CREATE,
    SYSTEM_PERMISSIONS.USER_READ,
    SYSTEM_PERMISSIONS.USER_UPDATE,
    SYSTEM_PERMISSIONS.USER_DELETE,
  ],
  APPOINTMENT_MANAGEMENT: [
    SYSTEM_PERMISSIONS.APPOINTMENT_CREATE,
    SYSTEM_PERMISSIONS.APPOINTMENT_READ,
    SYSTEM_PERMISSIONS.APPOINTMENT_UPDATE,
    SYSTEM_PERMISSIONS.APPOINTMENT_DELETE,
  ],
  CLINIC_OPERATIONS: [SYSTEM_PERMISSIONS.CLINIC_MANAGE],
  SYSTEM_OPERATIONS: [SYSTEM_PERMISSIONS.SYSTEM_ADMIN],
} as const;

/**
 * Default role-permission mappings
 *
 * Defines which permissions are associated with each role by default
 */
export const DEFAULT_ROLE_PERMISSIONS = {
  [ROLE_IDENTIFIERS.SUPER_ADMIN]: [
    ...PERMISSION_GROUPS.USER_MANAGEMENT,
    ...PERMISSION_GROUPS.APPOINTMENT_MANAGEMENT,
    ...PERMISSION_GROUPS.CLINIC_OPERATIONS,
    ...PERMISSION_GROUPS.SYSTEM_OPERATIONS,
  ],
  [ROLE_IDENTIFIERS.CLINIC_OWNER]: [
    ...PERMISSION_GROUPS.USER_MANAGEMENT,
    ...PERMISSION_GROUPS.APPOINTMENT_MANAGEMENT,
    ...PERMISSION_GROUPS.CLINIC_OPERATIONS,
  ],
  [ROLE_IDENTIFIERS.CLINIC_ADMIN]: [
    ...PERMISSION_GROUPS.USER_MANAGEMENT,
    ...PERMISSION_GROUPS.APPOINTMENT_MANAGEMENT,
  ],
  [ROLE_IDENTIFIERS.PROFESSIONAL]: [
    SYSTEM_PERMISSIONS.APPOINTMENT_CREATE,
    SYSTEM_PERMISSIONS.APPOINTMENT_READ,
    SYSTEM_PERMISSIONS.APPOINTMENT_UPDATE,
    SYSTEM_PERMISSIONS.USER_READ,
  ],
  [ROLE_IDENTIFIERS.RECEPTIONIST]: [
    SYSTEM_PERMISSIONS.APPOINTMENT_CREATE,
    SYSTEM_PERMISSIONS.APPOINTMENT_READ,
    SYSTEM_PERMISSIONS.APPOINTMENT_UPDATE,
    SYSTEM_PERMISSIONS.USER_READ,
  ],
  [ROLE_IDENTIFIERS.CONSUMER]: [SYSTEM_PERMISSIONS.APPOINTMENT_READ, SYSTEM_PERMISSIONS.USER_READ],
  [ROLE_IDENTIFIERS.GUEST]: [
    // No default permissions for guests
  ],
} as const;
