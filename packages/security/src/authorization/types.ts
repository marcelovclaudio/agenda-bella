/**
 * Authorization types and interfaces for CASL-based ACL system
 *
 * This module provides comprehensive type definitions for role-based access control (RBAC),
 * attribute-based access control (ABAC), and permission management using CASL abilities.
 *
 * @packageDocumentation
 */

import type { SecurityContext, SecurityError } from '../types';

/**
 * Available actions that can be performed on subjects
 * Based on CRUD operations plus additional business actions
 */
export type Action =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'manage'
  | 'list'
  | 'view'
  | 'edit'
  | 'publish'
  | 'archive'
  | 'approve'
  | 'reject'
  | 'schedule'
  | 'cancel'
  | 'complete'
  | 'review'
  | 'moderate'
  | 'export'
  | 'import'
  | 'configure'
  | 'administer';

/**
 * Business domain subjects that can be acted upon
 * Represents the main entities in the agenda system
 */
export type Subject =
  | 'User'
  | 'Clinic'
  | 'Professional'
  | 'Appointment'
  | 'Procedure'
  | 'Review'
  | 'Schedule'
  | 'Payment'
  | 'Notification'
  | 'Report'
  | 'Settings'
  | 'System'
  | 'all';

/**
 * Permission definition with optional conditions for attribute-based access
 * Compatible with CASL ability definitions
 */
export interface Permission {
  /** The action that can be performed */
  action: Action | Action[];
  /** The subject the action can be performed on */
  subject: Subject | Subject[];
  /** Optional conditions for conditional permissions */
  conditions?: Record<string, unknown>;
  /** Optional field-level restrictions */
  fields?: string[];
  /** Whether this permission is inverted (forbidden) */
  inverted?: boolean;
  /** Permission priority for conflict resolution */
  priority?: number;
  /** Human-readable reason for the permission */
  reason?: string;
}

/**
 * Role definition with associated permissions and metadata
 * Supports hierarchical role inheritance
 */
export interface Role {
  /** Unique role identifier */
  id: string;
  /** Human-readable role name */
  name: string;
  /** Role description for documentation */
  description?: string;
  /** Permissions granted by this role */
  permissions: Permission[];
  /** Parent roles for inheritance */
  inherits?: string[];
  /** Whether this role is a system role (cannot be deleted) */
  isSystem?: boolean;
  /** Role scope (global, clinic-specific, etc.) */
  scope?: 'global' | 'clinic' | 'organization';
  /** Role metadata */
  metadata?: Record<string, unknown>;
  /** When the role was created */
  createdAt?: Date;
  /** When the role was last updated */
  updatedAt?: Date;
}

/**
 * User abilities combining roles and direct permissions
 * Represents the complete authorization context for a user
 */
export interface UserAbilities {
  /** User identifier */
  userId: string;
  /** User roles (role IDs) */
  roles: string[];
  /** Direct permissions assigned to the user */
  permissions: Permission[];
  /** Contextual attributes for ABAC */
  attributes?: Record<string, unknown>;
  /** User's clinic associations for multi-tenancy */
  clinicAssociations?: ClinicAssociation[];
  /** When the abilities were last computed */
  computedAt: Date;
  /** Cache expiration time */
  expiresAt?: Date;
}

/**
 * Clinic association for multi-tenant authorization
 */
export interface ClinicAssociation {
  /** Clinic identifier */
  clinicId: string;
  /** User's role within the clinic */
  role: string;
  /** Association status */
  status: 'active' | 'pending' | 'suspended' | 'revoked';
  /** Additional permissions for this clinic */
  permissions?: Permission[];
  /** When the association was created */
  createdAt: Date;
  /** When the association expires (if applicable) */
  expiresAt?: Date;
}

/**
 * Authorization check request
 * Input for ability checking operations
 */
export interface AuthorizationRequest {
  /** User identifier */
  userId: string;
  /** Action to check */
  action: Action;
  /** Subject to check against */
  subject: Subject | Record<string, unknown>;
  /** Additional context for the check */
  context?: Record<string, unknown>;
  /** Security context */
  securityContext: SecurityContext;
  /** Optional field-level check */
  field?: string;
  /** Override cached abilities */
  bypassCache?: boolean;
}

/**
 * Authorization check result
 * Comprehensive result of an authorization check
 */
export interface AuthorizationCheckResult {
  /** Whether the action is allowed */
  allowed: boolean;
  /** User abilities used for the check */
  abilities?: UserAbilities | undefined;
  /** Matched permission rule */
  matchedRule?: (Permission & { sourceRole?: string }) | undefined;
  /** Reason for the decision */
  reason?: string | undefined;
  /** Error information if check failed */
  error?: SecurityError | undefined;
  /** Security context for the check */
  context: SecurityContext;
  /** Check duration for performance monitoring */
  duration?: number | undefined;
  /** Whether the result was served from cache */
  fromCache?: boolean | undefined;
}

/**
 * Bulk authorization request for multiple checks
 */
export interface BulkAuthorizationRequest {
  /** User identifier */
  userId: string;
  /** Multiple authorization checks */
  checks: Array<{
    action: Action;
    subject: Subject | Record<string, unknown>;
    field?: string;
    context?: Record<string, unknown>;
  }>;
  /** Security context */
  securityContext: SecurityContext;
  /** Override cached abilities */
  bypassCache?: boolean;
}

/**
 * Bulk authorization result
 */
export interface BulkAuthorizationResult {
  /** Individual check results */
  results: Array<{
    allowed: boolean;
    matchedRule?: Permission & { sourceRole?: string };
    reason?: string;
  }>;
  /** Overall success status */
  success: boolean;
  /** User abilities used for all checks */
  abilities?: UserAbilities;
  /** Error information if bulk check failed */
  error?: SecurityError;
  /** Security context for the checks */
  context: SecurityContext;
  /** Total check duration */
  duration?: number;
}

/**
 * Permission resolution context
 * Context information for resolving dynamic permissions
 */
export interface PermissionContext {
  /** Current user information */
  user: {
    id: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  /** Resource being accessed */
  resource?: Record<string, unknown>;
  /** Request context */
  request?: {
    method: string;
    path: string;
    query: Record<string, unknown>;
    headers: Record<string, unknown>;
  };
  /** Temporal context */
  temporal?: {
    now: Date;
    timezone: string;
  };
  /** Additional contextual data */
  metadata?: Record<string, unknown>;
}

/**
 * Dynamic permission resolver function
 * Allows for runtime permission computation
 */
export type PermissionResolver = (
  context: PermissionContext
) => Promise<Permission[]> | Permission[];

/**
 * Authorization cache entry
 */
export interface AuthorizationCacheEntry {
  /** Cached user abilities */
  abilities: UserAbilities;
  /** Cache key */
  key: string;
  /** When the entry was created */
  createdAt: Date;
  /** When the entry expires */
  expiresAt: Date;
  /** Entry access count */
  accessCount: number;
  /** Last access timestamp */
  lastAccessedAt: Date;
}

/**
 * Authorization middleware options
 * Configuration for authorization middleware
 */
export interface AuthorizationMiddlewareOptions {
  /** Required action for access */
  action: Action;
  /** Required subject for access */
  subject: Subject | ((req: unknown) => Subject | Record<string, unknown>);
  /** Optional field-level restriction */
  field?: string;
  /** Custom authorization logic */
  custom?: (req: unknown, abilities: UserAbilities) => Promise<boolean> | boolean;
  /** Skip authorization for certain conditions */
  skip?: (req: unknown) => boolean;
  /** Error handling strategy */
  errorStrategy?: 'throw' | 'next' | 'custom';
  /** Custom error handler */
  onError?: (error: SecurityError, req: unknown) => void;
  /** Use cached abilities */
  useCache?: boolean;
  /** Additional context provider */
  contextProvider?: (req: unknown) => Record<string, unknown>;
}

/**
 * Role management operations
 */
export interface RoleManagementOptions {
  /** Include inherited permissions in results */
  includeInherited?: boolean;
  /** Validate role hierarchy for cycles */
  validateHierarchy?: boolean;
  /** Merge strategy for conflicting permissions */
  mergeStrategy?: 'union' | 'intersection' | 'priority';
  /** Maximum inheritance depth */
  maxInheritanceDepth?: number;
}

/**
 * Permission query options for filtering and pagination
 */
export interface PermissionQueryOptions {
  /** Filter by actions */
  actions?: Action[];
  /** Filter by subjects */
  subjects?: Subject[];
  /** Filter by user ID */
  userId?: string;
  /** Filter by role ID */
  roleId?: string;
  /** Filter by scope */
  scope?: string;
  /** Include system roles */
  includeSystem?: boolean;
  /** Pagination offset */
  offset?: number;
  /** Pagination limit */
  limit?: number;
  /** Sort options */
  sort?: {
    field: 'name' | 'createdAt' | 'updatedAt' | 'priority';
    direction: 'asc' | 'desc';
  };
}

/**
 * Authorization audit event
 * For tracking authorization decisions
 */
export interface AuthorizationAuditEvent {
  /** Event unique identifier */
  id: string;
  /** User who performed the action */
  userId: string;
  /** Action that was checked */
  action: Action;
  /** Subject that was checked */
  subject: Subject;
  /** Whether the action was allowed */
  allowed: boolean;
  /** Matched rule information */
  matchedRule?: {
    permission: Permission;
    sourceRole?: string;
    source: 'role' | 'direct' | 'inherited';
  };
  /** Request context */
  requestContext: {
    ip: string;
    userAgent?: string;
    path?: string;
    method?: string;
  };
  /** Authorization context */
  authContext: Record<string, unknown>;
  /** Event timestamp */
  timestamp: Date;
  /** Check duration */
  duration?: number;
  /** Error information if check failed */
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

/**
 * Resource access policy
 * Defines access rules for specific resources
 */
export interface ResourceAccessPolicy {
  /** Resource identifier pattern */
  resource: string | RegExp;
  /** Subject type this policy applies to */
  subject: Subject;
  /** Access rules */
  rules: Array<{
    action: Action | Action[];
    condition?: string; // MongoDB-style query or custom condition
    effect: 'allow' | 'deny';
    priority: number;
  }>;
  /** Policy metadata */
  metadata?: {
    name: string;
    description?: string;
    version?: string;
    createdBy?: string;
    createdAt?: Date;
  };
}

/**
 * Conditional permission with advanced rule engine support
 */
export interface ConditionalPermission extends Permission {
  /** Condition expression (e.g., JSON Logic, MongoDB query) */
  condition: Record<string, unknown> | string;
  /** Condition engine type */
  conditionType: 'json-logic' | 'mongodb' | 'javascript' | 'custom';
  /** Dynamic context requirements */
  requiredContext?: string[];
  /** Time-based constraints */
  timeConstraints?: {
    startTime?: Date;
    endTime?: Date;
    timezone?: string;
    daysOfWeek?: number[];
    hoursOfDay?: number[];
  };
  /** Location-based constraints */
  locationConstraints?: {
    allowedRegions?: string[];
    deniedRegions?: string[];
    ipRanges?: string[];
  };
}

/**
 * Permission inheritance configuration
 */
export interface PermissionInheritanceConfig {
  /** Maximum inheritance depth */
  maxDepth: number;
  /** Inheritance resolution strategy */
  strategy: 'merge' | 'override' | 'prioritize';
  /** Cycle detection enabled */
  detectCycles: boolean;
  /** Conflict resolution for overlapping permissions */
  conflictResolution: 'most-permissive' | 'least-permissive' | 'explicit-wins' | 'priority-based';
  /** Cache inherited permissions */
  cacheInherited: boolean;
  /** Inheritance cache TTL in seconds */
  inheritanceCacheTtl?: number;
}

/**
 * Authorization statistics and metrics
 */
export interface AuthorizationMetrics {
  /** Total authorization checks performed */
  totalChecks: number;
  /** Successful authorization checks */
  successfulChecks: number;
  /** Failed authorization checks */
  failedChecks: number;
  /** Cache hit rate */
  cacheHitRate: number;
  /** Average check duration */
  averageCheckDuration: number;
  /** Most frequently checked actions */
  topActions: Array<{ action: Action; count: number }>;
  /** Most frequently checked subjects */
  topSubjects: Array<{ subject: Subject; count: number }>;
  /** Error distribution */
  errorDistribution: Record<string, number>;
  /** Metrics collection period */
  period: {
    start: Date;
    end: Date;
  };
}
