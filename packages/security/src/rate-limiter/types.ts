/**
 * Rate limiting types and interfaces
 * @packageDocumentation
 */

import type { SecurityContext } from '../types/common.types';
import type { RedisConfig } from '../types/config.types';

/**
 * Rate limiting strategies supported by the system
 */
export type RateLimitStrategy = 'sliding_window' | 'fixed_window' | 'token_bucket' | 'leaky_bucket';

/**
 * Rate limiting algorithms for different use cases
 */
export type RateLimitAlgorithm =
  | 'counter'
  | 'sliding_window_log'
  | 'sliding_window_counter'
  | 'token_bucket'
  | 'leaky_bucket'
  | 'concurrency';

/**
 * User types for Brazilian business context
 */
export type UserType = 'consumer' | 'professional' | 'clinic_admin' | 'system_admin' | 'guest';

/**
 * Authentication status for rate limiting decisions
 */
export type AuthStatus = 'authenticated' | 'unauthenticated' | 'privileged' | 'service_account';

/**
 * Rate limit store backends
 */
export type RateLimitStore = 'memory' | 'redis' | 'database' | 'hybrid';

/**
 * Core rate limiting configuration
 */
export interface RateLimiterConfig {
  /** Time window in milliseconds */
  windowMs: number;
  /** Maximum requests allowed in the window */
  maxRequests: number;
  /** Strategy to use for rate limiting */
  strategy?: RateLimitStrategy;
  /** Algorithm implementation */
  algorithm?: RateLimitAlgorithm;
  /** Message returned when limit is exceeded */
  message?: string;
  /** HTTP status code when limit is exceeded */
  statusCode?: number;
  /** Whether to include standard rate limit headers */
  standardHeaders?: boolean;
  /** Whether to include legacy X-RateLimit headers */
  legacyHeaders?: boolean;
  /** Custom headers to include in response */
  customHeaders?: Record<string, string>;
  /** Skip rate limiting if condition is met */
  skipIf?: (req: unknown) => boolean;
  /** Custom key generator for identifying clients */
  keyGenerator?: (req: unknown) => string;
  /** Skip successful requests (2xx status codes) */
  skipSuccessfulRequests?: boolean;
  /** Skip failed requests (4xx/5xx status codes) */
  skipFailedRequests?: boolean;
  /** Store backend configuration */
  store?: RateLimitStore;
  /** Redis configuration if using Redis store */
  redis?: RedisConfig;
  /** Burst allowance for token bucket strategy */
  burstSize?: number;
  /** Refill rate for token bucket (tokens per second) */
  refillRate?: number;
  /** Enable distributed rate limiting */
  distributed?: boolean;
  /** Prefix for rate limit keys */
  keyPrefix?: string;
}

/**
 * Rate limiting rule definition
 */
export interface RateLimitRule {
  /** Unique name for the rule */
  name: string;
  /** Rule configuration */
  config: RateLimiterConfig;
  /** Paths this rule applies to (glob patterns supported) */
  paths: string[];
  /** HTTP methods this rule applies to */
  methods?: string[];
  /** User types this rule applies to */
  userTypes?: UserType[];
  /** Authentication status this rule applies to */
  authStatus?: AuthStatus[];
  /** Priority for rule evaluation (higher = evaluated first) */
  priority?: number;
  /** Whether this rule is enabled */
  enabled?: boolean;
  /** Rule description for documentation */
  description?: string;
}

/**
 * Rate limit information returned to clients
 */
export interface RateLimitInfo {
  /** Maximum requests allowed in window */
  limit: number;
  /** Current request count in window */
  current: number;
  /** Remaining requests in current window */
  remaining: number;
  /** When the rate limit window resets */
  resetTime: Date;
  /** Time until reset in milliseconds */
  resetTimeMs: number;
  /** Strategy used for this rate limit */
  strategy?: RateLimitStrategy;
  /** Rule name that was applied */
  ruleName?: string;
}

/**
 * Extended rate limit result with detailed information
 */
export interface RateLimiterResult extends RateLimitInfo {
  /** Whether the request was allowed */
  allowed: boolean;
  /** Reason for blocking if not allowed */
  reason?: string;
  /** Client identifier used for rate limiting */
  clientId: string;
  /** Security context */
  context: SecurityContext;
  /** Headers to include in response */
  headers: Record<string, string>;
  /** Retry after time in seconds if blocked */
  retryAfter?: number;
}

/**
 * Rate limit bypass configuration
 */
export interface RateLimitBypass {
  /** IP addresses to bypass (CIDR notation supported) */
  ipWhitelist?: string[];
  /** User IDs to bypass */
  userWhitelist?: string[];
  /** API keys to bypass */
  apiKeyWhitelist?: string[];
  /** User types that get elevated limits */
  privilegedUserTypes?: UserType[];
  /** Custom bypass condition */
  customBypass?: (req: unknown, context: SecurityContext) => boolean;
  /** Emergency bypass key */
  emergencyBypass?: string | undefined;
}

/**
 * Rate limiting analytics configuration
 */
export interface RateLimitAnalytics {
  /** Whether to collect analytics */
  enabled: boolean;
  /** Sample rate (0.0 to 1.0) for analytics collection */
  sampleRate?: number;
  /** Metrics to collect */
  metrics?: RateLimitMetricType[];
  /** Storage backend for analytics */
  storage?: 'memory' | 'redis' | 'database';
  /** Retention period for analytics data in days */
  retentionDays?: number;
}

/**
 * Types of rate limiting metrics to collect
 */
export type RateLimitMetricType =
  | 'request_count'
  | 'blocked_requests'
  | 'average_window_usage'
  | 'peak_usage'
  | 'top_clients'
  | 'rule_effectiveness';

/**
 * Rate limiting metric data
 */
export interface RateLimitMetric {
  /** Metric type */
  type: RateLimitMetricType;
  /** Timestamp when metric was recorded */
  timestamp: Date;
  /** Rule name that generated the metric */
  ruleName: string;
  /** Metric value */
  value: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Business-specific rate limiting configuration for Brazilian market
 */
export interface BusinessRateLimitConfig {
  /** Consumer (patient) rate limits */
  consumer: RateLimiterConfig;
  /** Professional (doctor/therapist) rate limits */
  professional: RateLimiterConfig;
  /** Clinic admin rate limits */
  clinic_admin: RateLimiterConfig;
  /** System admin rate limits */
  system_admin: RateLimiterConfig;
  /** Guest/unauthenticated user rate limits */
  guest: RateLimiterConfig;
}

/**
 * Endpoint-specific rate limiting configuration
 */
export interface EndpointRateLimitConfig {
  /** Authentication endpoints (login, register, password reset) */
  auth: RateLimiterConfig;
  /** Public API endpoints */
  publicApi: RateLimiterConfig;
  /** Private API endpoints */
  privateApi: RateLimiterConfig;
  /** Administrative endpoints */
  admin: RateLimiterConfig;
  /** File upload endpoints */
  upload: RateLimiterConfig;
  /** Search endpoints */
  search: RateLimiterConfig;
  /** Clinic-specific endpoints */
  clinic: RateLimiterConfig;
  /** Consumer-facing endpoints */
  consumer: RateLimiterConfig;
}

/**
 * Rate limiting middleware options
 */
export interface RateLimitMiddlewareOptions {
  /** Rules to apply */
  rules: RateLimitRule[];
  /** Default configuration for unmatched requests */
  defaultConfig?: RateLimiterConfig;
  /** Bypass configuration */
  bypass?: RateLimitBypass;
  /** Analytics configuration */
  analytics?: RateLimitAnalytics;
  /** Whether to trust proxy headers for IP detection */
  trustProxy?: boolean;
  /** Custom error handler */
  onExceeded?: (req: unknown, res: unknown, info: RateLimiterResult) => void;
  /** Custom success handler */
  onSuccess?: (req: unknown, res: unknown, info: RateLimiterResult) => void;
  /** Whether to add rate limit info to request object */
  addToRequest?: boolean;
  /** Request property name to add rate limit info */
  requestProperty?: string;
}

/**
 * Rate limiting quota system for premium features
 */
export interface RateLimitQuota {
  /** User/client identifier */
  clientId: string;
  /** Quota type (e.g., 'api_calls', 'file_uploads') */
  quotaType: string;
  /** Total quota allowed */
  totalQuota: number;
  /** Used quota */
  usedQuota: number;
  /** Remaining quota */
  remainingQuota: number;
  /** Quota reset period in milliseconds */
  resetPeriod: number;
  /** When quota last reset */
  lastReset: Date;
  /** When quota next resets */
  nextReset: Date;
  /** Whether quota is enabled */
  enabled: boolean;
}

/**
 * Distributed rate limiting coordination
 */
export interface DistributedRateLimitConfig {
  /** Node identifier for this instance */
  nodeId: string;
  /** Coordination strategy */
  strategy: 'leader_follower' | 'gossip' | 'central_coordinator';
  /** Synchronization interval in milliseconds */
  syncInterval: number;
  /** Tolerance for distributed counter drift */
  driftTolerance: number;
  /** Redis configuration for coordination */
  redis?: RedisConfig;
  /** Fallback behavior when coordination fails */
  fallbackBehavior: 'allow' | 'deny' | 'local_only';
}

/**
 * Rate limiting health check information
 */
export interface RateLimitHealthCheck {
  /** Overall health status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Store connection status */
  storeStatus: 'connected' | 'disconnected' | 'error';
  /** Last health check timestamp */
  lastCheck: Date;
  /** Number of active rules */
  activeRules: number;
  /** Average response time for rate limit checks */
  averageResponseTime: number;
  /** Error rate percentage */
  errorRate: number;
  /** Memory usage if using memory store */
  memoryUsage?: number;
}
