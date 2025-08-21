/**
 * Rate limiting module
 *
 * Provides comprehensive rate limiting capabilities for the Agenda Bella platform,
 * including support for different user types, endpoints, and Brazilian business context.
 *
 * @packageDocumentation
 */

// Export all types
export type {
  RateLimiterConfig,
  RateLimitRule,
  RateLimitInfo,
  RateLimiterResult,
  RateLimitStrategy,
  RateLimitAlgorithm,
  RateLimitStore,
  UserType,
  AuthStatus,
  RateLimitBypass,
  RateLimitAnalytics,
  RateLimitMetricType,
  RateLimitMetric,
  BusinessRateLimitConfig,
  EndpointRateLimitConfig,
  RateLimitMiddlewareOptions,
  RateLimitQuota,
  DistributedRateLimitConfig,
  RateLimitHealthCheck,
} from './types';

// Export all utilities and constants
export {
  DEFAULT_RATE_LIMITS,
  RATE_LIMIT_STRATEGIES,
  RATE_LIMIT_ALGORITHMS,
  DEFAULT_BUSINESS_RATE_LIMITS,
  DEFAULT_ENDPOINT_RATE_LIMITS,
  RATE_LIMIT_STATUS_CODES,
  RATE_LIMIT_HEADERS,
  DEFAULT_RATE_LIMIT_BYPASS,
  RATE_LIMIT_MESSAGES,
  TIME_CONSTANTS,
  getRateLimitConfigByUserType,
  getRateLimitConfigByEndpoint,
  generateRateLimitKey,
  extractClientIP,
  defaultKeyGenerator,
  isPrivilegedUserType,
  isPrivilegedAuthStatus,
  calculateRetryAfter,
  createDefaultRateLimitRules,
} from './utils';
