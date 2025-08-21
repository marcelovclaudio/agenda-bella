/**
 * Rate limiting utilities and constants
 * @packageDocumentation
 */

import type {
  AuthStatus,
  BusinessRateLimitConfig,
  EndpointRateLimitConfig,
  RateLimitAlgorithm,
  RateLimitBypass,
  RateLimiterConfig,
  RateLimitRule,
  RateLimitStrategy,
  UserType,
} from './types';

/**
 * Default rate limiting configurations for different scenarios
 */
export const DEFAULT_RATE_LIMITS = {
  /** Global default rate limit */
  GLOBAL: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    strategy: 'sliding_window' as RateLimitStrategy,
    algorithm: 'sliding_window_counter' as RateLimitAlgorithm,
    standardHeaders: true,
    legacyHeaders: false,
  },
  /** Authentication endpoints (stricter limits) */
  AUTH: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    strategy: 'fixed_window' as RateLimitStrategy,
    algorithm: 'counter' as RateLimitAlgorithm,
    standardHeaders: true,
    statusCode: 429,
    message: 'Muitas tentativas de autenticação. Tente novamente em 15 minutos.',
  },
  /** Public API endpoints */
  API: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    strategy: 'sliding_window' as RateLimitStrategy,
    algorithm: 'sliding_window_counter' as RateLimitAlgorithm,
    standardHeaders: true,
    skipSuccessfulRequests: false,
  },
  /** Admin endpoints (higher limits) */
  ADMIN: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5000,
    strategy: 'token_bucket' as RateLimitStrategy,
    algorithm: 'token_bucket' as RateLimitAlgorithm,
    burstSize: 100,
    refillRate: 10,
    standardHeaders: true,
  },
  /** File upload endpoints */
  UPLOAD: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 50,
    strategy: 'leaky_bucket' as RateLimitStrategy,
    algorithm: 'leaky_bucket' as RateLimitAlgorithm,
    standardHeaders: true,
    message: 'Limite de uploads excedido. Tente novamente em 1 hora.',
  },
  /** Search endpoints */
  SEARCH: {
    windowMs: 1 * 60 * 1000, // 1 minute
    maxRequests: 30,
    strategy: 'sliding_window' as RateLimitStrategy,
    algorithm: 'sliding_window_counter' as RateLimitAlgorithm,
    standardHeaders: true,
  },
} as const;

/**
 * Rate limiting strategies configuration
 */
export const RATE_LIMIT_STRATEGIES = {
  SLIDING_WINDOW: 'sliding_window',
  FIXED_WINDOW: 'fixed_window',
  TOKEN_BUCKET: 'token_bucket',
  LEAKY_BUCKET: 'leaky_bucket',
} as const;

/**
 * Rate limiting algorithms configuration
 */
export const RATE_LIMIT_ALGORITHMS = {
  COUNTER: 'counter',
  SLIDING_WINDOW_LOG: 'sliding_window_log',
  SLIDING_WINDOW_COUNTER: 'sliding_window_counter',
  TOKEN_BUCKET: 'token_bucket',
  LEAKY_BUCKET: 'leaky_bucket',
  CONCURRENCY: 'concurrency',
} as const;

/**
 * Business-specific rate limits for Brazilian market
 */
export const DEFAULT_BUSINESS_RATE_LIMITS: BusinessRateLimitConfig = {
  /** Consumer (patient) rate limits - moderate limits for patient interactions */
  consumer: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 200,
    strategy: 'sliding_window',
    algorithm: 'sliding_window_counter',
    standardHeaders: true,
    message: 'Limite de requisições excedido. Aguarde alguns minutos.',
  },
  /** Professional (doctor/therapist) rate limits - higher limits for work usage */
  professional: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    strategy: 'token_bucket',
    algorithm: 'token_bucket',
    burstSize: 50,
    refillRate: 20,
    standardHeaders: true,
    message: 'Limite de requisições profissionais excedido.',
  },
  /** Clinic admin rate limits - elevated limits for administrative tasks */
  clinic_admin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 2000,
    strategy: 'token_bucket',
    algorithm: 'token_bucket',
    burstSize: 100,
    refillRate: 30,
    standardHeaders: true,
  },
  /** System admin rate limits - highest limits for system operations */
  system_admin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10000,
    strategy: 'token_bucket',
    algorithm: 'token_bucket',
    burstSize: 500,
    refillRate: 100,
    standardHeaders: true,
  },
  /** Guest/unauthenticated user rate limits - strictest limits */
  guest: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 50,
    strategy: 'fixed_window',
    algorithm: 'counter',
    standardHeaders: true,
    message: 'Muitas requisições. Faça login para obter limites maiores.',
  },
};

/**
 * Endpoint-specific rate limiting configuration
 */
export const DEFAULT_ENDPOINT_RATE_LIMITS: EndpointRateLimitConfig = {
  /** Authentication endpoints - strict limits to prevent brute force */
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    strategy: 'fixed_window',
    algorithm: 'counter',
    standardHeaders: true,
    statusCode: 429,
    message: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
  },
  /** Public API endpoints - moderate limits */
  publicApi: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    strategy: 'sliding_window',
    algorithm: 'sliding_window_counter',
    standardHeaders: true,
  },
  /** Private API endpoints - higher limits for authenticated users */
  privateApi: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    strategy: 'sliding_window',
    algorithm: 'sliding_window_counter',
    standardHeaders: true,
  },
  /** Administrative endpoints - elevated limits */
  admin: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5000,
    strategy: 'token_bucket',
    algorithm: 'token_bucket',
    burstSize: 200,
    refillRate: 50,
    standardHeaders: true,
  },
  /** File upload endpoints - limited by resource constraints */
  upload: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 20,
    strategy: 'leaky_bucket',
    algorithm: 'leaky_bucket',
    standardHeaders: true,
    message: 'Limite de uploads excedido. Aguarde uma hora.',
  },
  /** Search endpoints - frequent but lightweight operations */
  search: {
    windowMs: 1 * 60 * 1000, // 1 minute
    maxRequests: 30,
    strategy: 'sliding_window',
    algorithm: 'sliding_window_counter',
    standardHeaders: true,
    message: 'Muitas pesquisas. Aguarde um momento.',
  },
  /** Clinic-specific endpoints - business workflow limits */
  clinic: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 2000,
    strategy: 'token_bucket',
    algorithm: 'token_bucket',
    burstSize: 100,
    refillRate: 25,
    standardHeaders: true,
  },
  /** Consumer-facing endpoints - patient interaction limits */
  consumer: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 500,
    strategy: 'sliding_window',
    algorithm: 'sliding_window_counter',
    standardHeaders: true,
  },
};

/**
 * Standard HTTP status codes for rate limiting
 */
export const RATE_LIMIT_STATUS_CODES = {
  /** Too Many Requests */
  TOO_MANY_REQUESTS: 429,
  /** Service Unavailable (when rate limiter is down) */
  SERVICE_UNAVAILABLE: 503,
  /** Forbidden (for blocked IPs) */
  FORBIDDEN: 403,
} as const;

/**
 * Standard rate limit headers
 */
export const RATE_LIMIT_HEADERS = {
  /** Standard headers (RFC 6585) */
  LIMIT: 'X-RateLimit-Limit',
  REMAINING: 'X-RateLimit-Remaining',
  RESET: 'X-RateLimit-Reset',
  RETRY_AFTER: 'Retry-After',
  /** Draft standard headers */
  RATELIMIT_LIMIT: 'RateLimit-Limit',
  RATELIMIT_REMAINING: 'RateLimit-Remaining',
  RATELIMIT_RESET: 'RateLimit-Reset',
} as const;

/**
 * Default rate limit bypass configuration
 */
export const DEFAULT_RATE_LIMIT_BYPASS: RateLimitBypass = {
  /** Development and testing IPs */
  ipWhitelist: ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  /** Privileged user types that get elevated limits */
  privilegedUserTypes: ['system_admin', 'clinic_admin'],
  /** Emergency bypass disabled by default */
  // emergencyBypass intentionally omitted (undefined)
};

/**
 * Rate limiting error messages in Portuguese
 */
export const RATE_LIMIT_MESSAGES = {
  DEFAULT: 'Muitas requisições. Tente novamente mais tarde.',
  AUTH_LIMIT: 'Muitas tentativas de autenticação. Aguarde 15 minutos.',
  UPLOAD_LIMIT: 'Limite de uploads excedido. Tente novamente em uma hora.',
  SEARCH_LIMIT: 'Muitas pesquisas realizadas. Aguarde um momento.',
  API_LIMIT: 'Limite de chamadas da API excedido.',
  GUEST_LIMIT: 'Limite para usuários não autenticados excedido. Faça login para obter mais acesso.',
  ADMIN_LIMIT: 'Limite administrativo excedido.',
  CLINIC_LIMIT: 'Limite para operações da clínica excedido.',
  CONSUMER_LIMIT: 'Limite para operações do paciente excedido.',
  GLOBAL_LIMIT: 'Limite global de requisições excedido.',
} as const;

/**
 * Time constants for rate limiting
 */
export const TIME_CONSTANTS = {
  ONE_SECOND: 1000,
  ONE_MINUTE: 60 * 1000,
  FIVE_MINUTES: 5 * 60 * 1000,
  FIFTEEN_MINUTES: 15 * 60 * 1000,
  THIRTY_MINUTES: 30 * 60 * 1000,
  ONE_HOUR: 60 * 60 * 1000,
  ONE_DAY: 24 * 60 * 60 * 1000,
  ONE_WEEK: 7 * 24 * 60 * 60 * 1000,
} as const;

/**
 * Get rate limit configuration by user type
 * @param userType - The user type to get configuration for
 * @returns Rate limit configuration for the user type
 */
export function getRateLimitConfigByUserType(userType: UserType): RateLimiterConfig {
  return DEFAULT_BUSINESS_RATE_LIMITS[userType] || DEFAULT_BUSINESS_RATE_LIMITS.guest;
}

/**
 * Get rate limit configuration by endpoint type
 * @param endpointType - The endpoint type to get configuration for
 * @returns Rate limit configuration for the endpoint type
 */
export function getRateLimitConfigByEndpoint(
  endpointType: keyof EndpointRateLimitConfig
): RateLimiterConfig {
  return DEFAULT_ENDPOINT_RATE_LIMITS[endpointType] || DEFAULT_ENDPOINT_RATE_LIMITS.publicApi;
}

/**
 * Generate a rate limit key for client identification
 * @param clientId - Base client identifier
 * @param ruleName - Rule name being applied
 * @param prefix - Optional prefix for the key
 * @returns Generated rate limit key
 */
export function generateRateLimitKey(
  clientId: string,
  ruleName: string,
  prefix: string = 'rl'
): string {
  return `${prefix}:${ruleName}:${clientId}`;
}

/**
 * Extract client IP address from request
 * @param req - Request object
 * @param trustProxy - Whether to trust proxy headers
 * @returns Client IP address
 */
export function extractClientIP(
  req: {
    ip?: string;
    headers?: Record<string, string | string[]>;
    connection?: { remoteAddress?: string };
    socket?: { remoteAddress?: string };
    [key: string]: unknown;
  },
  trustProxy: boolean = false
): string {
  if (trustProxy) {
    const forwardedFor = req.headers?.['x-forwarded-for'];
    const realIp = req.headers?.['x-real-ip'];

    return (
      req.ip ||
      (typeof forwardedFor === 'string' ? forwardedFor.split(',')[0]?.trim() : undefined) ||
      (typeof realIp === 'string' ? realIp : undefined) ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      '127.0.0.1'
    );
  }

  return req.connection?.remoteAddress || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Generate default key for rate limiting
 * @param req - Request object
 * @param trustProxy - Whether to trust proxy headers
 * @returns Generated key for rate limiting
 */
export function defaultKeyGenerator(
  req: {
    user?: { id?: string; userId?: string };
    session?: { id?: string };
    sessionId?: string;
    [key: string]: unknown;
  },
  trustProxy: boolean = false
): string {
  const ip = extractClientIP(req, trustProxy);
  const userId = req.user?.id || req['userId'];
  const sessionId = req.session?.id || req['sessionId'];

  // Prefer user ID for authenticated users, fall back to session, then IP
  if (userId && typeof userId === 'string') {
    return `user:${userId}`;
  }

  if (sessionId && typeof sessionId === 'string') {
    return `session:${sessionId}`;
  }

  return `ip:${ip}`;
}

/**
 * Check if a user type is privileged
 * @param userType - User type to check
 * @returns Whether the user type is privileged
 */
export function isPrivilegedUserType(userType: UserType): boolean {
  return ['system_admin', 'clinic_admin'].includes(userType);
}

/**
 * Check if an auth status is privileged
 * @param authStatus - Auth status to check
 * @returns Whether the auth status is privileged
 */
export function isPrivilegedAuthStatus(authStatus: AuthStatus): boolean {
  return ['privileged', 'service_account'].includes(authStatus);
}

/**
 * Calculate retry after time based on rate limit window
 * @param windowMs - Rate limit window in milliseconds
 * @param resetTime - When the rate limit resets
 * @returns Retry after time in seconds
 */
export function calculateRetryAfter(resetTime: Date): number {
  const now = Date.now();
  const resetTimeMs = resetTime.getTime();
  const retryAfterMs = Math.max(0, resetTimeMs - now);
  return Math.ceil(retryAfterMs / 1000);
}

/**
 * Create default rate limit rules for common scenarios
 * @returns Array of default rate limit rules
 */
export function createDefaultRateLimitRules(): RateLimitRule[] {
  return [
    {
      name: 'auth_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.auth,
      paths: ['/auth/*', '/login', '/register', '/password-reset'],
      methods: ['POST'],
      priority: 100,
      enabled: true,
      description: 'Strict rate limiting for authentication endpoints',
    },
    {
      name: 'upload_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.upload,
      paths: ['/upload/*', '/files/*'],
      methods: ['POST', 'PUT'],
      priority: 90,
      enabled: true,
      description: 'Rate limiting for file upload endpoints',
    },
    {
      name: 'search_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.search,
      paths: ['/search/*', '/api/search/*'],
      methods: ['GET', 'POST'],
      priority: 80,
      enabled: true,
      description: 'Rate limiting for search endpoints',
    },
    {
      name: 'admin_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.admin,
      paths: ['/admin/*', '/api/admin/*'],
      userTypes: ['system_admin', 'clinic_admin'],
      priority: 70,
      enabled: true,
      description: 'Elevated rate limits for administrative endpoints',
    },
    {
      name: 'clinic_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.clinic,
      paths: ['/clinic/*', '/api/clinic/*'],
      userTypes: ['professional', 'clinic_admin'],
      priority: 60,
      enabled: true,
      description: 'Business-specific rate limits for clinic operations',
    },
    {
      name: 'consumer_endpoints',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.consumer,
      paths: ['/consumer/*', '/api/consumer/*', '/patient/*'],
      userTypes: ['consumer'],
      priority: 50,
      enabled: true,
      description: 'Rate limits for consumer/patient endpoints',
    },
    {
      name: 'api_authenticated',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.privateApi,
      paths: ['/api/*'],
      authStatus: ['authenticated', 'privileged'],
      priority: 40,
      enabled: true,
      description: 'Rate limits for authenticated API access',
    },
    {
      name: 'api_public',
      config: DEFAULT_ENDPOINT_RATE_LIMITS.publicApi,
      paths: ['/api/public/*'],
      authStatus: ['unauthenticated'],
      priority: 30,
      enabled: true,
      description: 'Rate limits for public API access',
    },
    {
      name: 'global_fallback',
      config: DEFAULT_RATE_LIMITS.GLOBAL,
      paths: ['*'],
      priority: 1,
      enabled: true,
      description: 'Global fallback rate limiting for all requests',
    },
  ];
}
