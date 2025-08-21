/**
 * Configuration types for security components
 * @packageDocumentation
 */

/**
 * JWT authentication configuration
 */
export interface JwtConfig {
  /** Secret key for signing JWT tokens */
  secret: string;
  /** Token expiration time (e.g., '15m', '1h', '7d') */
  expiresIn: string;
  /** Refresh token expiration time (e.g., '7d', '30d') */
  refreshExpiresIn: string;
  /** JWT signing algorithm */
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  /** Token issuer */
  issuer?: string;
  /** Token audience */
  audience?: string;
  /** Clock tolerance in seconds */
  clockTolerance?: number;
}

/**
 * Password security configuration
 */
export interface PasswordConfig {
  /** Minimum password length */
  minLength: number;
  /** Maximum password length */
  maxLength?: number;
  /** Require at least one number */
  requireNumbers: boolean;
  /** Require at least one symbol/special character */
  requireSymbols: boolean;
  /** Require at least one uppercase letter */
  requireUppercase: boolean;
  /** Require at least one lowercase letter */
  requireLowercase: boolean;
  /** Number of bcrypt salt rounds */
  bcryptRounds: number;
  /** Prevent common passwords */
  preventCommon?: boolean;
  /** Password history length (prevent reuse) */
  historyLength?: number;
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  /** Time window in milliseconds */
  windowMs: number;
  /** Maximum requests per window */
  max: number;
  /** Message to send when limit is exceeded */
  message?: string;
  /** HTTP status code to send when limit is exceeded */
  statusCode?: number;
  /** Skip successful requests in rate limiting */
  skipSuccessfulRequests?: boolean;
  /** Skip failed requests in rate limiting */
  skipFailedRequests?: boolean;
  /** Custom key generator function */
  keyGenerator?: (req: unknown) => string;
  /** Store for rate limit data */
  store?: string;
  /** Redis configuration if using Redis store */
  redis?: RedisConfig;
}

/**
 * Helmet security headers configuration
 */
export interface HelmetConfig {
  /** Content Security Policy configuration */
  contentSecurityPolicy?: {
    useDefaults?: boolean;
    directives?: Record<string, string[] | string | boolean>;
  };
  /** Cross-Origin-Embedder-Policy */
  crossOriginEmbedderPolicy?: boolean;
  /** Cross-Origin-Opener-Policy */
  crossOriginOpenerPolicy?: boolean;
  /** Cross-Origin-Resource-Policy */
  crossOriginResourcePolicy?: { policy: string };
  /** DNS Prefetch Control */
  dnsPrefetchControl?: boolean;
  /** Expect-CT */
  expectCt?: boolean;
  /** Frameguard (X-Frame-Options) */
  frameguard?: { action: string };
  /** Hide Powered-By */
  hidePoweredBy?: boolean;
  /** HTTP Strict Transport Security */
  hsts?: {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  /** IE No Open */
  ieNoOpen?: boolean;
  /** No Sniff */
  noSniff?: boolean;
  /** Origin Agent Cluster */
  originAgentCluster?: boolean;
  /** Permitted Cross-Domain Policies */
  permittedCrossDomainPolicies?: boolean;
  /** Referrer Policy */
  referrerPolicy?: { policy: string | string[] };
  /** X-XSS-Protection */
  xssFilter?: boolean;
}

/**
 * CORS configuration
 */
export interface CorsConfig {
  /** Allowed origins */
  origin: string | string[] | boolean | ((origin: string) => boolean);
  /** Allowed methods */
  methods?: string | string[];
  /** Allowed headers */
  allowedHeaders?: string | string[];
  /** Exposed headers */
  exposedHeaders?: string | string[];
  /** Credentials support */
  credentials?: boolean;
  /** Preflight max age */
  maxAge?: number;
  /** Options success status */
  optionsSuccessStatus?: number;
}

/**
 * Session configuration
 */
export interface SessionConfig {
  /** Session secret key */
  secret: string;
  /** Session name */
  name?: string;
  /** Cookie configuration */
  cookie?: {
    /** Cookie max age in milliseconds */
    maxAge?: number;
    /** Secure flag */
    secure?: boolean;
    /** HTTP only flag */
    httpOnly?: boolean;
    /** Same site policy */
    sameSite?: 'strict' | 'lax' | 'none' | boolean;
    /** Cookie domain */
    domain?: string;
    /** Cookie path */
    path?: string;
  };
  /** Whether to save uninitialized sessions */
  saveUninitialized?: boolean;
  /** Whether to save sessions on every request */
  resave?: boolean;
  /** Rolling sessions */
  rolling?: boolean;
  /** Session store configuration */
  store?: string;
  /** Redis configuration if using Redis store */
  redis?: RedisConfig;
}

/**
 * Redis configuration for stores
 */
export interface RedisConfig {
  /** Redis host */
  host: string;
  /** Redis port */
  port: number;
  /** Redis password */
  password?: string;
  /** Redis database number */
  db?: number;
  /** Connection timeout */
  connectTimeout?: number;
  /** Command timeout */
  commandTimeout?: number;
  /** Retry delay on failure */
  retryDelayOnFailover?: number;
  /** Maximum retry attempts */
  maxRetriesPerRequest?: number;
  /** Key prefix for Redis keys */
  keyPrefix?: string;
}

/**
 * Audit configuration
 */
export interface AuditConfig {
  /** Whether auditing is enabled */
  enabled: boolean;
  /** Events to audit */
  events: string[];
  /** Storage backend for audit logs */
  storage: 'file' | 'database' | 'redis';
  /** File path if using file storage */
  filePath?: string;
  /** Database configuration if using database storage */
  database?: {
    table: string;
    connection: string;
  };
  /** Redis configuration if using Redis storage */
  redis?: RedisConfig;
  /** Retention period for audit logs in days */
  retentionDays?: number;
  /** Whether to include request/response data */
  includeData?: boolean;
}

/**
 * Complete security configuration with environment-specific overrides
 */
export interface SecurityEnvironmentConfig {
  /** Environment name */
  environment: 'development' | 'staging' | 'production';
  /** Debug mode flag */
  debug?: boolean;
  /** Audit configuration */
  audit?: AuditConfig;
  /** JWT authentication configuration */
  jwt?: JwtConfig;
  /** Rate limiting configuration */
  rateLimit?: RateLimitConfig;
  /** Password security configuration */
  password?: PasswordConfig;
  /** Helmet security headers configuration */
  helmet?: HelmetConfig;
  /** CORS configuration */
  cors?: CorsConfig;
  /** Session configuration */
  session?: SessionConfig;
}
