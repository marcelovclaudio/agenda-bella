/**
 * Middleware types for the security package
 *
 * This module defines basic types for Express middleware and security configurations
 * as specified in SUB-SEC-001-09.
 *
 * @packageDocumentation
 */

/**
 * Express-compatible types for middleware without requiring Express as a dependency
 * These types match Express interfaces but allow for peer dependency usage
 */
export interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  socket?: {
    remoteAddress?: string;
  };
  sessionID?: string;
  [key: string]: unknown;
}

export interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(obj: unknown): ExpressResponse;
  [key: string]: unknown;
}

export type ExpressNextFunction = (error?: Error) => void;

/**
 * Security middleware configuration interface
 */
export interface SecurityMiddlewareConfig {
  helmet?: HelmetConfig;
  cors?: CorsConfig;
  rateLimiting?: boolean;
  authentication?: boolean;
  authorization?: boolean;
}

/**
 * Helmet security headers configuration
 */
export interface HelmetConfig {
  contentSecurityPolicy?: boolean;
  crossOriginEmbedderPolicy?: boolean;
  crossOriginOpenerPolicy?: boolean;
  crossOriginResourcePolicy?: boolean;
  dnsPrefetchControl?: boolean;
  frameguard?: boolean;
  hidePoweredBy?: boolean;
  hsts?: boolean;
  ieNoOpen?: boolean;
  noSniff?: boolean;
  originAgentCluster?: boolean;
  permittedCrossDomainPolicies?: boolean;
  referrerPolicy?: boolean;
  xssFilter?: boolean;
}

/**
 * CORS configuration interface
 */
export interface CorsConfig {
  origin?: string | string[] | boolean;
  methods?: string[];
  allowedHeaders?: string[];
  credentials?: boolean;
  maxAge?: number;
}

/**
 * Express middleware function type
 */
export type ExpressMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction
) => void | Promise<void>;

/**
 * Security middleware function type as specified in SUB-SEC-001-09
 */
export type SecurityMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction
) => void | Promise<void>;

/**
 * Express error handling middleware function type
 */
export type ExpressErrorMiddleware = (
  error: Error,
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction
) => void | Promise<void>;
