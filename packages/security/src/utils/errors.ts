/**
 * Error factory utilities and error handling helpers
 *
 * This module provides factory functions and utilities for creating and handling
 * security errors in a consistent way throughout the application.
 *
 * @packageDocumentation
 */

import type { SecurityContext } from '../types/common.types';
import {
  AccountLockedError,
  AccountSuspendedError,
  AuthenticationError,
  CryptographicError,
  EmailVerificationRequiredError,
  InsufficientPermissionsError,
  InvalidCredentialsError,
  InvalidMfaCodeError,
  InvalidRefreshTokenError,
  InvalidSessionError,
  InvalidTokenError,
  MfaRequiredError,
  OperationForbiddenError,
  PasswordExpiredError,
  PasswordReuseError,
  ResourceNotFoundError,
  SecurityConfigError,
  SecurityError,
  SessionExpiredError,
  TokenExpiredError,
  TooManyLoginAttemptsError,
  TooManyRequestsError,
  WeakPasswordError,
  type SecurityErrorType,
} from '../types/errors.types';

/**
 * Error factory configuration options
 */
interface ErrorFactoryOptions {
  /** Security context when the error occurred */
  context?: SecurityContext;
  /** Additional error-specific details */
  details?: Record<string, unknown>;
  /** Original error that caused this security error */
  cause?: Error;
  /** Custom error message (uses default if not provided) */
  message?: string;
}

/**
 * Rate limit error factory options
 */
interface RateLimitErrorOptions extends ErrorFactoryOptions {
  /** Rate limit details */
  rateLimitDetails?: {
    limit: number;
    remaining: number;
    resetTime: Date;
    resetTimeMs: number;
  };
}

/**
 * Default error messages for different error types
 */
const DEFAULT_ERROR_MESSAGES = {
  // Authentication errors
  INVALID_CREDENTIALS: 'Credenciais inválidas fornecidas',
  INVALID_TOKEN: 'Token de autenticação inválido ou malformado',
  TOKEN_EXPIRED: 'Token de autenticação expirado',
  INVALID_REFRESH_TOKEN: 'Token de renovação inválido ou expirado',

  // Authorization errors
  INSUFFICIENT_PERMISSIONS: 'Permissões insuficientes para realizar esta operação',
  RESOURCE_NOT_FOUND: 'Recurso não encontrado ou acesso negado',
  OPERATION_FORBIDDEN: 'Operação não permitida para este usuário',

  // Rate limiting errors
  TOO_MANY_REQUESTS: 'Muitas solicitações. Tente novamente mais tarde',
  TOO_MANY_LOGIN_ATTEMPTS: 'Muitas tentativas de login. Conta temporariamente bloqueada',

  // Password errors
  WEAK_PASSWORD: 'Senha não atende aos requisitos de segurança',
  PASSWORD_REUSE: 'Esta senha foi usada recentemente e não pode ser reutilizada',
  PASSWORD_EXPIRED: 'Senha expirada. É necessário alterar a senha',

  // Account errors
  ACCOUNT_LOCKED: 'Conta bloqueada devido a atividade suspeita',
  ACCOUNT_SUSPENDED: 'Conta suspensa pelo administrador',
  EMAIL_VERIFICATION_REQUIRED: 'Verificação de email necessária',

  // MFA errors
  MFA_REQUIRED: 'Autenticação de múltiplos fatores necessária',
  INVALID_MFA_CODE: 'Código de autenticação multifator inválido',

  // Session errors
  SESSION_EXPIRED: 'Sessão expirada. Faça login novamente',
  INVALID_SESSION: 'Sessão inválida ou corrompida',

  // System errors
  SECURITY_CONFIG_ERROR: 'Erro de configuração de segurança',
  CRYPTOGRAPHIC_ERROR: 'Erro em operação criptográfica',
} as const;

/**
 * Authentication error factory functions
 */
export const AuthErrors = {
  /**
   * Create an invalid credentials error
   */
  invalidCredentials(options: ErrorFactoryOptions = {}): InvalidCredentialsError {
    return new InvalidCredentialsError(
      options.message || DEFAULT_ERROR_MESSAGES.INVALID_CREDENTIALS,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create an invalid token error
   */
  invalidToken(options: ErrorFactoryOptions = {}): InvalidTokenError {
    return new InvalidTokenError(
      options.message || DEFAULT_ERROR_MESSAGES.INVALID_TOKEN,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create a token expired error
   */
  tokenExpired(options: ErrorFactoryOptions = {}): TokenExpiredError {
    return new TokenExpiredError(
      options.message || DEFAULT_ERROR_MESSAGES.TOKEN_EXPIRED,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create an invalid refresh token error
   */
  invalidRefreshToken(options: ErrorFactoryOptions = {}): InvalidRefreshTokenError {
    return new InvalidRefreshTokenError(
      options.message || DEFAULT_ERROR_MESSAGES.INVALID_REFRESH_TOKEN,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create an MFA required error
   */
  mfaRequired(options: ErrorFactoryOptions = {}): MfaRequiredError {
    return new MfaRequiredError(
      options.message || DEFAULT_ERROR_MESSAGES.MFA_REQUIRED,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create an invalid MFA code error
   */
  invalidMfaCode(options: ErrorFactoryOptions = {}): InvalidMfaCodeError {
    return new InvalidMfaCodeError(
      options.message || DEFAULT_ERROR_MESSAGES.INVALID_MFA_CODE,
      options.context,
      options.details,
      options.cause
    );
  },
};

/**
 * Authorization error factory functions
 */
export const AuthzErrors = {
  /**
   * Create an insufficient permissions error
   */
  insufficientPermissions(
    requiredPermissions?: string[],
    options: ErrorFactoryOptions = {}
  ): InsufficientPermissionsError {
    return new InsufficientPermissionsError(
      options.message || DEFAULT_ERROR_MESSAGES.INSUFFICIENT_PERMISSIONS,
      options.context,
      {
        ...options.details,
        requiredPermissions,
      },
      options.cause
    );
  },

  /**
   * Create a resource not found error
   */
  resourceNotFound(
    resourceType?: string,
    resourceId?: string,
    options: ErrorFactoryOptions = {}
  ): ResourceNotFoundError {
    return new ResourceNotFoundError(
      options.message || DEFAULT_ERROR_MESSAGES.RESOURCE_NOT_FOUND,
      options.context,
      {
        ...options.details,
        resourceType,
        resourceId,
      },
      options.cause
    );
  },

  /**
   * Create an operation forbidden error
   */
  operationForbidden(
    operation?: string,
    options: ErrorFactoryOptions = {}
  ): OperationForbiddenError {
    return new OperationForbiddenError(
      options.message || DEFAULT_ERROR_MESSAGES.OPERATION_FORBIDDEN,
      options.context,
      {
        ...options.details,
        operation,
      },
      options.cause
    );
  },
};

/**
 * Rate limiting error factory functions
 */
export const RateLimitErrors = {
  /**
   * Create a too many requests error
   */
  tooManyRequests(options: RateLimitErrorOptions = {}): TooManyRequestsError {
    return new TooManyRequestsError(
      options.message || DEFAULT_ERROR_MESSAGES.TOO_MANY_REQUESTS,
      options.context,
      options.rateLimitDetails,
      options.cause
    );
  },

  /**
   * Create a too many login attempts error
   */
  tooManyLoginAttempts(options: RateLimitErrorOptions = {}): TooManyLoginAttemptsError {
    return new TooManyLoginAttemptsError(
      options.message || DEFAULT_ERROR_MESSAGES.TOO_MANY_LOGIN_ATTEMPTS,
      options.context,
      options.rateLimitDetails,
      options.cause
    );
  },
};

/**
 * Password policy error factory functions
 */
export const PasswordErrors = {
  /**
   * Create a weak password error
   */
  weakPassword(requirements?: string[], options: ErrorFactoryOptions = {}): WeakPasswordError {
    return new WeakPasswordError(
      options.message || DEFAULT_ERROR_MESSAGES.WEAK_PASSWORD,
      options.context,
      {
        ...options.details,
        failedRequirements: requirements,
      },
      options.cause
    );
  },

  /**
   * Create a password reuse error
   */
  passwordReuse(historySize?: number, options: ErrorFactoryOptions = {}): PasswordReuseError {
    return new PasswordReuseError(
      options.message || DEFAULT_ERROR_MESSAGES.PASSWORD_REUSE,
      options.context,
      {
        ...options.details,
        historySize,
      },
      options.cause
    );
  },

  /**
   * Create a password expired error
   */
  passwordExpired(expiresAt?: Date, options: ErrorFactoryOptions = {}): PasswordExpiredError {
    return new PasswordExpiredError(
      options.message || DEFAULT_ERROR_MESSAGES.PASSWORD_EXPIRED,
      options.context,
      {
        ...options.details,
        expiresAt: expiresAt?.toISOString(),
      },
      options.cause
    );
  },
};

/**
 * Account security error factory functions
 */
export const AccountErrors = {
  /**
   * Create an account locked error
   */
  accountLocked(
    lockReason?: string,
    unlockTime?: Date,
    options: ErrorFactoryOptions = {}
  ): AccountLockedError {
    return new AccountLockedError(
      options.message || DEFAULT_ERROR_MESSAGES.ACCOUNT_LOCKED,
      options.context,
      {
        ...options.details,
        lockReason,
        unlockTime: unlockTime?.toISOString(),
      },
      options.cause
    );
  },

  /**
   * Create an account suspended error
   */
  accountSuspended(
    suspensionReason?: string,
    options: ErrorFactoryOptions = {}
  ): AccountSuspendedError {
    return new AccountSuspendedError(
      options.message || DEFAULT_ERROR_MESSAGES.ACCOUNT_SUSPENDED,
      options.context,
      {
        ...options.details,
        suspensionReason,
      },
      options.cause
    );
  },

  /**
   * Create an email verification required error
   */
  emailVerificationRequired(options: ErrorFactoryOptions = {}): EmailVerificationRequiredError {
    return new EmailVerificationRequiredError(
      options.message || DEFAULT_ERROR_MESSAGES.EMAIL_VERIFICATION_REQUIRED,
      options.context,
      options.details,
      options.cause
    );
  },
};

/**
 * Session error factory functions
 */
export const SessionErrors = {
  /**
   * Create a session expired error
   */
  sessionExpired(options: ErrorFactoryOptions = {}): SessionExpiredError {
    return new SessionExpiredError(
      options.message || DEFAULT_ERROR_MESSAGES.SESSION_EXPIRED,
      options.context,
      options.details,
      options.cause
    );
  },

  /**
   * Create an invalid session error
   */
  invalidSession(options: ErrorFactoryOptions = {}): InvalidSessionError {
    return new InvalidSessionError(
      options.message || DEFAULT_ERROR_MESSAGES.INVALID_SESSION,
      options.context,
      options.details,
      options.cause
    );
  },
};

/**
 * System error factory functions
 */
export const SystemErrors = {
  /**
   * Create a security configuration error
   */
  securityConfig(configKey?: string, options: ErrorFactoryOptions = {}): SecurityConfigError {
    return new SecurityConfigError(
      options.message || DEFAULT_ERROR_MESSAGES.SECURITY_CONFIG_ERROR,
      options.context,
      {
        ...options.details,
        configKey,
      },
      options.cause
    );
  },

  /**
   * Create a cryptographic error
   */
  cryptographic(operation?: string, options: ErrorFactoryOptions = {}): CryptographicError {
    return new CryptographicError(
      options.message || DEFAULT_ERROR_MESSAGES.CRYPTOGRAPHIC_ERROR,
      options.context,
      {
        ...options.details,
        operation,
      },
      options.cause
    );
  },
};

/**
 * Utility function to create a security context from Express request-like object
 */
export function createSecurityContext(req: {
  ip?: string;
  get?: (header: string) => string | undefined;
  headers?: Record<string, string | string[] | undefined>;
  user?: { id: string };
  sessionID?: string;
  session?: { id: string };
}): SecurityContext {
  const sessionId = req.sessionID || req.session?.id || crypto.randomUUID();
  const ipAddress =
    req.ip ||
    (req.get && req.get('x-forwarded-for')) ||
    (req.headers &&
      (Array.isArray(req.headers['x-forwarded-for'])
        ? req.headers['x-forwarded-for'][0]
        : req.headers['x-forwarded-for'])) ||
    '0.0.0.0';

  const userAgent =
    (req.get && req.get('user-agent')) ||
    (req.headers && (req.headers['user-agent'] as string)) ||
    undefined;

  return {
    sessionId,
    ipAddress,
    ...(userAgent && { userAgent }),
    ...(req.user?.id && { userId: req.user.id }),
    timestamp: new Date(),
  };
}

/**
 * Utility function to extract error information for logging
 */
export function extractErrorInfo(error: unknown): {
  name: string;
  message: string;
  code?: string | undefined;
  statusCode?: number | undefined;
  severity?: string | undefined;
  stack?: string | undefined;
  isSecurityError: boolean;
} {
  if (error instanceof SecurityError) {
    return {
      name: error.name,
      message: error.message,
      code: error.code,
      statusCode: error.statusCode,
      severity: error.severity,
      stack: error.stack ?? undefined,
      isSecurityError: true,
    };
  }

  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack ?? undefined,
      isSecurityError: false,
    };
  }

  return {
    name: 'UnknownError',
    message: String(error),
    isSecurityError: false,
  };
}

/**
 * Utility function to determine if an error should be logged
 */
export function shouldLogError(error: unknown): boolean {
  if (error instanceof SecurityError) {
    return error.shouldLog;
  }

  // Log all non-security errors by default
  return true;
}

/**
 * Utility function to get error severity
 */
export function getErrorSeverity(error: unknown): 'low' | 'medium' | 'high' | 'critical' {
  if (error instanceof SecurityError) {
    return error.severity;
  }

  // Default severity for non-security errors
  return 'medium';
}

/**
 * Type-safe error factory that creates the appropriate error type based on code
 */
export function createSecurityError<T extends SecurityErrorType>(
  errorCode: string,
  message?: string,
  options: ErrorFactoryOptions = {}
): T {
  const finalMessage =
    message || DEFAULT_ERROR_MESSAGES[errorCode as keyof typeof DEFAULT_ERROR_MESSAGES];

  switch (errorCode) {
    case 'INVALID_CREDENTIALS':
      return new InvalidCredentialsError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'INVALID_TOKEN':
      return new InvalidTokenError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'TOKEN_EXPIRED':
      return new TokenExpiredError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'INVALID_REFRESH_TOKEN':
      return new InvalidRefreshTokenError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'INSUFFICIENT_PERMISSIONS':
      return new InsufficientPermissionsError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'RESOURCE_NOT_FOUND':
      return new ResourceNotFoundError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'OPERATION_FORBIDDEN':
      return new OperationForbiddenError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'TOO_MANY_REQUESTS':
      return new TooManyRequestsError(finalMessage, options.context, undefined, options.cause) as T;
    case 'TOO_MANY_LOGIN_ATTEMPTS':
      return new TooManyLoginAttemptsError(
        finalMessage,
        options.context,
        undefined,
        options.cause
      ) as T;
    case 'WEAK_PASSWORD':
      return new WeakPasswordError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'PASSWORD_REUSE':
      return new PasswordReuseError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'PASSWORD_EXPIRED':
      return new PasswordExpiredError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'ACCOUNT_LOCKED':
      return new AccountLockedError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'ACCOUNT_SUSPENDED':
      return new AccountSuspendedError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'EMAIL_VERIFICATION_REQUIRED':
      return new EmailVerificationRequiredError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'MFA_REQUIRED':
      return new MfaRequiredError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'INVALID_MFA_CODE':
      return new InvalidMfaCodeError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'SESSION_EXPIRED':
      return new SessionExpiredError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'INVALID_SESSION':
      return new InvalidSessionError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'SECURITY_CONFIG_ERROR':
      return new SecurityConfigError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    case 'CRYPTOGRAPHIC_ERROR':
      return new CryptographicError(
        finalMessage,
        options.context,
        options.details,
        options.cause
      ) as T;
    default:
      return new AuthenticationError(
        finalMessage || 'Erro de segurança desconhecido',
        options.context,
        options.details,
        options.cause
      ) as T;
  }
}
