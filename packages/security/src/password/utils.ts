/**
 * Password security utilities and constants
 *
 * This module provides utility functions, constants, and default configurations
 * for password security operations, including validation, hashing, and policy
 * enforcement.
 *
 * @packageDocumentation
 */

import type {
  PasswordGenerationOptions,
  PasswordPolicy,
  PasswordPolicySet,
  PasswordRotationPolicy,
  PasswordSecurityConfig,
} from './types';

/**
 * Default password policy for consumer users
 * Balanced security requirements for end users
 */
export const DEFAULT_CONSUMER_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 8,
  maxLength: 128,
  requireNumbers: true,
  requireSymbols: true,
  requireUppercase: true,
  requireLowercase: true,
  preventCommonPasswords: true,
  preventSequential: false,
  preventRepeated: false,
  minUniqueChars: 6,
  customPatterns: [],
  forbiddenPatterns: [],
};

/**
 * Enhanced password policy for professional users (clinic staff)
 * Stricter requirements for healthcare professionals
 */
export const DEFAULT_PROFESSIONAL_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 10,
  maxLength: 128,
  requireNumbers: true,
  requireSymbols: true,
  requireUppercase: true,
  requireLowercase: true,
  preventCommonPasswords: true,
  preventSequential: true,
  preventRepeated: true,
  minUniqueChars: 8,
  customPatterns: [],
  forbiddenPatterns: [
    // Prevent common healthcare-related weak patterns
    /^(clinic|hospital|health|medical|doctor|patient)/i,
    /^(agenda|bella|appointment)/i,
  ],
};

/**
 * Maximum security password policy for admin users
 * Highest security requirements for administrative access
 */
export const DEFAULT_ADMIN_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireNumbers: true,
  requireSymbols: true,
  requireUppercase: true,
  requireLowercase: true,
  preventCommonPasswords: true,
  preventSequential: true,
  preventRepeated: true,
  minUniqueChars: 10,
  customPatterns: [],
  forbiddenPatterns: [
    // Prevent admin-related weak patterns
    /^(admin|administrator|root|super|system)/i,
    /^(clinic|hospital|health|medical)/i,
    /^(agenda|bella)/i,
  ],
};

/**
 * Default password rotation policy for consumer users
 */
export const DEFAULT_CONSUMER_ROTATION_POLICY: PasswordRotationPolicy = {
  maxAgeDays: 365, // 1 year
  historyCount: 5,
  warningDays: 30,
  gracePeriodDays: 7,
  enforceForUserTypes: ['consumer'],
};

/**
 * Default password rotation policy for professional users
 */
export const DEFAULT_PROFESSIONAL_ROTATION_POLICY: PasswordRotationPolicy = {
  maxAgeDays: 180, // 6 months
  historyCount: 10,
  warningDays: 14,
  gracePeriodDays: 3,
  enforceForUserTypes: ['professional'],
};

/**
 * Default password rotation policy for admin users
 */
export const DEFAULT_ADMIN_ROTATION_POLICY: PasswordRotationPolicy = {
  maxAgeDays: 90, // 3 months
  historyCount: 15,
  warningDays: 7,
  gracePeriodDays: 1,
  enforceForUserTypes: ['admin'],
};

/**
 * Default password policy set for all user levels
 */
export const DEFAULT_PASSWORD_POLICY_SET: PasswordPolicySet = {
  consumer: DEFAULT_CONSUMER_PASSWORD_POLICY,
  professional: DEFAULT_PROFESSIONAL_PASSWORD_POLICY,
  admin: DEFAULT_ADMIN_PASSWORD_POLICY,
  rotation: {
    consumer: DEFAULT_CONSUMER_ROTATION_POLICY,
    professional: DEFAULT_PROFESSIONAL_ROTATION_POLICY,
    admin: DEFAULT_ADMIN_ROTATION_POLICY,
  },
};

/**
 * Bcrypt round configurations for different security levels
 * Higher rounds provide better security but slower performance
 */
export const BCRYPT_ROUNDS = {
  /** Low security - fast hashing for development */
  LOW: 10,
  /** Medium security - balanced performance */
  MEDIUM: 12,
  /** High security - slower but more secure */
  HIGH: 14,
  /** Maximum security - very slow but maximum protection */
  MAXIMUM: 16,
} as const;

/**
 * Default bcrypt rounds based on user type
 */
export const DEFAULT_BCRYPT_ROUNDS_BY_USER_TYPE = {
  consumer: BCRYPT_ROUNDS.MEDIUM,
  professional: BCRYPT_ROUNDS.HIGH,
  admin: BCRYPT_ROUNDS.HIGH,
} as const;

/**
 * Password strength score labels
 * Human-readable labels for password strength scores
 */
export const PASSWORD_STRENGTH_LABELS = {
  0: 'Muito Fraca',
  1: 'Fraca',
  2: 'Regular',
  3: 'Forte',
  4: 'Muito Forte',
} as const;

/**
 * Common password patterns to detect and prevent
 */
export const COMMON_WEAK_PATTERNS = {
  /** Sequential characters */
  SEQUENTIAL:
    /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789)/i,

  /** Repeated characters */
  REPEATED: /(.)\1{2,}/,

  /** Keyboard patterns */
  KEYBOARD: /(?:qwerty|asdfgh|zxcvbn|123456|654321)/i,

  /** Date patterns */
  DATE_PATTERNS: /(?:19|20)\d{2}|(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/,

  /** Common substitutions */
  SUBSTITUTIONS: /@|3|1|0|5|7/g,
} as const;

/**
 * Character sets for password generation
 */
export const CHARACTER_SETS = {
  UPPERCASE: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  LOWERCASE: 'abcdefghijklmnopqrstuvwxyz',
  NUMBERS: '0123456789',
  SYMBOLS: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  AMBIGUOUS: '0O1lI',
} as const;

/**
 * Default password generation options
 */
export const DEFAULT_PASSWORD_GENERATION_OPTIONS: PasswordGenerationOptions = {
  length: 16,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true,
  excludeAmbiguous: true,
  excludeChars: '',
};

/**
 * Password generation options by user type
 */
export const PASSWORD_GENERATION_OPTIONS_BY_USER_TYPE = {
  consumer: {
    ...DEFAULT_PASSWORD_GENERATION_OPTIONS,
    length: 12,
  },
  professional: {
    ...DEFAULT_PASSWORD_GENERATION_OPTIONS,
    length: 16,
  },
  admin: {
    ...DEFAULT_PASSWORD_GENERATION_OPTIONS,
    length: 20,
  },
} as const;

/**
 * Default password security configuration
 */
export const DEFAULT_PASSWORD_SECURITY_CONFIG: PasswordSecurityConfig = {
  policies: DEFAULT_PASSWORD_POLICY_SET,
  bcrypt: {
    defaultRounds: BCRYPT_ROUNDS.MEDIUM,
    minRounds: BCRYPT_ROUNDS.LOW,
    maxRounds: BCRYPT_ROUNDS.MAXIMUM,
  },
  breachCheck: {
    enabled: true,
    timeout: 5000, // 5 seconds
    cache: true,
    cacheTtl: 86400, // 24 hours
  },
  reset: {
    tokenExpirationMinutes: 30,
    maxAttemptsPerHour: 5,
    cooldownMinutes: 15,
  },
};

/**
 * Common passwords to check against (top 100 most common)
 * These should be prevented in password validation
 */
export const COMMON_PASSWORDS = new Set([
  '123456',
  'password',
  '123456789',
  '12345678',
  '12345',
  '111111',
  '1234567',
  'sunshine',
  'qwerty',
  'iloveyou',
  'princess',
  'admin',
  'welcome',
  '666666',
  'abc123',
  'football',
  '123123',
  'monkey',
  '654321',
  '!@#$%^&*',
  'charlie',
  'aa123456',
  'donald',
  'password1',
  'qwerty123',
  // Add Brazilian Portuguese common passwords
  'senha',
  'senha123',
  'brasil',
  'futebol',
  'familia',
  'amor',
  'dinheiro',
  'trabalho',
  'casa',
  'vida',
  'felicidade',
  'saude',
  'clinica',
  'medico',
  'paciente',
  'agendabella',
  'agenda',
  'bella',
]);

/**
 * Password entropy calculation constants
 */
export const ENTROPY_CONSTANTS = {
  /** Bits per character for different character sets */
  BITS_PER_CHARSET: {
    lowercase: Math.log2(26),
    uppercase: Math.log2(26),
    numbers: Math.log2(10),
    symbols: Math.log2(32), // Approximate for common symbols
  },
  /** Minimum entropy for different strength levels */
  MIN_ENTROPY: {
    weak: 25,
    fair: 50,
    good: 75,
    strong: 100,
  },
} as const;

/**
 * Password validation error messages in Portuguese
 */
export const PASSWORD_VALIDATION_MESSAGES = {
  TOO_SHORT: (min: number) => `A senha deve ter pelo menos ${min} caracteres`,
  TOO_LONG: (max: number) => `A senha deve ter no máximo ${max} caracteres`,
  MISSING_UPPERCASE: 'A senha deve conter pelo menos uma letra maiúscula',
  MISSING_LOWERCASE: 'A senha deve conter pelo menos uma letra minúscula',
  MISSING_NUMBER: 'A senha deve conter pelo menos um número',
  MISSING_SYMBOL: 'A senha deve conter pelo menos um símbolo',
  COMMON_PASSWORD: 'Esta senha é muito comum e não é segura',
  SEQUENTIAL_CHARS: 'A senha não deve conter caracteres sequenciais',
  REPEATED_CHARS: 'A senha não deve conter caracteres repetidos',
  INSUFFICIENT_UNIQUE: (min: number) => `A senha deve ter pelo menos ${min} caracteres únicos`,
  FORBIDDEN_PATTERN: 'A senha contém padrões não permitidos',
  COMPROMISED: 'Esta senha foi encontrada em vazamentos de dados',
} as const;

/**
 * Password strength feedback messages in Portuguese
 */
export const PASSWORD_STRENGTH_FEEDBACK = {
  SUGGESTIONS: {
    ADD_ANOTHER_WORD: 'Adicione mais uma palavra não relacionada',
    CAPITALIZE: 'Use maiúsculas em locais menos previsíveis',
    ALL_UPPERCASE: 'Evite usar todas as letras em maiúsculas',
    REVERSE_WORDS: 'Evite palavras comuns mesmo ao contrário',
    PREDICTABLE_SUBSTITUTIONS: 'Evite substituições previsíveis como @ por a',
    ADD_SYMBOLS_NUMBERS: 'Adicione símbolos e números',
    LONGER_KEYBOARD_PATTERN: 'Evite padrões de teclado',
    LONGER_PASSWORD: 'Use uma senha mais longa',
    MIXED_CASE: 'Use uma mistura de maiúsculas e minúsculas',
    NO_PERSONAL_INFO: 'Evite informações pessoais',
  },
  WARNINGS: {
    STRAIGHT_ROWS: 'Evite sequências de teclas adjacentes',
    SHORT_KEYBOARD_PATTERNS: 'Evite padrões curtos de teclado',
    REPEATS: 'Evite caracteres e palavras repetidas',
    SEQUENCES: 'Evite sequências de caracteres',
    RECENT_YEARS: 'Evite anos recentes',
    DATES: 'Evite datas',
    TOP10_PASSWORDS: 'Esta é uma das 10 senhas mais usadas',
    TOP100_PASSWORDS: 'Esta é uma das 100 senhas mais usadas',
    VERY_COMMON: 'Esta é uma senha muito comum',
    SIMILAR_TO_COMMON: 'Esta senha é similar a senhas comuns',
    WORD_BY_ITSELF: 'Uma palavra sozinha é fácil de adivinhar',
    NAME_BY_ITSELF: 'Nomes sozinhos são fáceis de adivinhar',
    COMMON_NAME: 'Nomes comuns são fáceis de adivinhar',
    USER_INPUTS: 'Evite usar informações pessoais na senha',
  },
} as const;

/**
 * Regular expressions for password validation
 */
export const PASSWORD_REGEX = {
  /** At least one uppercase letter */
  HAS_UPPERCASE: /[A-Z]/,
  /** At least one lowercase letter */
  HAS_LOWERCASE: /[a-z]/,
  /** At least one number */
  HAS_NUMBER: /\d/,
  /** At least one symbol */
  HAS_SYMBOL: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>?]/,
  /** Sequential characters (3 or more) */
  SEQUENTIAL:
    /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789|987|876|765|654|543|432|321)/i,
  /** Repeated characters (3 or more) */
  REPEATED: /(.)\1{2,}/,
  /** Only letters and numbers (no symbols) */
  ALPHANUMERIC_ONLY: /^[a-zA-Z0-9]+$/,
} as const;

/**
 * Timing constants for security operations
 */
export const TIMING_CONSTANTS = {
  /** Minimum time for password verification (to prevent timing attacks) */
  MIN_VERIFICATION_TIME_MS: 100,
  /** Maximum time for password verification before timeout */
  MAX_VERIFICATION_TIME_MS: 5000,
  /** Delay between failed login attempts */
  FAILED_LOGIN_DELAY_MS: 1000,
} as const;

/**
 * Utility function to get password policy by user type
 */
export function getPasswordPolicyByUserType(
  userType: 'consumer' | 'professional' | 'admin',
  customPolicies?: Partial<PasswordPolicySet>
): PasswordPolicy {
  const policies = customPolicies || DEFAULT_PASSWORD_POLICY_SET;
  return policies[userType] || DEFAULT_PASSWORD_POLICY_SET[userType];
}

/**
 * Utility function to get bcrypt rounds by user type
 */
export function getBcryptRoundsByUserType(userType: 'consumer' | 'professional' | 'admin'): number {
  return DEFAULT_BCRYPT_ROUNDS_BY_USER_TYPE[userType] || BCRYPT_ROUNDS.MEDIUM;
}

/**
 * Utility function to get password generation options by user type
 */
export function getPasswordGenerationOptionsByUserType(
  userType: 'consumer' | 'professional' | 'admin'
): PasswordGenerationOptions {
  return PASSWORD_GENERATION_OPTIONS_BY_USER_TYPE[userType] || DEFAULT_PASSWORD_GENERATION_OPTIONS;
}

/**
 * Utility function to check if a password is in the common passwords list
 */
export function isCommonPassword(password: string): boolean {
  return COMMON_PASSWORDS.has(password.toLowerCase());
}

/**
 * Utility function to calculate password entropy
 */
export function calculatePasswordEntropy(password: string): number {
  const length = password.length;
  let charsetSize = 0;

  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/\d/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  return length * Math.log2(charsetSize);
}

/**
 * Utility function to generate character set for password generation
 */
export function generateCharacterSet(options: PasswordGenerationOptions): string {
  let charset = '';

  if (options.includeLowercase) charset += CHARACTER_SETS.LOWERCASE;
  if (options.includeUppercase) charset += CHARACTER_SETS.UPPERCASE;
  if (options.includeNumbers) charset += CHARACTER_SETS.NUMBERS;
  if (options.includeSymbols) charset += CHARACTER_SETS.SYMBOLS;

  if (options.customCharset) {
    charset = options.customCharset;
  }

  if (options.excludeAmbiguous) {
    charset = charset.replace(new RegExp(`[${CHARACTER_SETS.AMBIGUOUS}]`, 'g'), '');
  }

  if (options.excludeChars) {
    charset = charset.replace(new RegExp(`[${options.excludeChars}]`, 'g'), '');
  }

  return charset;
}
