/**
 * Password security module
 *
 * This module provides comprehensive password security functionality including:
 * - Password policy enforcement and validation
 * - Secure password hashing with bcrypt
 * - Password strength assessment and feedback
 * - Password generation with customizable options
 * - Password history and rotation management
 * - Breach checking and compromised password detection
 *
 * The module supports different security levels for different user types:
 * - Consumer: Standard security requirements
 * - Professional: Enhanced security for clinic staff
 * - Admin: Maximum security for administrative access
 *
 * @packageDocumentation
 */

// Export all password security types
export type {
  PasswordPolicy,
  PasswordStrength,
  HashResult,
  PasswordValidationResult,
  PasswordHistoryEntry,
  PasswordRotationPolicy,
  PasswordResetRequest,
  PasswordResetResult,
  PasswordChangeRequest,
  PasswordChangeResult,
  PasswordVerificationRequest,
  PasswordVerificationResult,
  PasswordBreachResult,
  PasswordPolicyLevel,
  PasswordPolicySet,
  PasswordSecurityConfig,
  PasswordGenerationOptions,
  GeneratedPasswordResult,
} from './types';

// Export all password utilities and constants
export {
  DEFAULT_CONSUMER_PASSWORD_POLICY,
  DEFAULT_PROFESSIONAL_PASSWORD_POLICY,
  DEFAULT_ADMIN_PASSWORD_POLICY,
  DEFAULT_CONSUMER_ROTATION_POLICY,
  DEFAULT_PROFESSIONAL_ROTATION_POLICY,
  DEFAULT_ADMIN_ROTATION_POLICY,
  DEFAULT_PASSWORD_POLICY_SET,
  BCRYPT_ROUNDS,
  DEFAULT_BCRYPT_ROUNDS_BY_USER_TYPE,
  PASSWORD_STRENGTH_LABELS,
  COMMON_WEAK_PATTERNS,
  CHARACTER_SETS,
  DEFAULT_PASSWORD_GENERATION_OPTIONS,
  PASSWORD_GENERATION_OPTIONS_BY_USER_TYPE,
  DEFAULT_PASSWORD_SECURITY_CONFIG,
  COMMON_PASSWORDS,
  ENTROPY_CONSTANTS,
  PASSWORD_VALIDATION_MESSAGES,
  PASSWORD_STRENGTH_FEEDBACK,
  PASSWORD_REGEX,
  TIMING_CONSTANTS,
  getPasswordPolicyByUserType,
  getBcryptRoundsByUserType,
  getPasswordGenerationOptionsByUserType,
  isCommonPassword,
  calculatePasswordEntropy,
  generateCharacterSet,
  hashPassword,
  verifyPassword,
} from './utils';

// TODO: Export password service implementations when ready
// export { PasswordService } from './service';
// export { PasswordValidator } from './validator';
// export { PasswordHasher } from './hasher';
// export { PasswordGenerator } from './generator';
