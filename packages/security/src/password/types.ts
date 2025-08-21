/**
 * Password security types and interfaces
 *
 * This module provides comprehensive type definitions for password security,
 * including password policies, strength validation, secure hashing, and
 * password lifecycle management.
 *
 * @packageDocumentation
 */

import type { SecurityContext, SecurityError } from '../types';

/**
 * Password policy configuration
 * Defines rules and requirements for password validation
 */
export interface PasswordPolicy {
  /** Minimum password length */
  minLength: number;
  /** Maximum password length */
  maxLength: number;
  /** Require at least one number (0-9) */
  requireNumbers: boolean;
  /** Require at least one symbol/special character */
  requireSymbols: boolean;
  /** Require at least one uppercase letter (A-Z) */
  requireUppercase: boolean;
  /** Require at least one lowercase letter (a-z) */
  requireLowercase: boolean;
  /** Check against common/compromised password lists */
  preventCommonPasswords: boolean;
  /** Prevent sequential characters (abc, 123, etc.) */
  preventSequential?: boolean;
  /** Prevent repeated characters (aaa, 111, etc.) */
  preventRepeated?: boolean;
  /** Minimum unique characters required */
  minUniqueChars?: number;
  /** Custom regex patterns that passwords must match */
  customPatterns?: RegExp[];
  /** Custom regex patterns that passwords must NOT match */
  forbiddenPatterns?: RegExp[];
}

/**
 * Password strength assessment result
 * Provides detailed feedback about password quality
 */
export interface PasswordStrength {
  /** Strength score from 0 (very weak) to 4 (very strong) */
  score: 0 | 1 | 2 | 3 | 4;
  /** Human-readable feedback messages */
  feedback: string[];
  /** Whether password meets minimum policy requirements */
  isValid: boolean;
  /** Estimated time to crack the password */
  crackTime?: string;
  /** Detected patterns that weaken the password */
  weaknesses?: string[];
  /** Suggestions for improving password strength */
  suggestions?: string[];
  /** Whether password was found in breach databases */
  isCompromised?: boolean;
}

/**
 * Password hashing result
 * Contains hashed password and algorithm metadata
 */
export interface HashResult {
  /** The hashed password */
  hash: string;
  /** Salt used for hashing (if applicable) */
  salt?: string;
  /** Hashing algorithm used */
  algorithm: 'bcrypt';
  /** Number of rounds/iterations used */
  rounds: number;
  /** When the hash was created */
  createdAt: Date;
}

/**
 * Password validation result
 * Result of validating a password against a policy
 */
export interface PasswordValidationResult {
  /** Whether the password is valid */
  isValid: boolean;
  /** Password strength assessment */
  strength: PasswordStrength;
  /** Policy violations if any */
  violations: string[];
  /** Security context for the validation */
  context: SecurityContext;
}

/**
 * Password history entry
 * Tracks previous passwords to prevent reuse
 */
export interface PasswordHistoryEntry {
  /** Unique identifier for the history entry */
  id: string;
  /** User ID this history belongs to */
  userId: string;
  /** Hashed password */
  passwordHash: string;
  /** When the password was set */
  createdAt: Date;
  /** Hash algorithm used */
  algorithm: 'bcrypt';
  /** Hash rounds used */
  rounds: number;
}

/**
 * Password rotation policy
 * Defines when and how passwords should be rotated
 */
export interface PasswordRotationPolicy {
  /** Maximum age of password in days */
  maxAgeDays: number;
  /** Number of previous passwords to remember */
  historyCount: number;
  /** Days before expiration to start warning user */
  warningDays: number;
  /** Grace period after expiration before forcing change */
  gracePeriodDays: number;
  /** Whether to enforce rotation for specific user types */
  enforceForUserTypes?: ('consumer' | 'professional' | 'admin')[];
}

/**
 * Password reset request
 * Information needed to initiate password reset
 */
export interface PasswordResetRequest {
  /** User identifier (email or username) */
  identifier: string;
  /** Security context for the request */
  context: SecurityContext;
  /** Optional challenge response (CAPTCHA, etc.) */
  challengeResponse?: string;
  /** Reset method preference */
  method?: 'email' | 'sms' | 'security_questions';
}

/**
 * Password reset result
 * Result of password reset request
 */
export interface PasswordResetResult {
  /** Whether the reset was initiated successfully */
  success: boolean;
  /** Reset token if successful */
  resetToken?: string;
  /** When the reset token expires */
  expiresAt?: Date;
  /** Reset method used */
  method?: 'email' | 'sms' | 'security_questions';
  /** Error information if reset failed */
  error?: SecurityError;
  /** Security context for the reset */
  context: SecurityContext;
}

/**
 * Password change request
 * Information needed to change a password
 */
export interface PasswordChangeRequest {
  /** User ID or reset token */
  userIdOrToken: string;
  /** New password */
  newPassword: string;
  /** Current password (for authenticated changes) */
  currentPassword?: string;
  /** Whether this is a reset using a token */
  isReset?: boolean;
  /** Whether to force password change */
  forceChange?: boolean;
  /** Security context for the change */
  context: SecurityContext;
}

/**
 * Password change result
 * Result of password change operation
 */
export interface PasswordChangeResult {
  /** Whether the change was successful */
  success: boolean;
  /** Whether user needs to re-authenticate */
  requiresReauth?: boolean;
  /** New password strength assessment */
  strength?: PasswordStrength;
  /** When the password was changed */
  changedAt?: Date;
  /** When the password will expire */
  expiresAt?: Date;
  /** Error information if change failed */
  error?: SecurityError;
  /** Security context for the change */
  context: SecurityContext;
}

/**
 * Password verification request
 * Information needed to verify a password
 */
export interface PasswordVerificationRequest {
  /** Password to verify */
  password: string;
  /** Stored password hash */
  hash: string;
  /** Security context for verification */
  context: SecurityContext;
}

/**
 * Password verification result
 * Result of password verification
 */
export interface PasswordVerificationResult {
  /** Whether the password matches */
  isValid: boolean;
  /** Whether the hash needs rehashing (outdated algorithm/rounds) */
  needsRehash?: boolean;
  /** Recommended new hash if rehashing needed */
  newHash?: HashResult;
  /** Time taken for verification (for timing attack prevention) */
  verificationTime?: number;
  /** Security context for verification */
  context: SecurityContext;
}

/**
 * Password breach check result
 * Result of checking password against breach databases
 */
export interface PasswordBreachResult {
  /** Whether password was found in breach databases */
  isCompromised: boolean;
  /** Number of times password was found in breaches */
  breachCount?: number;
  /** Breach databases checked */
  databasesChecked?: string[];
  /** When the check was performed */
  checkedAt: Date;
}

/**
 * Password policy enforcement levels
 * Different security levels for different user types
 */
export type PasswordPolicyLevel = 'consumer' | 'professional' | 'admin';

/**
 * Password policy set
 * Collection of policies for different user levels
 */
export interface PasswordPolicySet {
  /** Policy for consumer users */
  consumer: PasswordPolicy;
  /** Policy for professional users (clinic staff) */
  professional: PasswordPolicy;
  /** Policy for admin users */
  admin: PasswordPolicy;
  /** Rotation policies for each level */
  rotation: Record<PasswordPolicyLevel, PasswordRotationPolicy>;
}

/**
 * Password security configuration
 * Overall configuration for password security system
 */
export interface PasswordSecurityConfig {
  /** Password policies by user level */
  policies: PasswordPolicySet;
  /** Bcrypt configuration */
  bcrypt: {
    /** Default rounds for new hashes */
    defaultRounds: number;
    /** Minimum rounds to accept */
    minRounds: number;
    /** Maximum rounds to use */
    maxRounds: number;
  };
  /** Breach checking configuration */
  breachCheck: {
    /** Whether to enable breach checking */
    enabled: boolean;
    /** Timeout for breach check requests */
    timeout: number;
    /** Whether to cache breach check results */
    cache: boolean;
    /** Cache TTL in seconds */
    cacheTtl: number;
  };
  /** Password reset configuration */
  reset: {
    /** Token expiration time in minutes */
    tokenExpirationMinutes: number;
    /** Maximum reset attempts per hour */
    maxAttemptsPerHour: number;
    /** Cooldown period between attempts in minutes */
    cooldownMinutes: number;
  };
}

/**
 * Password generation options
 * Configuration for generating secure passwords
 */
export interface PasswordGenerationOptions {
  /** Password length */
  length: number;
  /** Include uppercase letters */
  includeUppercase: boolean;
  /** Include lowercase letters */
  includeLowercase: boolean;
  /** Include numbers */
  includeNumbers: boolean;
  /** Include symbols */
  includeSymbols: boolean;
  /** Exclude ambiguous characters (0, O, l, 1, etc.) */
  excludeAmbiguous: boolean;
  /** Custom character set to use */
  customCharset?: string;
  /** Characters to exclude */
  excludeChars?: string;
}

/**
 * Generated password result
 * Result of password generation
 */
export interface GeneratedPasswordResult {
  /** Generated password */
  password: string;
  /** Password strength assessment */
  strength: PasswordStrength;
  /** Generation options used */
  options: PasswordGenerationOptions;
  /** Entropy bits of the generated password */
  entropy: number;
}
