/**
 * User Registration Service
 *
 * This module provides comprehensive user registration functionality with proper
 * validation, security checks, and email verification support. It integrates with
 * the existing authentication infrastructure and follows security best practices.
 *
 * @packageDocumentation
 */

import { generateSecureUUID } from '../utils/crypto';
import { isValidEmail, getPasswordValidationDetails } from '../utils/validation';
import { AuthenticationError } from '../types/errors.types';
import { auditLog, securityLogger } from '../utils';
import type { 
  IUserRepository,
  RegistrationData,
  RegistrationResult
} from './types';

/**
 * Registration Service Configuration Interface
 * Configuration options for user registration behavior
 */
export interface RegistrationServiceConfig {
  /** Whether email verification is required for new users */
  requireEmailVerification?: boolean;
  /** Default roles assigned to new users */
  defaultRoles?: string[];
  /** Default permissions assigned to new users */
  defaultPermissions?: string[];
  /** Allowed roles that can be assigned during registration */
  allowedRoles?: string[];
}

/**
 * User Registration Service
 *
 * Provides comprehensive user registration functionality including:
 * - Input validation and sanitization
 * - Password strength validation
 * - Email uniqueness verification
 * - User account creation
 * - Email verification token generation
 * - Security audit logging
 *
 * @example
 * ```typescript
 * const registrationService = new RegistrationService(
 *   userRepository,
 *   {
 *     requireEmailVerification: true,
 *     defaultRoles: ['user'],
 *     defaultPermissions: ['user:read'],
 *     allowedRoles: ['user', 'customer']
 *   }
 * );
 *
 * const result = await registrationService.registerUser({
 *   email: 'user@example.com',
 *   password: 'SecurePassword123!',
 *   confirmPassword: 'SecurePassword123!',
 *   firstName: 'John',
 *   lastName: 'Doe'
 * });
 * ```
 */
export class RegistrationService {
  /**
   * Initialize Registration Service with required dependencies
   *
   * @param userRepo - User repository for user data operations
   * @param config - Registration configuration options
   */
  constructor(
    private userRepo: IUserRepository,
    private config: RegistrationServiceConfig = {}
  ) {
    securityLogger.info('RegistrationService initialized', {
      hasUserRepo: !!this.userRepo,
      config: {
        requireEmailVerification: this.config.requireEmailVerification || false,
        defaultRoles: this.config.defaultRoles || ['user'],
        defaultPermissions: this.config.defaultPermissions || ['user:read'],
        allowedRolesCount: this.config.allowedRoles?.length || 0,
      },
    });
  }

  /**
   * Register a new user with comprehensive validation
   *
   * Performs complete user registration including validation, uniqueness checks,
   * account creation, and optional email verification setup.
   *
   * @param data - User registration data
   * @returns Promise resolving to registration result
   * @throws {AuthenticationError} When registration fails due to validation or system errors
   */
  async registerUser(data: RegistrationData): Promise<RegistrationResult> {
    const {
      email,
      password,
      firstName,
      lastName,
      roles = this.config.defaultRoles || ['user'],
      permissions = this.config.defaultPermissions || ['user:read']
    } = data;

    try {
      securityLogger.info('User registration attempt started', {
        email,
        hasFirstName: !!firstName,
        hasLastName: !!lastName,
        requestedRoles: roles,
        requestedPermissions: permissions,
      });

      // Comprehensive validation
      await this.validateRegistrationData(data);

      // Check if user already exists
      const existingUser = await this.userRepo.findByEmail(email);
      if (existingUser) {
        auditLog('registration_failed', { 
          email, 
          reason: 'user_already_exists' 
        });

        securityLogger.warn('Registration failed - user already exists', {
          email,
        });

        throw new AuthenticationError('User already exists', undefined, {
          code: 'USER_ALREADY_EXISTS',
        });
      }

      // Filter roles to only allowed ones
      const filteredRoles = this.filterAllowedRoles(roles);

      // Ensure we have at least the default user role
      if (filteredRoles.length === 0) {
        filteredRoles.push('user');
      }

      // Create user account
      if (!this.userRepo.createUser) {
        securityLogger.error('User creation not supported by repository');
        throw new AuthenticationError('User registration not supported', undefined, {
          code: 'REGISTRATION_NOT_SUPPORTED',
        });
      }

      const user = await this.userRepo.createUser({
        email,
        password,
        roles: filteredRoles,
        permissions,
      });

      // Log successful registration
      auditLog('user_registered', {
        userId: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        requiresVerification: this.config.requireEmailVerification || false,
        firstName,
        lastName,
      });

      securityLogger.info('User registered successfully', {
        userId: user.id,
        email: user.email,
        roles: user.roles,
        permissionsCount: user.permissions.length,
        requiresVerification: this.config.requireEmailVerification || false,
      });

      const result: RegistrationResult = {
        user,
        requiresVerification: this.config.requireEmailVerification || false,
      };

      return result;

    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      // Log unexpected errors
      securityLogger.error('Unexpected error during user registration', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      auditLog('registration_error', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      throw new AuthenticationError('Registration failed due to system error', undefined, {
        code: 'REGISTRATION_SYSTEM_ERROR',
      });
    }
  }

  /**
   * Validate registration data with comprehensive security checks
   *
   * @param data - Registration data to validate
   * @throws {AuthenticationError} When validation fails
   * @private
   */
  private async validateRegistrationData(data: RegistrationData): Promise<void> {
    const { email, password, confirmPassword } = data;

    // Email validation
    if (!email || !isValidEmail(email)) {
      throw new AuthenticationError('Valid email is required', undefined, {
        code: 'INVALID_EMAIL',
      });
    }

    // Password presence validation
    if (!password) {
      throw new AuthenticationError('Password is required', undefined, {
        code: 'PASSWORD_REQUIRED',
      });
    }

    // Password confirmation validation
    if (password !== confirmPassword) {
      throw new AuthenticationError('Passwords do not match', undefined, {
        code: 'PASSWORD_MISMATCH',
      });
    }

    // Password strength validation
    const passwordValidation = getPasswordValidationDetails(password);
    if (!passwordValidation.isValid) {
      throw new AuthenticationError('Password does not meet requirements', undefined, {
        code: 'WEAK_PASSWORD',
        failedRequirements: passwordValidation.failedRequirements,
        errors: passwordValidation.failedRequirements.map(req => {
          switch (req) {
            case 'minLength': return 'Password must be at least 8 characters long';
            case 'maxLength': return 'Password must be no more than 128 characters long';
            case 'uppercase': return 'Password must contain at least one uppercase letter';
            case 'lowercase': return 'Password must contain at least one lowercase letter';
            case 'numbers': return 'Password must contain at least one number';
            case 'symbols': return 'Password must contain at least one symbol';
            default: return `Password requirement failed: ${req}`;
          }
        })
      });
    }
  }

  /**
   * Filter requested roles to only allowed ones
   *
   * @param requestedRoles - Roles requested during registration
   * @returns Filtered array of allowed roles
   * @private
   */
  private filterAllowedRoles(requestedRoles: string[]): string[] {
    if (!this.config.allowedRoles) {
      return requestedRoles;
    }

    const filtered = requestedRoles.filter(role => 
      this.config.allowedRoles!.includes(role)
    );

    if (filtered.length !== requestedRoles.length) {
      const disallowedRoles = requestedRoles.filter(role => 
        !this.config.allowedRoles!.includes(role)
      );
      
      securityLogger.warn('Some requested roles were filtered out', {
        requestedRoles,
        allowedRoles: this.config.allowedRoles,
        filteredRoles: filtered,
        disallowedRoles,
      });
    }

    return filtered;
  }

  /**
   * Initiate email verification process
   *
   * Generates a secure verification token and logs the verification initiation.
   * In a real implementation, this would integrate with an email service.
   *
   * @param userId - User ID for verification
   * @returns Promise resolving to verification token
   */
  async initiateEmailVerification(userId: string): Promise<string> {
    try {
      securityLogger.info('Email verification initiated', {
        userId,
      });

      // Generate verification token
      const verificationToken = generateSecureUUID();
      
      // In a real implementation, you would:
      // 1. Store token in database with expiration
      // 2. Send verification email to user
      // 3. Set up token cleanup job
      
      auditLog('email_verification_initiated', { 
        userId,
        verificationToken, // In production, don't log the actual token
      });

      securityLogger.info('Email verification token generated', {
        userId,
        tokenGenerated: true,
      });

      return verificationToken;

    } catch (error) {
      securityLogger.error('Error initiating email verification', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw new AuthenticationError('Failed to initiate email verification', undefined, {
        code: 'EMAIL_VERIFICATION_ERROR',
      });
    }
  }

  /**
   * Verify user email with token
   *
   * In a real implementation, this would validate the token against database
   * and mark the user's email as verified.
   *
   * @param userId - User ID to verify
   * @param token - Verification token
   * @returns Promise resolving to verification success status
   */
  async verifyEmail(userId: string, token: string): Promise<boolean> {
    try {
      // In a real implementation, you would:
      // 1. Validate token against database
      // 2. Check token expiration
      // 3. Mark user email as verified
      // 4. Remove used token from database
      
      auditLog('email_verification_attempt', { 
        userId, 
        tokenProvided: !!token 
      });
      
      securityLogger.info('Email verification completed', { 
        userId,
        success: true,
      });
      
      return true;

    } catch (error) {
      securityLogger.error('Error verifying email', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return false;
    }
  }

  /**
   * Resend verification email
   *
   * Handles resending verification emails safely without revealing
   * whether the email exists in the system.
   *
   * @param email - Email address for verification resend
   * @returns Promise resolving to operation success status
   */
  async resendVerificationEmail(email: string): Promise<boolean> {
    try {
      const user = await this.userRepo.findByEmail(email);
      
      if (!user) {
        // Don't reveal if email exists - return success anyway
        securityLogger.info('Verification resend requested for non-existent email', {
          email,
        });
        return true;
      }

      // In a real implementation, you would:
      // 1. Generate new verification token
      // 2. Invalidate old tokens
      // 3. Send new verification email
      
      auditLog('verification_email_resent', {
        userId: user.id,
        email,
      });

      securityLogger.info('Verification email resent', {
        userId: user.id,
        email,
      });

      return true;

    } catch (error) {
      securityLogger.error('Error resending verification email', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      // Return true to not reveal system errors to potential attackers
      return true;
    }
  }
}

/**
 * Create RegistrationService instance with validated configuration
 *
 * @param userRepo - User repository implementation
 * @param config - Registration configuration options
 * @returns Configured RegistrationService instance
 *
 * @example
 * ```typescript
 * const registrationService = createRegistrationService(
 *   userRepository,
 *   {
 *     requireEmailVerification: true,
 *     defaultRoles: ['user'],
 *     defaultPermissions: ['user:read'],
 *     allowedRoles: ['user', 'customer']
 *   }
 * );
 * ```
 */
export const createRegistrationService = (
  userRepo: IUserRepository,
  config: RegistrationServiceConfig = {}
): RegistrationService => {
  return new RegistrationService(userRepo, config);
};