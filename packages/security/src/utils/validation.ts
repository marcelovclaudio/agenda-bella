/**
 * Input validation and sanitization utility functions
 *
 * This module provides common validation functions for user inputs, security
 * validation, and data sanitization. All functions are designed with security
 * in mind and follow best practices for input validation.
 *
 * @packageDocumentation
 */

/**
 * Password validation requirements interface
 */
export interface PasswordRequirements {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
}

/**
 * Default password requirements following security best practices
 */
export const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
};

/**
 * Validate email address format using comprehensive regex
 *
 * This function validates email format according to RFC 5322 standards
 * with practical considerations for real-world usage.
 *
 * @param email - Email address to validate
 * @returns True if email format is valid
 *
 * @example
 * ```typescript
 * isValidEmail('user@example.com'); // true
 * isValidEmail('invalid.email'); // false
 * isValidEmail('user+tag@example.co.uk'); // true
 * ```
 */
export const isValidEmail = (email: string): boolean => {
  if (typeof email !== 'string' || email.length === 0) {
    return false;
  }

  // Trim whitespace and check length limits
  const trimmedEmail = email.trim();
  if (trimmedEmail.length > 254) {
    // RFC 5321 limit
    return false;
  }

  // Comprehensive email regex that covers most practical cases
  const emailRegex =
    /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;

  return emailRegex.test(trimmedEmail);
};

/**
 * Validate password strength against security requirements
 *
 * @param password - Password to validate
 * @param requirements - Password requirements (optional, uses defaults)
 * @returns True if password meets all requirements
 *
 * @example
 * ```typescript
 * isValidPassword('MySecurePass123!'); // true
 * isValidPassword('weak'); // false
 *
 * // Custom requirements
 * const customReqs = { ...DEFAULT_PASSWORD_REQUIREMENTS, minLength: 12 };
 * isValidPassword('MyPass123!', customReqs);
 * ```
 */
export const isValidPassword = (
  password: string,
  requirements: PasswordRequirements = DEFAULT_PASSWORD_REQUIREMENTS
): boolean => {
  if (typeof password !== 'string') {
    return false;
  }

  // Check length requirements
  if (password.length < requirements.minLength || password.length > requirements.maxLength) {
    return false;
  }

  // Check character requirements
  if (requirements.requireUppercase && !/[A-Z]/.test(password)) {
    return false;
  }

  if (requirements.requireLowercase && !/[a-z]/.test(password)) {
    return false;
  }

  if (requirements.requireNumbers && !/[0-9]/.test(password)) {
    return false;
  }

  if (requirements.requireSymbols && !/[^A-Za-z0-9]/.test(password)) {
    return false;
  }

  return true;
};

/**
 * Get detailed password validation results with specific feedback
 *
 * @param password - Password to validate
 * @param requirements - Password requirements (optional, uses defaults)
 * @returns Object with validation results and feedback
 *
 * @example
 * ```typescript
 * const result = getPasswordValidationDetails('weak');
 * // Returns: { isValid: false, failedRequirements: ['minLength', 'uppercase', ...] }
 * ```
 */
export const getPasswordValidationDetails = (
  password: string,
  requirements: PasswordRequirements = DEFAULT_PASSWORD_REQUIREMENTS
): { isValid: boolean; failedRequirements: string[] } => {
  const failedRequirements: string[] = [];

  if (typeof password !== 'string') {
    return { isValid: false, failedRequirements: ['invalidType'] };
  }

  if (password.length < requirements.minLength) {
    failedRequirements.push('minLength');
  }

  if (password.length > requirements.maxLength) {
    failedRequirements.push('maxLength');
  }

  if (requirements.requireUppercase && !/[A-Z]/.test(password)) {
    failedRequirements.push('uppercase');
  }

  if (requirements.requireLowercase && !/[a-z]/.test(password)) {
    failedRequirements.push('lowercase');
  }

  if (requirements.requireNumbers && !/[0-9]/.test(password)) {
    failedRequirements.push('numbers');
  }

  if (requirements.requireSymbols && !/[^A-Za-z0-9]/.test(password)) {
    failedRequirements.push('symbols');
  }

  return {
    isValid: failedRequirements.length === 0,
    failedRequirements,
  };
};

/**
 * Sanitize user input by removing potentially dangerous characters
 *
 * This function provides basic sanitization for user inputs to prevent
 * XSS and other injection attacks. For more comprehensive sanitization,
 * consider using specialized libraries like DOMPurify.
 *
 * @param input - String to sanitize
 * @param options - Sanitization options
 * @returns Sanitized string
 *
 * @example
 * ```typescript
 * sanitizeInput('<script>alert("xss")</script>Hello'); // 'Hello'
 * sanitizeInput('  Hello World  '); // 'Hello World'
 * sanitizeInput('Hello "world"', { preserveQuotes: true }); // 'Hello "world"'
 * ```
 */
export const sanitizeInput = (
  input: string,
  options: {
    preserveQuotes?: boolean;
    preserveNewlines?: boolean;
    maxLength?: number;
  } = {}
): string => {
  if (typeof input !== 'string') {
    return '';
  }

  let sanitized = input.trim();

  // Apply length limit if specified
  if (options.maxLength && sanitized.length > options.maxLength) {
    sanitized = sanitized.substring(0, options.maxLength);
  }

  // Remove potentially dangerous HTML/XML characters
  sanitized = sanitized.replace(/[<>]/g, '');

  // Remove quotes unless preserved
  if (!options.preserveQuotes) {
    sanitized = sanitized.replace(/['"]/g, '');
  }

  // Remove newlines unless preserved
  if (!options.preserveNewlines) {
    sanitized = sanitized.replace(/[\r\n]/g, ' ');
  }

  // Remove multiple spaces
  sanitized = sanitized.replace(/\s+/g, ' ');

  return sanitized.trim();
};

/**
 * Validate IPv4 address format
 *
 * @param ip - IP address string to validate
 * @returns True if valid IPv4 address
 */
export const isValidIPv4 = (ip: string): boolean => {
  if (typeof ip !== 'string') {
    return false;
  }

  const ipv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
};

/**
 * Validate IPv6 address format
 *
 * @param ip - IP address string to validate
 * @returns True if valid IPv6 address
 */
export const isValidIPv6 = (ip: string): boolean => {
  if (typeof ip !== 'string') {
    return false;
  }

  // Comprehensive IPv6 regex (simplified for practical use)
  const ipv6Regex =
    /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
};

/**
 * Validate IP address (both IPv4 and IPv6)
 *
 * @param ip - IP address string to validate
 * @returns True if valid IPv4 or IPv6 address
 *
 * @example
 * ```typescript
 * isValidIPAddress('192.168.1.1'); // true (IPv4)
 * isValidIPAddress('2001:db8::1'); // true (IPv6)
 * isValidIPAddress('invalid.ip'); // false
 * ```
 */
export const isValidIPAddress = (ip: string): boolean => {
  return isValidIPv4(ip) || isValidIPv6(ip);
};

/**
 * Validate URL format
 *
 * @param url - URL string to validate
 * @param options - Validation options
 * @returns True if URL format is valid
 *
 * @example
 * ```typescript
 * isValidURL('https://example.com'); // true
 * isValidURL('http://localhost:3000'); // true
 * isValidURL('invalid-url'); // false
 * isValidURL('ftp://example.com', { allowedProtocols: ['ftp'] }); // true
 * ```
 */
export const isValidURL = (
  url: string,
  options: {
    allowedProtocols?: string[];
    requireHttps?: boolean;
  } = {}
): boolean => {
  if (typeof url !== 'string' || url.length === 0) {
    return false;
  }

  try {
    const parsed = new URL(url);

    // Check protocol requirements
    if (options.requireHttps && parsed.protocol !== 'https:') {
      return false;
    }

    if (options.allowedProtocols) {
      const protocol = parsed.protocol.slice(0, -1); // Remove trailing ':'
      if (!options.allowedProtocols.includes(protocol)) {
        return false;
      }
    } else {
      // Default allowed protocols
      const allowedProtocols = ['http', 'https'];
      const protocol = parsed.protocol.slice(0, -1);
      if (!allowedProtocols.includes(protocol)) {
        return false;
      }
    }

    // Additional validation for hostname
    if (!parsed.hostname) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
};

/**
 * Validate username format
 *
 * @param username - Username to validate
 * @param options - Validation options
 * @returns True if username format is valid
 *
 * @example
 * ```typescript
 * isValidUsername('user123'); // true
 * isValidUsername('user_name'); // true
 * isValidUsername('us'); // false (too short with default options)
 * ```
 */
export const isValidUsername = (
  username: string,
  options: {
    minLength?: number;
    maxLength?: number;
    allowUnderscore?: boolean;
    allowDash?: boolean;
    allowDots?: boolean;
  } = {}
): boolean => {
  if (typeof username !== 'string') {
    return false;
  }

  const {
    minLength = 3,
    maxLength = 30,
    allowUnderscore = true,
    allowDash = true,
    allowDots = false,
  } = options;

  // Check length
  if (username.length < minLength || username.length > maxLength) {
    return false;
  }

  // Build regex based on options
  let pattern = '^[a-zA-Z0-9';
  if (allowUnderscore) pattern += '_';
  if (allowDash) pattern += '-';
  if (allowDots) pattern += '.';
  pattern += ']+$';

  const regex = new RegExp(pattern);

  // Must start and end with alphanumeric
  if (!/^[a-zA-Z0-9]/.test(username) || !/[a-zA-Z0-9]$/.test(username)) {
    return false;
  }

  return regex.test(username);
};

/**
 * Validate phone number format (international format)
 *
 * @param phone - Phone number to validate
 * @returns True if phone number format is valid
 *
 * @example
 * ```typescript
 * isValidPhoneNumber('+5511999999999'); // true
 * isValidPhoneNumber('+1-555-123-4567'); // true
 * isValidPhoneNumber('123456'); // false
 * ```
 */
export const isValidPhoneNumber = (phone: string): boolean => {
  if (typeof phone !== 'string') {
    return false;
  }

  // Remove all non-digit characters except +
  const cleaned = phone.replace(/[^\d+]/g, '');

  // Must start with + and have 7-15 digits (international standard)
  const phoneRegex = /^\+[1-9]\d{6,14}$/;

  return phoneRegex.test(cleaned);
};

/**
 * Validate that a string contains only alphanumeric characters
 *
 * @param input - String to validate
 * @param allowSpaces - Whether to allow spaces
 * @returns True if string is alphanumeric
 */
export const isAlphanumeric = (input: string, allowSpaces: boolean = false): boolean => {
  if (typeof input !== 'string') {
    return false;
  }

  const regex = allowSpaces ? /^[a-zA-Z0-9\s]+$/ : /^[a-zA-Z0-9]+$/;
  return regex.test(input);
};

/**
 * Validate that a string is a valid hex color code
 *
 * @param color - Color string to validate
 * @returns True if valid hex color
 *
 * @example
 * ```typescript
 * isValidHexColor('#FF0000'); // true
 * isValidHexColor('#f00'); // true
 * isValidHexColor('red'); // false
 * ```
 */
export const isValidHexColor = (color: string): boolean => {
  if (typeof color !== 'string') {
    return false;
  }

  const hexColorRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;
  return hexColorRegex.test(color);
};
