/**
 * Cryptographic utility functions for secure operations
 *
 * This module provides secure cryptographic functions using Node.js built-in crypto module.
 * All functions follow security best practices and are designed to be safe against
 * timing attacks and other cryptographic vulnerabilities.
 *
 * @packageDocumentation
 */

import crypto from 'node:crypto';

/**
 * Generate a secure random token using cryptographically secure random bytes
 *
 * @param length - Length in bytes for the random token (default: 32)
 * @returns Hex-encoded secure random token
 *
 * @example
 * ```typescript
 * const token = generateSecureToken(32); // 64-character hex string
 * const shortToken = generateSecureToken(16); // 32-character hex string
 * ```
 */
export const generateSecureToken = (length: number = 32): string => {
  if (length <= 0 || length > 1024) {
    throw new Error('Token length must be between 1 and 1024 bytes');
  }

  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate a secure secret using cryptographically secure random bytes
 *
 * This function is designed for generating secrets like JWT signing keys,
 * API keys, and other sensitive tokens that need to be URL-safe.
 *
 * @param length - Length in bytes for the random secret (default: 64)
 * @returns Base64URL-encoded secure random secret
 *
 * @example
 * ```typescript
 * const jwtSecret = generateSecureSecret(64); // URL-safe secret for JWT
 * const apiKey = generateSecureSecret(32); // Shorter API key
 * ```
 */
export const generateSecureSecret = (length: number = 64): string => {
  if (length <= 0 || length > 1024) {
    throw new Error('Secret length must be between 1 and 1024 bytes');
  }

  return crypto.randomBytes(length).toString('base64url');
};

/**
 * Create SHA-256 hash of input string
 *
 * This function creates a SHA-256 hash, which is suitable for non-password
 * hashing use cases like creating content fingerprints, checksums, or
 * deterministic IDs.
 *
 * @param input - String to hash
 * @returns Hex-encoded SHA-256 hash
 *
 * @example
 * ```typescript
 * const hash = hashSHA256('Hello World');
 * // Returns: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
 *
 * const fileHash = hashSHA256(fileContent);
 * ```
 *
 * @security
 * Do NOT use this function for password hashing. Use bcrypt or similar
 * password-specific hashing functions instead.
 */
export const hashSHA256 = (input: string): string => {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
};

/**
 * Perform constant-time string comparison to prevent timing attacks
 *
 * This function compares two strings in constant time, making it safe
 * for comparing sensitive values like tokens, hashes, or secrets without
 * leaking information through timing side-channels.
 *
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal, false otherwise
 *
 * @example
 * ```typescript
 * const storedToken = 'abc123';
 * const providedToken = 'abc123';
 * const isValid = constantTimeCompare(storedToken, providedToken); // true
 *
 * // Safe for comparing sensitive values
 * const isPasswordValid = constantTimeCompare(hashedPassword, storedHash);
 * ```
 *
 * @security
 * This function prevents timing attacks by ensuring comparison time
 * is constant regardless of where the strings differ.
 */
export const constantTimeCompare = (a: string, b: string): boolean => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    throw new Error('Both inputs must be strings');
  }

  // Early return for length mismatch (this is safe to leak)
  if (a.length !== b.length) {
    return false;
  }

  // Use Node.js built-in constant-time comparison
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    // Handle any Buffer creation errors
    return false;
  }
};

/**
 * Generate a cryptographically secure random UUID v4
 *
 * @returns UUID v4 string
 *
 * @example
 * ```typescript
 * const id = generateSecureUUID();
 * // Returns: 123e4567-e89b-12d3-a456-426614174000
 * ```
 */
export const generateSecureUUID = (): string => {
  return crypto.randomUUID();
};

/**
 * Generate secure random bytes for custom encoding needs
 *
 * @param length - Number of bytes to generate
 * @returns Buffer containing secure random bytes
 *
 * @example
 * ```typescript
 * const randomBytes = generateSecureBytes(32);
 * const customEncoded = randomBytes.toString('base64');
 * ```
 */
export const generateSecureBytes = (length: number): Buffer => {
  if (length <= 0 || length > 1024) {
    throw new Error('Byte length must be between 1 and 1024');
  }

  return crypto.randomBytes(length);
};

/**
 * Create HMAC signature using SHA-256
 *
 * @param data - Data to sign
 * @param secret - Secret key for HMAC
 * @returns Hex-encoded HMAC signature
 *
 * @example
 * ```typescript
 * const signature = createHMACSignature('data', 'secret');
 * const isValid = constantTimeCompare(signature, expectedSignature);
 * ```
 */
export const createHMACSignature = (data: string, secret: string): string => {
  if (typeof data !== 'string' || typeof secret !== 'string') {
    throw new Error('Both data and secret must be strings');
  }

  return crypto.createHmac('sha256', secret).update(data, 'utf8').digest('hex');
};

/**
 * Verify HMAC signature in constant time
 *
 * @param data - Original data
 * @param signature - Signature to verify
 * @param secret - Secret key used for signing
 * @returns True if signature is valid
 *
 * @example
 * ```typescript
 * const isValid = verifyHMACSignature('data', signature, 'secret');
 * ```
 */
export const verifyHMACSignature = (data: string, signature: string, secret: string): boolean => {
  try {
    const expectedSignature = createHMACSignature(data, secret);
    return constantTimeCompare(signature, expectedSignature);
  } catch {
    return false;
  }
};
