/**
 * JWT Manager Tests
 * 
 * Comprehensive tests for JwtManager class covering token generation,
 * validation, refresh functionality, and error handling scenarios.
 */

// Mock the utils module to avoid shared package dependency issues in tests
jest.mock('../../src/utils', () => ({
  createChildLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
  auditLog: jest.fn(),
  logSecurityError: jest.fn(),
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
  createSecurityError: jest.fn((code, message, details) => {
    const error = new Error(message);
    (error as any).code = code;
    (error as any).details = details;
    return error;
  }),
}));

// Mock crypto utilities
jest.mock('../../src/utils/crypto', () => ({
  generateSecureSecret: jest.fn(() => 'mocked-secure-secret-123456789012345678901234567890'),
  generateSecureUUID: jest.fn(() => 'mocked-uuid-1234-5678-9012-123456789012'),
}));

import { JwtManager } from '../../src/auth/jwt';
import { AuthenticationError } from '../../src/types/errors.types';
import type { JwtManagerConfig } from '../../src/auth/types';

describe('JwtManager', () => {
  let jwtManager: JwtManager;
  const testConfig: JwtManagerConfig = {
    secret: 'test-secret-key-min-32-characters-long',
    expiresIn: '15m',
    refreshExpiresIn: '7d',
    algorithm: 'HS256' as const,
    issuer: 'test-issuer',
    audience: 'test-audience',
    clockTolerance: 30,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jwtManager = new JwtManager(testConfig);
  });

  describe('constructor and configuration validation', () => {
    it('should initialize JWT Manager with valid configuration', () => {
      expect(() => new JwtManager(testConfig)).not.toThrow();
    });

    it('should reject configuration without secret', () => {
      const invalidConfig = { ...testConfig, secret: '' };
      expect(() => new JwtManager(invalidConfig)).toThrow();
    });

    it('should reject configuration with short secret', () => {
      const invalidConfig = { ...testConfig, secret: 'too-short' };
      expect(() => new JwtManager(invalidConfig)).toThrow();
    });

    it('should reject configuration without expiresIn', () => {
      const invalidConfig = { ...testConfig, expiresIn: '' as any };
      expect(() => new JwtManager(invalidConfig)).toThrow();
    });

    it('should reject configuration without refreshExpiresIn', () => {
      const invalidConfig = { ...testConfig, refreshExpiresIn: '' as any };
      expect(() => new JwtManager(invalidConfig)).toThrow();
    });

    it('should reject unsupported algorithm', () => {
      const invalidConfig = { ...testConfig, algorithm: 'INVALID' as any };
      expect(() => new JwtManager(invalidConfig)).toThrow();
    });
  });

  describe('token generation', () => {
    it('should generate valid access and refresh tokens', async () => {
      const options = {
        userId: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        roles: ['user'],
        permissions: ['user:read'],
      };

      const tokens = await jwtManager.generateTokens(options);

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(tokens.tokenType).toBe('Bearer');
      expect(tokens.expiresAt).toBeInstanceOf(Date);
      expect(tokens.refreshExpiresAt).toBeInstanceOf(Date);
      expect(tokens.expiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(tokens.refreshExpiresAt!.getTime()).toBeGreaterThan(Date.now());
      expect(tokens.scope).toEqual(['user:read']);
    });

    it('should include correct payload in access token', async () => {
      const options = {
        userId: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        roles: ['user'],
        permissions: ['user:read'],
      };

      const tokens = await jwtManager.generateTokens(options);
      const decodedPayload = jwtManager.verifyAccessToken(tokens.accessToken);

      expect(decodedPayload.sub).toBe(options.userId);
      expect(decodedPayload.email).toBe(options.email);
      expect(decodedPayload.name).toBe(options.name);
      expect(decodedPayload.roles).toEqual(options.roles);
      expect(decodedPayload.permissions).toEqual(options.permissions);
      expect(decodedPayload.iat).toBeDefined();
      expect(decodedPayload.exp).toBeDefined();
      expect(decodedPayload.tokenType).toBe('access');
    });

    it('should generate tokens with minimal payload', async () => {
      const options = {
        userId: 'user456',
      };

      const tokens = await jwtManager.generateTokens(options);
      const decodedPayload = jwtManager.verifyAccessToken(tokens.accessToken);

      expect(decodedPayload.sub).toBe('user456');
      expect(decodedPayload.email).toBeUndefined();
      expect(decodedPayload.roles).toBeUndefined();
      expect(decodedPayload.permissions).toBeUndefined();
    });

    it('should generate tokens with custom expiration times', () => {
      const customConfig = {
        ...testConfig,
        expiresIn: '1h',
        refreshExpiresIn: '30d',
      };
      const customManager = new JwtManager(customConfig);

      const options = {
        userId: 'user789',
      };

      return expect(customManager.generateTokens(options)).resolves.toBeDefined();
    });
  });

  describe('token validation', () => {
    it('should validate valid access tokens', async () => {
      const options = {
        userId: 'user123',
        roles: ['user'],
        permissions: ['user:read'],
      };

      const tokens = await jwtManager.generateTokens(options);
      const decodedPayload = jwtManager.verifyAccessToken(tokens.accessToken);

      expect(decodedPayload.sub).toBe('user123');
      expect(decodedPayload.tokenType).toBe('access');
    });

    it('should reject invalid tokens', () => {
      expect(() => {
        jwtManager.verifyAccessToken('invalid-token');
      }).toThrow(AuthenticationError);
    });

    it('should reject tokens with wrong signature', async () => {
      const otherManager = new JwtManager({
        ...testConfig,
        secret: 'different-secret-key-min-32-characters',
      });

      const tokens = await otherManager.generateTokens({ userId: 'user123' });

      expect(() => {
        jwtManager.verifyAccessToken(tokens.accessToken);
      }).toThrow(AuthenticationError);
    });

    it('should reject malformed tokens', () => {
      expect(() => {
        jwtManager.verifyAccessToken('malformed.token');
      }).toThrow(AuthenticationError);
    });

    it('should reject empty tokens', () => {
      expect(() => {
        jwtManager.verifyAccessToken('');
      }).toThrow(AuthenticationError);
    });

    it('should provide detailed error information for invalid tokens', () => {
      try {
        jwtManager.verifyAccessToken('invalid-token');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(AuthenticationError);
        expect((error as any).message).toContain('Invalid token');
      }
    });
  });

  describe('refresh tokens', () => {
    it('should validate refresh tokens', async () => {
      const tokens = await jwtManager.generateTokens({ userId: 'user123' });
      const refreshPayload = jwtManager.verifyRefreshToken(tokens.refreshToken);

      expect(refreshPayload.sub).toBe('user123');
      expect(refreshPayload.type).toBe('refresh');
    });

    it('should reject access token as refresh token', async () => {
      const tokens = await jwtManager.generateTokens({ userId: 'user123' });

      expect(() => {
        jwtManager.verifyRefreshToken(tokens.accessToken);
      }).toThrow(AuthenticationError);
    });

    it('should refresh tokens with new payload', async () => {
      const originalTokens = await jwtManager.generateTokens({ 
        userId: 'user123',
        roles: ['user'] 
      });

      const newTokens = jwtManager.refreshTokens(originalTokens.refreshToken, {
        sub: 'user123',
        roles: ['user', 'admin'],
        permissions: ['user:read', 'admin:all'],
      });

      const newPayload = jwtManager.verifyAccessToken(newTokens.accessToken);
      expect(newPayload.roles).toContain('admin');
      expect(newPayload.permissions).toContain('admin:all');
    });

    it('should reject invalid refresh token for refreshing', () => {
      expect(() => {
        jwtManager.refreshTokens('invalid-refresh-token', {
          sub: 'user123',
        });
      }).toThrow(AuthenticationError);
    });

    it('should reject access token for refreshing', async () => {
      const tokens = await jwtManager.generateTokens({ userId: 'user123' });

      expect(() => {
        jwtManager.refreshTokens(tokens.accessToken, {
          sub: 'user123',
        });
      }).toThrow(AuthenticationError);
    });
  });

  describe('token validation with security context', () => {
    const mockContext = {
      sessionId: 'session123',
      ipAddress: '127.0.0.1',
      timestamp: new Date(),
      userAgent: 'test-agent',
    };

    it('should validate tokens with security context', async () => {
      const tokens = await jwtManager.generateTokens({ userId: 'user123' });
      const result = await jwtManager.validateToken(tokens.accessToken, mockContext);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.payload!.sub).toBe('user123');
      expect(result.context).toBe(mockContext);
    });

    it('should return error details for invalid tokens with context', async () => {
      const result = await jwtManager.validateToken('invalid-token', mockContext);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('JWT_VALIDATION_FAILED');
      expect(result.error!.type).toBe('malformed');
      expect(result.context).toBe(mockContext);
    });

    it('should refresh tokens with security context', async () => {
      const tokens = await jwtManager.generateTokens({ userId: 'user123' });
      const result = await jwtManager.refreshTokensWithContext(tokens.refreshToken, mockContext);

      expect(result.success).toBe(true);
      expect(result.tokens).toBeDefined();
      expect(result.tokens!.accessToken).toBeDefined();
      expect(result.tokens!.refreshToken).toBeDefined();
    });

    it('should handle refresh token failure with context', async () => {
      const result = await jwtManager.refreshTokensWithContext('invalid-refresh', mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.tokens).toBeUndefined();
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle token with invalid issuer', () => {
      const configWithIssuer = { ...testConfig, issuer: 'valid-issuer' };
      const managerWithIssuer = new JwtManager(configWithIssuer);
      
      const configWithDifferentIssuer = { ...testConfig, issuer: 'different-issuer' };
      const managerWithDifferentIssuer = new JwtManager(configWithDifferentIssuer);

      return managerWithDifferentIssuer.generateTokens({ userId: 'user123' }).then(tokens => {
        expect(() => {
          managerWithIssuer.verifyAccessToken(tokens.accessToken);
        }).toThrow(AuthenticationError);
      });
    });

    it('should handle token with invalid audience', () => {
      const configWithAudience = { ...testConfig, audience: 'valid-audience' };
      const managerWithAudience = new JwtManager(configWithAudience);
      
      const configWithDifferentAudience = { ...testConfig, audience: 'different-audience' };
      const managerWithDifferentAudience = new JwtManager(configWithDifferentAudience);

      return managerWithDifferentAudience.generateTokens({ userId: 'user123' }).then(tokens => {
        expect(() => {
          managerWithAudience.verifyAccessToken(tokens.accessToken);
        }).toThrow(AuthenticationError);
      });
    });

    it('should handle token generation errors gracefully', async () => {
      // Mock jwt.sign to throw an error
      const originalSign = require('jsonwebtoken').sign;
      require('jsonwebtoken').sign = jest.fn(() => {
        throw new Error('Signing failed');
      });

      await expect(jwtManager.generateTokens({ userId: 'user123' }))
        .rejects
        .toThrow();

      // Restore original function
      require('jsonwebtoken').sign = originalSign;
    });
  });

  describe('configuration edge cases', () => {
    it('should handle different expiration formats', () => {
      const configs = [
        { ...testConfig, expiresIn: '30s' },
        { ...testConfig, expiresIn: '5m' },
        { ...testConfig, expiresIn: '2h' },
        { ...testConfig, expiresIn: '1d' },
      ];

      configs.forEach(config => {
        expect(() => new JwtManager(config)).not.toThrow();
      });
    });

    it('should reject invalid expiration formats', () => {
      const invalidConfigs = [
        { ...testConfig, expiresIn: '30x' },
        { ...testConfig, expiresIn: 'invalid' },
        { ...testConfig, expiresIn: '30' },
      ];

      invalidConfigs.forEach(config => {
        const manager = new JwtManager(config);
        expect(() => manager.generateTokens({ userId: 'user123' }))
          .rejects
          .toThrow();
      });
    });

    it('should handle different algorithms', () => {
      const algorithms: Array<'HS256' | 'HS384' | 'HS512'> = ['HS256', 'HS384', 'HS512'];

      algorithms.forEach(algorithm => {
        const config = { ...testConfig, algorithm };
        expect(() => new JwtManager(config)).not.toThrow();
      });
    });

    it('should calculate expiration times correctly', async () => {
      const manager = new JwtManager({
        ...testConfig,
        expiresIn: '1h',
      });

      const tokens = await manager.generateTokens({ userId: 'user123' });
      const payload = manager.verifyAccessToken(tokens.accessToken);
      
      // Should expire in approximately 1 hour
      const expectedExpiry = Math.floor(Date.now() / 1000) + 3600;
      expect(payload.exp).toBeCloseTo(expectedExpiry, -2); // Allow 100s tolerance
    });
  });

  describe('static methods', () => {
    it('should generate secure secret', () => {
      const secret = JwtManager.generateSecret();
      
      expect(secret).toBeDefined();
      expect(typeof secret).toBe('string');
      expect(secret.length).toBeGreaterThan(32);
    });

    it('should generate secret with custom length', () => {
      const secret = JwtManager.generateSecret(128);
      
      expect(secret).toBeDefined();
      expect(typeof secret).toBe('string');
    });
  });
});