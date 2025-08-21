import {
  AuthenticationError,
  AuthorizationError,
  PasswordPolicyError,
  RateLimitError,
  SecurityError,
} from '../../src/types/errors.types';

describe('SecurityError Classes', () => {
  describe('SecurityError (Abstract Base)', () => {
    // Create a concrete implementation for testing
    class TestSecurityError extends SecurityError {
      readonly code = 'TEST_ERROR';
      readonly statusCode = 500;
      readonly severity = 'medium' as const;
    }

    it('should create error with message', () => {
      const error = new TestSecurityError('Test error message');

      expect(error.message).toBe('Test error message');
      expect(error.code).toBe('TEST_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.timestamp).toBeInstanceOf(Date);
      expect(error.name).toBe('TestSecurityError');
    });

    it('should create error with context', () => {
      const context = {
        userId: '123',
        sessionId: 'session-123',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { action: 'test' },
      };
      const error = new TestSecurityError('Test error', context);

      expect(error.context).toEqual(context);
    });

    it('should have stack trace', () => {
      const error = new TestSecurityError('Test error');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('TestSecurityError');
    });

    it('should be instance of Error', () => {
      const error = new TestSecurityError('Test error');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(SecurityError);
    });
  });

  describe('AuthenticationError', () => {
    it('should have correct properties', () => {
      const error = new AuthenticationError('Invalid credentials');

      expect(error.code).toBe('AUTH_ERROR');
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Invalid credentials');
      expect(error).toBeInstanceOf(SecurityError);
      expect(error).toBeInstanceOf(AuthenticationError);
    });

    it('should accept context', () => {
      const context = {
        userId: 'user123',
        sessionId: 'session-123',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { attempt: 3 },
      };
      const error = new AuthenticationError('Max attempts exceeded', context);

      expect(error.context).toEqual(context);
    });
  });

  describe('AuthorizationError', () => {
    it('should have correct properties', () => {
      const error = new AuthorizationError('Insufficient permissions');

      expect(error.code).toBe('AUTHZ_ERROR');
      expect(error.statusCode).toBe(403);
      expect(error.message).toBe('Insufficient permissions');
      expect(error).toBeInstanceOf(SecurityError);
      expect(error).toBeInstanceOf(AuthorizationError);
    });

    it('should accept context', () => {
      const context = {
        sessionId: 'session-123',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { requiredPermission: 'admin:delete', userRole: 'user' },
      };
      const error = new AuthorizationError('Access denied', context);

      expect(error.context).toEqual(context);
    });
  });

  describe('RateLimitError', () => {
    it('should have correct properties', () => {
      const error = new RateLimitError('Rate limit exceeded');

      expect(error.code).toBe('RATE_LIMIT_ERROR');
      expect(error.statusCode).toBe(429);
      expect(error.message).toBe('Rate limit exceeded');
      expect(error).toBeInstanceOf(SecurityError);
      expect(error).toBeInstanceOf(RateLimitError);
    });

    it('should accept context', () => {
      const context = {
        sessionId: 'session-123',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: { limit: 100, current: 150, windowMs: 60000 },
      };
      const error = new RateLimitError('Too many requests', context);

      expect(error.context).toEqual(context);
    });
  });

  describe('PasswordPolicyError', () => {
    it('should have correct properties', () => {
      const error = new PasswordPolicyError('Password too weak');

      expect(error.code).toBe('PASSWORD_POLICY_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Password too weak');
      expect(error).toBeInstanceOf(SecurityError);
      expect(error).toBeInstanceOf(PasswordPolicyError);
    });

    it('should accept context', () => {
      const context = {
        sessionId: 'session-123',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        metadata: {
          violations: ['minLength', 'requireNumbers'],
          minLength: 8,
          actualLength: 6,
        },
      };
      const error = new PasswordPolicyError('Password validation failed', context);

      expect(error.context).toEqual(context);
    });
  });

  describe('Error Hierarchy', () => {
    it('should maintain proper inheritance chain', () => {
      const authError = new AuthenticationError('Auth failed');
      const authzError = new AuthorizationError('Access denied');
      const rateError = new RateLimitError('Rate limited');
      const passError = new PasswordPolicyError('Weak password');

      // All should be instances of base classes
      expect(authError).toBeInstanceOf(Error);
      expect(authError).toBeInstanceOf(SecurityError);

      expect(authzError).toBeInstanceOf(Error);
      expect(authzError).toBeInstanceOf(SecurityError);

      expect(rateError).toBeInstanceOf(Error);
      expect(rateError).toBeInstanceOf(SecurityError);

      expect(passError).toBeInstanceOf(Error);
      expect(passError).toBeInstanceOf(SecurityError);

      // But not instances of each other
      expect(authError).not.toBeInstanceOf(AuthorizationError);
      expect(authzError).not.toBeInstanceOf(AuthenticationError);
      expect(rateError).not.toBeInstanceOf(PasswordPolicyError);
      expect(passError).not.toBeInstanceOf(RateLimitError);
    });

    it('should have unique error codes', () => {
      const errors = [
        new AuthenticationError('test'),
        new AuthorizationError('test'),
        new RateLimitError('test'),
        new PasswordPolicyError('test'),
      ];

      const codes = errors.map((e) => e.code);
      const uniqueCodes = [...new Set(codes)];

      expect(uniqueCodes).toHaveLength(codes.length);
    });

    it('should have appropriate HTTP status codes', () => {
      expect(new AuthenticationError('test').statusCode).toBe(401);
      expect(new AuthorizationError('test').statusCode).toBe(403);
      expect(new RateLimitError('test').statusCode).toBe(429);
      expect(new PasswordPolicyError('test').statusCode).toBe(400);
    });
  });

  describe('Timestamp Behavior', () => {
    it('should set timestamp on creation', () => {
      const before = new Date();
      const error = new AuthenticationError('test');
      const after = new Date();

      expect(error.timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(error.timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should have different timestamps for different error instances', async () => {
      const error1 = new AuthenticationError('test');

      // Wait a small amount to ensure different timestamps
      await new Promise((resolve) => setTimeout(resolve, 5));

      const error2 = new AuthenticationError('test');

      expect(error1.timestamp.getTime()).not.toBe(error2.timestamp.getTime());
    });
  });
});
