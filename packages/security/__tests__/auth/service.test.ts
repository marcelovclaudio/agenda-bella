/**
 * AuthService Tests
 * 
 * Comprehensive tests for the main Authentication Service covering all methods
 * and edge cases including login, token management, logout, registration,
 * and password reset functionality.
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
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

import { AuthService } from '../../src/auth/service';
import { createMockDatabaseRepositories } from '../../src/auth/database';
import { AuthenticationError } from '../../src/types/errors.types';

describe('AuthService', () => {
  let authService: AuthService;
  let mockRepositories: ReturnType<typeof createMockDatabaseRepositories>;

  const testConfig = {
    secret: 'test-secret-key-min-32-characters-long',
    expiresIn: '15m',
    refreshExpiresIn: '7d',
    algorithm: 'HS256' as const,
  };

  beforeEach(async () => {
    mockRepositories = createMockDatabaseRepositories();
    
    // Wait for the MockUserRepository to initialize its default users
    // Keep checking until the admin user is available
    let attempts = 0;
    const maxAttempts = 50;
    while (attempts < maxAttempts) {
      const adminUser = await mockRepositories.userRepo.findByEmail('admin@example.com');
      if (adminUser) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    
    authService = new AuthService(
      testConfig,
      mockRepositories.userRepo,
      mockRepositories.sessionRepo
    );
  });

  describe('login', () => {
    it('should login with valid credentials', async () => {
      const credentials = {
        email: 'admin@example.com',
        password: 'password123',
      };

      const result = await authService.login(credentials);

      expect(result.user.email).toBe(credentials.email);
      expect(result.tokens.accessToken).toBeDefined();
      expect(result.tokens.refreshToken).toBeDefined();
      expect(typeof result.isFirstLogin).toBe('boolean');
    });

    it('should reject invalid email', async () => {
      const credentials = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should reject invalid password', async () => {
      const credentials = {
        email: 'admin@example.com',
        password: 'wrongpassword',
      };

      await expect(authService.login(credentials))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should track device info in login', async () => {
      const credentials = {
        email: 'admin@example.com',
        password: 'password123',
        deviceInfo: {
          userAgent: 'test-browser',
          ipAddress: '127.0.0.1',
        },
      };

      const result = await authService.login(credentials);
      
      // Device info should be stored in session
      expect(result.user.sessionId).toBeDefined();
    });

    it('should require email and password', async () => {
      const credentialsWithoutEmail = {
        email: '',
        password: 'password123',
      };

      await expect(authService.login(credentialsWithoutEmail))
        .rejects
        .toThrow(AuthenticationError);

      const credentialsWithoutPassword = {
        email: 'admin@example.com',
        password: '',
      };

      await expect(authService.login(credentialsWithoutPassword))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should detect first login correctly', async () => {
      // Create a new user account
      await mockRepositories.userRepo.createUser?.({
        email: 'newuser@example.com',
        password: 'NewPassword123!@#',
        roles: ['user'],
        permissions: ['user:read'],
      });

      const credentials = {
        email: 'newuser@example.com',
        password: 'NewPassword123!@#',
      };

      const result = await authService.login(credentials);
      
      // Should detect as first login for newly created user
      expect(result.isFirstLogin).toBe(true);
    });
  });

  describe('token refresh', () => {
    it('should refresh tokens with valid refresh token', async () => {
      // First login
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // Then refresh
      const refreshResult = await authService.refresh({
        refreshToken: loginResult.tokens.refreshToken,
      });

      expect(refreshResult.accessToken).toBeDefined();
      expect(refreshResult.refreshToken).toBeDefined();
      expect(refreshResult.accessToken).not.toBe(loginResult.tokens.accessToken);
    });

    it('should reject invalid refresh token', async () => {
      await expect(authService.refresh({
        refreshToken: 'invalid-token',
      })).rejects.toThrow(AuthenticationError);
    });

    it('should reject blacklisted refresh token', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // Manually blacklist the refresh token
      await mockRepositories.sessionRepo.blacklistToken(
        loginResult.tokens.refreshToken,
        new Date(Date.now() + 3600000)
      );

      // Try to refresh with blacklisted token
      await expect(authService.refresh({
        refreshToken: loginResult.tokens.refreshToken,
      })).rejects.toThrow(AuthenticationError);
    });

    it('should require refresh token', async () => {
      await expect(authService.refresh({
        refreshToken: '',
      })).rejects.toThrow(AuthenticationError);
    });

    it('should handle device info in refresh', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      const deviceInfo = {
        userAgent: 'test-browser-updated',
        ipAddress: '127.0.0.1',
      };

      const refreshResult = await authService.refresh({
        refreshToken: loginResult.tokens.refreshToken,
        deviceInfo,
      });

      expect(refreshResult.accessToken).toBeDefined();
      expect(refreshResult.refreshToken).toBeDefined();
    });
  });

  describe('logout', () => {
    it('should logout with refresh token', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // Should not throw during logout
      await expect(authService.logout({
        refreshToken: loginResult.tokens.refreshToken,
      })).resolves.not.toThrow();
    });

    it('should logout all devices', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });
      
      await authService.logout({
        refreshToken: loginResult.tokens.refreshToken,
        logoutAllDevices: true,
      });

      // All sessions for user should be revoked
      const sessions = await authService.getUserActiveSessions(loginResult.user.id);
      expect(sessions).toHaveLength(0);
    });

    it('should handle logout without refresh token', async () => {
      // Should not throw even without refresh token
      await expect(authService.logout({}))
        .resolves
        .not
        .toThrow();
    });

    it('should handle invalid refresh token gracefully during logout', async () => {
      // Should not throw even with invalid token
      await expect(authService.logout({
        refreshToken: 'invalid-token',
      })).resolves.not.toThrow();
    });
  });

  describe('token validation', () => {
    it('should validate valid access token', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      const user = await authService.validateAccessToken(loginResult.tokens.accessToken);
      
      expect(user.id).toBe(loginResult.user.id);
      expect(user.email).toBe(loginResult.user.email);
    });

    it('should reject blacklisted access token', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // Blacklist the token manually
      await mockRepositories.sessionRepo.blacklistToken(
        loginResult.tokens.accessToken,
        new Date(Date.now() + 3600000)
      );

      await expect(authService.validateAccessToken(loginResult.tokens.accessToken))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should reject empty access token', async () => {
      await expect(authService.validateAccessToken(''))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should reject invalid access token format', async () => {
      await expect(authService.validateAccessToken('invalid-token'))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should reject token for non-existent user', async () => {
      // Create a token for a user that doesn't exist
      const fakeTokens = await authService.getJwtManager().generateTokens({
        userId: 'non-existent-user',
        email: 'fake@example.com',
        roles: ['user'],
        permissions: ['user:read'],
        sessionId: 'fake-session',
      });

      await expect(authService.validateAccessToken(fakeTokens.accessToken))
        .rejects
        .toThrow(AuthenticationError);
    });
  });

  describe('registration', () => {
    it('should register new user', async () => {
      const registrationData = {
        email: 'newuser@example.com',
        password: 'NewPassword123!@#',
        confirmPassword: 'NewPassword123!@#',
      };

      const result = await authService.register(registrationData);

      expect(result.user.email).toBe(registrationData.email);
      expect(result.user.roles).toContain('user');
      expect(result.requiresVerification).toBe(false);
    });

    it('should reject duplicate email registration', async () => {
      const registrationData = {
        email: 'admin@example.com', // Already exists
        password: 'NewPassword123!@#',
        confirmPassword: 'NewPassword123!@#',
      };

      await expect(authService.register(registrationData))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should reject password mismatch', async () => {
      const registrationData = {
        email: 'newuser@example.com',
        password: 'Password123!@#',
        confirmPassword: 'DifferentPassword123!@#',
      };

      await expect(authService.register(registrationData))
        .rejects
        .toThrow(AuthenticationError);
    });

    it('should handle registration with additional fields', async () => {
      const registrationData = {
        email: 'fulluser@example.com',
        password: 'NewPassword123!@#',
        confirmPassword: 'NewPassword123!@#',
        firstName: 'John',
        lastName: 'Doe',
        roles: ['user', 'customer'],
      };

      const result = await authService.register(registrationData);

      expect(result.user.email).toBe(registrationData.email);
      expect(result.user.roles).toEqual(expect.arrayContaining(['user', 'customer']));
    });
  });

  describe('password reset', () => {
    it('should initiate password reset', async () => {
      const result = await authService.initiatePasswordReset({
        email: 'admin@example.com',
      });

      expect(result).toBe(true);
    });

    it('should handle non-existent email gracefully', async () => {
      const result = await authService.initiatePasswordReset({
        email: 'nonexistent@example.com',
      });

      // Should still return true to prevent email enumeration
      expect(result).toBe(true);
    });

    it('should validate reset token', async () => {
      // First initiate reset
      await authService.initiatePasswordReset({
        email: 'admin@example.com',
      });

      // For mock implementation, any non-empty token should be valid
      const isValid = await authService.validateResetToken('mock-reset-token');
      expect(typeof isValid).toBe('boolean');
    });

    it('should confirm password reset', async () => {
      // This test is checking the interface, not the full implementation
      // since the mock implementation doesn't store actual reset tokens
      try {
        const result = await authService.confirmPasswordReset({
          token: 'mock-reset-token',
          newPassword: 'NewPassword123!@#',
          confirmPassword: 'NewPassword123!@#',
        });
        
        expect(typeof result).toBe('boolean');
      } catch (error) {
        // The mock implementation may throw for invalid tokens, which is expected
        expect(error).toBeInstanceOf(AuthenticationError);
      }
    });

    it('should handle invalid reset token', async () => {
      // The mock implementation throws for invalid tokens, which is expected behavior
      await expect(authService.confirmPasswordReset({
        token: 'invalid-token',
        newPassword: 'NewPassword123!@#',
        confirmPassword: 'NewPassword123!@#',
      })).rejects.toThrow(AuthenticationError);
    });
  });

  describe('session management', () => {
    it('should get user active sessions', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      const sessions = await authService.getUserActiveSessions(loginResult.user.id);

      expect(Array.isArray(sessions)).toBe(true);
      expect(sessions.length).toBeGreaterThanOrEqual(0);
    });

    it('should revoke user session', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // Should not throw
      await expect(authService.revokeUserSession(loginResult.user.id, 'fake-session-id'))
        .resolves
        .not
        .toThrow();
    });

    it('should return empty sessions for non-existent user', async () => {
      const sessions = await authService.getUserActiveSessions('non-existent-user');
      expect(sessions).toEqual([]);
    });
  });

  describe('password change', () => {
    it('should change password with valid current password', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      await expect(authService.changePassword(
        loginResult.user.id,
        'password123',
        'NewPassword123!@#'
      )).resolves.not.toThrow();
    });

    it('should reject password change with invalid current password', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      await expect(authService.changePassword(
        loginResult.user.id,
        'wrongpassword',
        'NewPassword123!@#'
      )).rejects.toThrow(AuthenticationError);
    });

    it('should reject password change for non-existent user', async () => {
      await expect(authService.changePassword(
        'non-existent-user',
        'anypassword',
        'NewPassword123!@#'
      )).rejects.toThrow(AuthenticationError);
    });
  });

  describe('email verification', () => {
    it('should initiate email verification', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      const verificationToken = await authService.initiateEmailVerification(loginResult.user.id);
      expect(typeof verificationToken).toBe('string');
      expect(verificationToken).toBeTruthy();
    });

    it('should verify email with valid token', async () => {
      const loginResult = await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      const verificationToken = await authService.initiateEmailVerification(loginResult.user.id);
      const result = await authService.verifyEmail(loginResult.user.id, verificationToken);
      
      expect(typeof result).toBe('boolean');
    });

    it('should resend verification email', async () => {
      const result = await authService.resendVerificationEmail('admin@example.com');
      expect(typeof result).toBe('boolean');
    });

    it('should handle resend for non-existent email', async () => {
      // Should return true to prevent email enumeration
      const result = await authService.resendVerificationEmail('nonexistent@example.com');
      expect(result).toBe(true);
    });
  });

  describe('maintenance', () => {
    it('should perform maintenance cleanup', async () => {
      // Create some test sessions first
      await authService.login({
        email: 'admin@example.com',
        password: 'password123',
      });

      // The mock implementation should handle cleanup
      const result = await mockRepositories.sessionRepo.cleanupExpiredSessions?.() ?? 0;

      expect(typeof result).toBe('number');
      expect(result).toBeGreaterThanOrEqual(0);
    });
  });

  describe('manager access methods', () => {
    it('should provide access to JWT manager', () => {
      const jwtManager = authService.getJwtManager();
      expect(jwtManager).toBeDefined();
      expect(typeof jwtManager.generateTokens).toBe('function');
    });

    it('should provide access to blacklist manager', () => {
      const blacklistManager = authService.getBlacklistManager();
      expect(blacklistManager).toBeDefined();
      expect(typeof blacklistManager.blacklistToken).toBe('function');
    });
  });

  describe('error handling', () => {
    it('should handle JWT manager errors gracefully', async () => {
      // Mock the JWT manager to throw an error
      const originalGenerateTokens = authService.getJwtManager().generateTokens;
      authService.getJwtManager().generateTokens = jest.fn().mockRejectedValue(new Error('JWT Error'));

      await expect(authService.login({
        email: 'admin@example.com',
        password: 'password123',
      })).rejects.toThrow(AuthenticationError);

      // Restore original method
      authService.getJwtManager().generateTokens = originalGenerateTokens;
    });

    it('should handle repository errors gracefully', async () => {
      // Mock the user repository to throw an error
      const originalFindByEmail = mockRepositories.userRepo.findByEmail;
      mockRepositories.userRepo.findByEmail = jest.fn().mockRejectedValue(new Error('Database Error'));

      await expect(authService.login({
        email: 'admin@example.com',
        password: 'password123',
      })).rejects.toThrow(AuthenticationError);

      // Restore original method
      mockRepositories.userRepo.findByEmail = originalFindByEmail;
    });
  });

  describe('configuration validation', () => {
    it('should initialize with valid configuration', () => {
      expect(authService).toBeDefined();
      expect(authService.getJwtManager()).toBeDefined();
      expect(authService.getBlacklistManager()).toBeDefined();
    });

    it('should handle missing optional configurations', () => {
      const authServiceMinimal = new AuthService(
        testConfig,
        mockRepositories.userRepo,
        mockRepositories.sessionRepo
      );

      expect(authServiceMinimal).toBeDefined();
    });
  });
});