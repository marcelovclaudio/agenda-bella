/**
 * Token Blacklist System Tests
 * 
 * Tests for TokenBlacklistManager and MemoryTokenBlacklist implementations
 * ensuring proper token blacklisting, validation, and security features.
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
}));

import { TokenBlacklistManager, MemoryTokenBlacklist, createMemoryTokenBlacklistManager } from '../../src/auth/blacklist';
import { AuthenticationError } from '../../src/types';
import type { ISessionRepository } from '../../src/auth/types';

describe('Token Blacklist System', () => {
  describe('MemoryTokenBlacklist', () => {
    let memoryBlacklist: MemoryTokenBlacklist;

    beforeEach(() => {
      memoryBlacklist = new MemoryTokenBlacklist();
    });

    afterEach(() => {
      memoryBlacklist.destroy();
    });

    describe('blacklistToken', () => {
      it('should blacklist a token successfully', async () => {
        const token = 'test-token-123';
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

        await memoryBlacklist.blacklistToken(token, expiresAt);
        
        const isBlacklisted = await memoryBlacklist.isTokenBlacklisted(token);
        expect(isBlacklisted).toBe(true);
      });

      it('should reject invalid token', async () => {
        const expiresAt = new Date(Date.now() + 3600000);

        await expect(memoryBlacklist.blacklistToken('', expiresAt))
          .rejects
          .toThrow('Invalid token provided');
      });

      it('should reject invalid expiration date', async () => {
        const token = 'test-token-123';

        await expect(memoryBlacklist.blacklistToken(token, 'invalid' as any))
          .rejects
          .toThrow('Invalid expiration date provided');
      });
    });

    describe('isTokenBlacklisted', () => {
      it('should return false for non-blacklisted token', async () => {
        const token = 'non-blacklisted-token';
        
        const isBlacklisted = await memoryBlacklist.isTokenBlacklisted(token);
        expect(isBlacklisted).toBe(false);
      });

      it('should return true for blacklisted token', async () => {
        const token = 'blacklisted-token';
        const expiresAt = new Date(Date.now() + 3600000);

        await memoryBlacklist.blacklistToken(token, expiresAt);
        
        const isBlacklisted = await memoryBlacklist.isTokenBlacklisted(token);
        expect(isBlacklisted).toBe(true);
      });

      it('should return false for expired blacklist entry', async () => {
        const token = 'expired-blacklist-token';
        const expiresAt = new Date(Date.now() - 1000); // 1 second ago

        await memoryBlacklist.blacklistToken(token, expiresAt);
        
        const isBlacklisted = await memoryBlacklist.isTokenBlacklisted(token);
        expect(isBlacklisted).toBe(false);
      });

      it('should handle invalid token gracefully', async () => {
        const isBlacklisted = await memoryBlacklist.isTokenBlacklisted('');
        expect(isBlacklisted).toBe(false);
      });
    });

    describe('cleanup functionality', () => {
      it('should clean up expired tokens', async () => {
        const expiredToken = 'expired-token';
        const validToken = 'valid-token';
        const pastDate = new Date(Date.now() - 1000);
        const futureDate = new Date(Date.now() + 3600000);

        await memoryBlacklist.blacklistToken(expiredToken, pastDate);
        await memoryBlacklist.blacklistToken(validToken, futureDate);

        expect(memoryBlacklist.getBlacklistSize()).toBe(2);

        const cleanedCount = memoryBlacklist.cleanupExpiredTokens();
        
        expect(cleanedCount).toBe(1);
        expect(memoryBlacklist.getBlacklistSize()).toBe(1);
        expect(await memoryBlacklist.isTokenBlacklisted(validToken)).toBe(true);
        expect(await memoryBlacklist.isTokenBlacklisted(expiredToken)).toBe(false);
      });

      it('should clear all tokens', async () => {
        const token1 = 'token-1';
        const token2 = 'token-2';
        const futureDate = new Date(Date.now() + 3600000);

        await memoryBlacklist.blacklistToken(token1, futureDate);
        await memoryBlacklist.blacklistToken(token2, futureDate);

        expect(memoryBlacklist.getBlacklistSize()).toBe(2);

        memoryBlacklist.clearAll();

        expect(memoryBlacklist.getBlacklistSize()).toBe(0);
        expect(await memoryBlacklist.isTokenBlacklisted(token1)).toBe(false);
        expect(await memoryBlacklist.isTokenBlacklisted(token2)).toBe(false);
      });
    });
  });

  describe('TokenBlacklistManager', () => {
    let blacklistManager: TokenBlacklistManager;
    let mockSessionRepo: jest.Mocked<ISessionRepository>;

    beforeEach(() => {
      mockSessionRepo = {
        createSession: jest.fn(),
        findSession: jest.fn(),
        revokeSession: jest.fn(),
        revokeAllUserSessions: jest.fn(),
        isTokenBlacklisted: jest.fn(),
        blacklistToken: jest.fn(),
      };

      blacklistManager = new TokenBlacklistManager(mockSessionRepo);
    });

    describe('blacklistToken', () => {
      it('should blacklist token successfully', async () => {
        const token = 'test-token-123';
        const expiresAt = new Date(Date.now() + 3600000);

        mockSessionRepo.blacklistToken.mockResolvedValue();

        await blacklistManager.blacklistToken(token, expiresAt);

        expect(mockSessionRepo.blacklistToken).toHaveBeenCalledWith(token, expiresAt);
      });

      it('should throw AuthenticationError for invalid token', async () => {
        const expiresAt = new Date(Date.now() + 3600000);

        await expect(blacklistManager.blacklistToken('', expiresAt))
          .rejects
          .toThrow(AuthenticationError);
      });

      it('should throw AuthenticationError for invalid expiration', async () => {
        const token = 'test-token-123';
        const pastDate = new Date(Date.now() - 1000);

        await expect(blacklistManager.blacklistToken(token, pastDate))
          .rejects
          .toThrow(AuthenticationError);
      });

      it('should handle repository errors', async () => {
        const token = 'test-token-123';
        const expiresAt = new Date(Date.now() + 3600000);

        mockSessionRepo.blacklistToken.mockRejectedValue(new Error('Database error'));

        await expect(blacklistManager.blacklistToken(token, expiresAt))
          .rejects
          .toThrow(AuthenticationError);
      });
    });

    describe('isTokenBlacklisted', () => {
      it('should check token blacklist status', async () => {
        const token = 'test-token-123';

        mockSessionRepo.isTokenBlacklisted.mockResolvedValue(true);

        const isBlacklisted = await blacklistManager.isTokenBlacklisted(token);

        expect(isBlacklisted).toBe(true);
        expect(mockSessionRepo.isTokenBlacklisted).toHaveBeenCalledWith(token);
      });

      it('should throw AuthenticationError for invalid token', async () => {
        await expect(blacklistManager.isTokenBlacklisted(''))
          .rejects
          .toThrow(AuthenticationError);
      });

      it('should handle repository errors', async () => {
        const token = 'test-token-123';

        mockSessionRepo.isTokenBlacklisted.mockRejectedValue(new Error('Database error'));

        await expect(blacklistManager.isTokenBlacklisted(token))
          .rejects
          .toThrow(AuthenticationError);
      });
    });

    describe('blacklistRefreshToken', () => {
      it('should blacklist refresh token with default expiration', async () => {
        const refreshToken = 'refresh-token-123';

        mockSessionRepo.blacklistToken.mockResolvedValue();

        await blacklistManager.blacklistRefreshToken(refreshToken);

        expect(mockSessionRepo.blacklistToken).toHaveBeenCalledWith(
          refreshToken,
          expect.any(Date)
        );

        // Verify expiration is approximately 7 days from now
        const callArgs = mockSessionRepo.blacklistToken.mock.calls[0];
        const expirationDate = callArgs![1] as Date;
        const sevenDaysFromNow = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        const timeDiff = Math.abs(expirationDate.getTime() - sevenDaysFromNow.getTime());
        
        expect(timeDiff).toBeLessThan(1000); // Should be within 1 second
      });
    });

    describe('getBlacklistStats', () => {
      it('should return basic statistics', async () => {
        const stats = await blacklistManager.getBlacklistStats();

        expect(stats).toEqual({
          totalEntries: 0,
          cleanupNeeded: false,
        });
      });
    });
  });

  describe('Factory Functions', () => {
    describe('createMemoryTokenBlacklistManager', () => {
      it('should create TokenBlacklistManager with MemoryTokenBlacklist', () => {
        const manager = createMemoryTokenBlacklistManager();
        
        expect(manager).toBeInstanceOf(TokenBlacklistManager);
      });

      it('should work with actual token operations', async () => {
        const manager = createMemoryTokenBlacklistManager();
        const token = 'test-token-123';
        const expiresAt = new Date(Date.now() + 3600000);

        await manager.blacklistToken(token, expiresAt);
        const isBlacklisted = await manager.isTokenBlacklisted(token);

        expect(isBlacklisted).toBe(true);
      });
    });
  });

  describe('Integration Tests', () => {
    it('should integrate TokenBlacklistManager with MemoryTokenBlacklist', async () => {
      const memoryBlacklist = new MemoryTokenBlacklist();
      const manager = new TokenBlacklistManager(memoryBlacklist as any);

      const token = 'integration-test-token';
      const expiresAt = new Date(Date.now() + 3600000);

      // Test blacklisting
      await manager.blacklistToken(token, expiresAt);
      
      // Test checking status
      const isBlacklisted = await manager.isTokenBlacklisted(token);
      expect(isBlacklisted).toBe(true);

      // Test refresh token blacklisting
      const refreshToken = 'refresh-integration-token';
      await manager.blacklistRefreshToken(refreshToken);
      
      const isRefreshBlacklisted = await manager.isTokenBlacklisted(refreshToken);
      expect(isRefreshBlacklisted).toBe(true);

      // Cleanup
      memoryBlacklist.destroy();
    });

    it('should handle security context in operations', async () => {
      const manager = createMemoryTokenBlacklistManager();
      const token = 'context-test-token';
      const expiresAt = new Date(Date.now() + 3600000);
      const context = {
        sessionId: 'test-session-id',
        ipAddress: '127.0.0.1',
        timestamp: new Date(),
        userAgent: 'test-agent',
      };

      // Should not throw with security context
      await expect(manager.blacklistToken(token, expiresAt, context))
        .resolves
        .not
        .toThrow();

      await expect(manager.isTokenBlacklisted(token, context))
        .resolves
        .toBe(true);
    });
  });
});