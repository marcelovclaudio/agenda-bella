/**
 * Database Abstraction Layer for Authentication
 *
 * This module provides database abstraction for authentication operations,
 * including mock implementations for development and testing, and interfaces
 * for future database integrations.
 *
 * Features:
 * - Mock implementations for User and Session repositories
 * - Database factory pattern for different backends
 * - Comprehensive session management with device tracking
 * - Security logging and audit trails
 * - Type-safe interfaces for future Prisma integration
 *
 * @packageDocumentation
 */

import { createChildLogger } from '../utils';
import { hashPassword, verifyPassword } from '../password/utils';
import type {
  IUserRepository,
  ISessionRepository,
  AuthenticatedUser,
  DatabaseConfig,
} from './types';

const logger = createChildLogger({ component: 'auth-database' });

/**
 * Mock User Repository Implementation
 *
 * Provides in-memory user management for development and testing.
 * Includes password hashing, user creation, and validation.
 */
export class MockUserRepository implements IUserRepository {
  private users: Map<string, AuthenticatedUser & { password: string }> = new Map();

  constructor() {
    // Add default admin user for testing
    void this.initializeDefaultUsers();
  }

  /**
   * Initialize default users for development and testing
   */
  private async initializeDefaultUsers(): Promise<void> {
    try {
      const adminPassword = await hashPassword('password123');
      
      this.users.set('admin@example.com', {
        id: '1',
        email: 'admin@example.com',
        roles: ['admin', 'user'],
        permissions: ['user:read', 'user:write', 'admin:all'],
        sessionId: '',
        lastLoginAt: new Date(),
        password: adminPassword,
      });

      // Add a regular user for testing
      const userPassword = await hashPassword('user123');
      this.users.set('user@example.com', {
        id: '2',
        email: 'user@example.com',
        roles: ['user'],
        permissions: ['user:read'],
        sessionId: '',
        lastLoginAt: new Date(),
        password: userPassword,
      });

      // Add a professional user for testing
      const professionalPassword = await hashPassword('professional123');
      this.users.set('doctor@clinic.com', {
        id: '3',
        email: 'doctor@clinic.com',
        roles: ['professional', 'user'],
        permissions: ['user:read', 'user:write', 'appointment:read', 'appointment:write', 'patient:read'],
        sessionId: '',
        lastLoginAt: new Date(),
        password: professionalPassword,
      });

      logger.info('Default users initialized for development', {
        userCount: this.users.size,
        users: Array.from(this.users.keys()),
      });
    } catch (error) {
      logger.error('Failed to initialize default users', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Find user by email address
   */
  findByEmail(email: string): Promise<AuthenticatedUser | null> {
    const user = this.users.get(email);
    if (!user) {
      logger.debug('User not found by email', { email });
      return Promise.resolve(null);
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user;
    
    logger.debug('User found by email', { 
      email, 
      userId: userWithoutPassword.id,
      roles: userWithoutPassword.roles,
    });

    return Promise.resolve(userWithoutPassword);
  }

  /**
   * Find user by unique identifier
   */
  findById(id: string): Promise<AuthenticatedUser | null> {
    for (const user of this.users.values()) {
      if (user.id === id) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, ...userWithoutPassword } = user;
        
        logger.debug('User found by ID', { 
          userId: id,
          email: userWithoutPassword.email,
          roles: userWithoutPassword.roles,
        });

        return Promise.resolve(userWithoutPassword);
      }
    }

    logger.debug('User not found by ID', { userId: id });
    return Promise.resolve(null);
  }

  /**
   * Update user's last login timestamp
   */
  updateLastLogin(id: string): Promise<void> {
    for (const [email, user] of this.users.entries()) {
      if (user.id === id) {
        user.lastLoginAt = new Date();
        this.users.set(email, user);
        
        logger.debug('User last login updated', { 
          userId: id,
          email: user.email,
          lastLoginAt: user.lastLoginAt.toISOString(),
        });
        
        return Promise.resolve();
      }
    }

    logger.warn('Attempted to update last login for non-existent user', { userId: id });
    return Promise.resolve();
  }

  /**
   * Validate user password
   */
  async validatePassword(email: string, password: string): Promise<boolean> {
    const user = this.users.get(email);
    if (!user) {
      logger.debug('Password validation failed - user not found', { email });
      return false;
    }

    try {
      const isValid = await verifyPassword(password, user.password);
      
      logger.debug('Password validation completed', { 
        email,
        userId: user.id,
        isValid,
      });

      return isValid;
    } catch (error) {
      logger.error('Password validation error', { 
        email, 
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Create new user (useful for testing and admin features)
   */
  async createUser(userData: {
    email: string;
    password: string;
    roles?: string[];
    permissions?: string[];
  }): Promise<AuthenticatedUser> {
    const { email, password, roles = ['user'], permissions = ['user:read'] } = userData;

    if (this.users.has(email)) {
      logger.warn('Attempted to create user with existing email', { email });
      throw new Error('User already exists');
    }

    try {
      const hashedPassword = await hashPassword(password);
      const id = `user_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

      const newUser = {
        id,
        email,
        roles,
        permissions,
        sessionId: '',
        lastLoginAt: new Date(),
        password: hashedPassword,
      };

      this.users.set(email, newUser);

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = newUser;

      logger.info('New user created', {
        userId: id,
        email,
        roles,
        permissions,
      });

      return userWithoutPassword;
    } catch (error) {
      logger.error('Failed to create user', {
        email,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new Error('Failed to create user');
    }
  }

  /**
   * List all users (for admin features)
   */
  listUsers(): Promise<Omit<AuthenticatedUser, 'sessionId'>[]> {
    const users: Omit<AuthenticatedUser, 'sessionId'>[] = [];

    for (const user of this.users.values()) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, sessionId, ...userWithoutSensitiveData } = user;
      users.push(userWithoutSensitiveData);
    }

    logger.debug('Users list requested', { userCount: users.length });

    return Promise.resolve(users);
  }

  /**
   * Update user password
   */
  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    // Find user by ID first
    let userToUpdate: (AuthenticatedUser & { password: string }) | undefined;
    let userEmail: string | undefined;

    for (const [email, user] of this.users.entries()) {
      if (user.id === userId) {
        userToUpdate = user;
        userEmail = email;
        break;
      }
    }

    if (!userToUpdate || !userEmail) {
      logger.error('Update password failed - user not found', { userId });
      throw new Error('User not found');
    }

    // Update the password
    userToUpdate.password = hashedPassword;
    this.users.set(userEmail, userToUpdate);

    logger.info('User password updated successfully', {
      userId,
      email: userEmail,
    });
  }
}

/**
 * Mock Session Repository Implementation
 *
 * Provides in-memory session management with comprehensive features including
 * device tracking, session expiration, and token blacklisting.
 */
export class MockSessionRepository implements ISessionRepository {
  private sessions = new Map<string, {
    userId: string;
    refreshToken: string;
    deviceInfo?: any;
    createdAt: Date;
    lastAccessedAt: Date;
  }>();
  
  private blacklistedTokens = new Map<string, Date>();
  private userSessions = new Map<string, Set<string>>(); // userId -> sessionIds

  /**
   * Create new user session
   */
  createSession(userId: string, refreshToken: string, deviceInfo?: unknown): Promise<string> {
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    const now = new Date();

    this.sessions.set(sessionId, {
      userId,
      refreshToken,
      deviceInfo,
      createdAt: now,
      lastAccessedAt: now,
    });

    // Track user sessions
    if (!this.userSessions.has(userId)) {
      this.userSessions.set(userId, new Set());
    }
    this.userSessions.get(userId)!.add(sessionId);

    logger.debug('Session created', {
      sessionId,
      userId,
      deviceInfo: deviceInfo ? {
        userAgent: (deviceInfo as any).userAgent?.substring(0, 50) + '...' || 'unknown',
        ipAddress: (deviceInfo as any).ipAddress || 'unknown',
      } : undefined,
      createdAt: now.toISOString(),
    });

    return Promise.resolve(sessionId);
  }

  /**
   * Find session by session identifier
   */
  findSession(sessionId: string): Promise<{ userId: string; refreshToken: string } | null> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      logger.debug('Session not found', { sessionId });
      return Promise.resolve(null);
    }

    // Update last accessed time
    session.lastAccessedAt = new Date();
    this.sessions.set(sessionId, session);

    logger.debug('Session found and updated', {
      sessionId,
      userId: session.userId,
      lastAccessedAt: session.lastAccessedAt.toISOString(),
    });

    return Promise.resolve({
      userId: session.userId,
      refreshToken: session.refreshToken,
    });
  }

  /**
   * Update session refresh token
   */
  async updateSessionToken(sessionId: string, newRefreshToken: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      logger.warn('Attempted to update token for non-existent session', { sessionId });
      return;
    }

    // Blacklist the old refresh token
    await this.blacklistToken(session.refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)); // 7 days

    session.refreshToken = newRefreshToken;
    session.lastAccessedAt = new Date();
    this.sessions.set(sessionId, session);

    logger.debug('Session token updated', {
      sessionId,
      userId: session.userId,
      lastAccessedAt: session.lastAccessedAt.toISOString(),
    });
  }

  /**
   * Revoke specific session
   */
  async revokeSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      logger.debug('Attempted to revoke non-existent session', { sessionId });
      return;
    }

    // Blacklist the refresh token
    await this.blacklistToken(session.refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)); // 7 days

    // Remove from user sessions tracking
    if (this.userSessions.has(session.userId)) {
      this.userSessions.get(session.userId)!.delete(sessionId);
    }

    this.sessions.delete(sessionId);

    logger.debug('Session revoked', {
      sessionId,
      userId: session.userId,
      revokedAt: new Date().toISOString(),
    });
  }

  /**
   * Revoke all user sessions
   */
  async revokeAllUserSessions(userId: string): Promise<void> {
    const userSessionIds = this.userSessions.get(userId);
    if (!userSessionIds) {
      logger.debug('No sessions found for user', { userId });
      return;
    }

    let revokedCount = 0;
    const revokedAt = new Date();

    for (const sessionId of userSessionIds) {
      const session = this.sessions.get(sessionId);
      if (session) {
        // Blacklist the refresh token
        await this.blacklistToken(session.refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)); // 7 days
        this.sessions.delete(sessionId);
        revokedCount++;
      }
    }

    // Clear user session tracking
    this.userSessions.delete(userId);

    logger.info('All user sessions revoked', {
      userId,
      revokedCount,
      revokedAt: revokedAt.toISOString(),
    });
  }

  /**
   * Get user's active sessions
   */
  async getUserActiveSessions(userId: string): Promise<Array<{
    sessionId: string;
    deviceInfo?: any;
    createdAt: Date;
    lastAccessedAt: Date;
  }>> {
    const userSessionIds = this.userSessions.get(userId) || new Set();
    const activeSessions: Array<{
      sessionId: string;
      deviceInfo?: any;
      createdAt: Date;
      lastAccessedAt: Date;
    }> = [];

    for (const sessionId of userSessionIds) {
      const session = this.sessions.get(sessionId);
      if (session) {
        activeSessions.push({
          sessionId,
          deviceInfo: session.deviceInfo,
          createdAt: session.createdAt,
          lastAccessedAt: session.lastAccessedAt,
        });
      }
    }

    logger.debug('User active sessions retrieved', {
      userId,
      sessionCount: activeSessions.length,
    });

    return activeSessions;
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    const expiryDate = this.blacklistedTokens.get(token);
    if (!expiryDate) {
      return false;
    }

    // Remove expired blacklisted tokens
    if (expiryDate < new Date()) {
      this.blacklistedTokens.delete(token);
      return false;
    }

    logger.debug('Token blacklist check', {
      tokenPrefix: token.substring(0, 10) + '...',
      isBlacklisted: true,
      expiresAt: expiryDate.toISOString(),
    });

    return true;
  }

  /**
   * Add token to blacklist
   */
  async blacklistToken(token: string, expiresAt: Date): Promise<void> {
    this.blacklistedTokens.set(token, expiresAt);

    logger.debug('Token blacklisted', {
      tokenPrefix: token.substring(0, 10) + '...',
      expiresAt: expiresAt.toISOString(),
      blacklistSize: this.blacklistedTokens.size,
    });

    // Clean up expired tokens periodically
    this.cleanupExpiredTokens();
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    const now = new Date();
    const expiredCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // 7 days
    let cleanedCount = 0;

    const expiredSessionIds: string[] = [];

    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.lastAccessedAt < expiredCutoff) {
        expiredSessionIds.push(sessionId);
      }
    }

    // Revoke all expired sessions
    for (const sessionId of expiredSessionIds) {
      await this.revokeSession(sessionId);
      cleanedCount++;
    }

    if (cleanedCount > 0) {
      logger.info('Expired sessions cleaned up', {
        cleanedCount,
        expiredCutoff: expiredCutoff.toISOString(),
        remainingSessions: this.sessions.size,
      });
    }

    return cleanedCount;
  }

  /**
   * Clean up expired blacklisted tokens
   */
  private cleanupExpiredTokens(): void {
    const now = new Date();
    let cleanedCount = 0;

    for (const [token, expiryDate] of this.blacklistedTokens.entries()) {
      if (expiryDate < now) {
        this.blacklistedTokens.delete(token);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug('Expired tokens cleaned up', {
        cleanedCount,
        remainingTokens: this.blacklistedTokens.size,
      });
    }
  }
}

/**
 * Create mock database repositories for development and testing
 */
export function createMockDatabaseRepositories(): {
  userRepo: IUserRepository;
  sessionRepo: ISessionRepository;
} {
  logger.info('Creating mock database repositories');
  
  return {
    userRepo: new MockUserRepository(),
    sessionRepo: new MockSessionRepository(),
  };
}

/**
 * Database abstraction factory for future CORE-001 integration
 */
export function createDatabaseRepositories(config: DatabaseConfig): {
  userRepo: IUserRepository;
  sessionRepo: ISessionRepository;
} {
  logger.info('Creating database repositories', { type: config.type });

  switch (config.type) {
    case 'mock':
      return createMockDatabaseRepositories();

    case 'custom':
      if (!config.customRepositories) {
        throw new Error('Custom repositories must be provided when type is "custom"');
      }
      
      logger.info('Using custom database repositories');
      return config.customRepositories;

    case 'prisma':
      // Will be implemented when CORE-001 is available
      logger.error('Prisma integration attempted but not yet available');
      throw new Error('Prisma integration not yet available. Use mock or custom repositories.');

    default:
      throw new Error(`Unsupported database type: ${config.type}`);
  }
}

/**
 * Database configuration validation
 */
export function validateDatabaseConfig(config: DatabaseConfig): void {
  if (!config.type) {
    throw new Error('Database type is required');
  }

  const validTypes = ['mock', 'prisma', 'custom'];
  if (!validTypes.includes(config.type)) {
    throw new Error(`Invalid database type: ${config.type}. Must be one of: ${validTypes.join(', ')}`);
  }

  if (config.type === 'custom' && !config.customRepositories) {
    throw new Error('Custom repositories must be provided when using custom database type');
  }

  if (config.type === 'custom' && config.customRepositories) {
    if (!config.customRepositories.userRepo) {
      throw new Error('Custom user repository is required');
    }
    if (!config.customRepositories.sessionRepo) {
      throw new Error('Custom session repository is required');
    }
  }

  logger.debug('Database configuration validated', { type: config.type });
}