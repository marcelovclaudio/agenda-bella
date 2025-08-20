# Security Package

## Overview

Comprehensive security utilities for Agenda Bella marketplace. Handles authentication, authorization, password security, rate limiting, and security best practices across all applications.

## Technology Stack

- **Authentication**: JWT tokens with refresh token rotation
- **Authorization**: CASL (Ability-based Access Control) for fine-grained permissions
- **Password Security**: bcrypt hashing with salt rounds
- **Rate Limiting**: Redis-based distributed rate limiting
- **Encryption**: AES encryption for sensitive data
- **Security Headers**: Helmet.js integration

## Features

- JWT authentication with access and refresh tokens
- Role-based and ability-based access control
- Secure password hashing and validation
- Rate limiting by user, IP, and endpoint
- Data encryption and decryption utilities
- Security middleware for Express.js
- CSRF protection and validation
- Input sanitization and XSS prevention

## Authentication

```typescript
import { AuthService, JWTService } from '@agenda-bella/security';

// Generate tokens
const { accessToken, refreshToken } = await AuthService.generateTokens(user);

// Validate and decode tokens
const payload = await JWTService.verifyToken(accessToken);

// Refresh tokens
const newTokens = await AuthService.refreshTokens(refreshToken);
```

## Authorization (CASL)

```typescript
import { AbilityBuilder, defineAbility } from '@agenda-bella/security';

// Define user abilities
const ability = defineAbility((can, cannot) => {
  if (user.role === 'CLINIC_OWNER') {
    can('manage', 'Appointment', { clinicId: user.clinicId });
    can('read', 'User', { id: user.id });
    cannot('delete', 'User');
  }
});

// Check permissions
if (ability.can('create', 'Appointment')) {
  // User can create appointments
}
```

## Password Security

```typescript
import { PasswordService } from '@agenda-bella/security';

// Hash password
const hashedPassword = await PasswordService.hash('userPassword');

// Verify password
const isValid = await PasswordService.verify('userPassword', hashedPassword);

// Validate password strength
const validation = PasswordService.validateStrength('newPassword');
```

## Rate Limiting

```typescript
import { RateLimiter } from '@agenda-bella/security';

// Create rate limiter
const loginLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  keyGenerator: (req) => req.ip,
});

// Apply to routes
app.post('/login', loginLimiter.middleware, authController.login);
```

## Security Middleware

- **Authentication**: Verify JWT tokens and set user context
- **Authorization**: Check user permissions for routes
- **Rate Limiting**: Protect against brute force and DoS attacks
- **CSRF Protection**: Validate CSRF tokens for state-changing operations
- **Security Headers**: Set security headers (HSTS, CSP, etc.)
- **Input Validation**: Sanitize and validate request data

## Usage

```bash
# Install the package
pnpm add @agenda-bella/security

# Import utilities
import { AuthService, RateLimiter, securityMiddleware } from '@agenda-bella/security'
```

## Development

```bash
# Install dependencies
pnpm install

# Build package
pnpm build

# Run tests
pnpm test

# Security audit
pnpm audit
```
