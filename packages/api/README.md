# API Package

## Overview
Shared API utilities, services, and middleware for Agenda Bella applications. Provides consistent API patterns, validation schemas, and reusable service functions across the entire platform.

## Technology Stack
- **Validation**: Zod schemas for runtime type validation
- **HTTP Client**: Axios with interceptors and retry logic
- **Types**: Shared TypeScript interfaces and types
- **Middleware**: Common Express.js middleware functions
- **Services**: Reusable business logic and API integrations

## Features
- Zod validation schemas for all API endpoints
- Type-safe API client with auto-completion
- Common middleware for authentication, logging, and error handling
- Shared business logic and service functions
- API response formatting and error standardization
- Rate limiting and security utilities
- File upload and processing utilities

## Validation Schemas
```typescript
import { z } from 'zod'

export const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
  phone: z.string().optional()
})

export const AppointmentSchema = z.object({
  clinicId: z.string().cuid(),
  serviceId: z.string().cuid(),
  datetime: z.date(),
  notes: z.string().optional()
})
```

## API Client
```typescript
import { ApiClient } from '@agenda-bella/api'

const api = new ApiClient({
  baseURL: process.env.API_URL,
  timeout: 10000
})

// Type-safe API calls
const user = await api.users.getById('user-id')
const appointments = await api.appointments.list({ clinicId: 'clinic-id' })
```

## Middleware
- **Authentication**: JWT token validation and user context
- **Authorization**: Role-based access control (RBAC)
- **Validation**: Request/response validation with Zod
- **Logging**: Structured logging with correlation IDs
- **Error Handling**: Consistent error responses and logging
- **Rate Limiting**: Configurable rate limiting by user/IP
- **CORS**: Cross-origin resource sharing configuration

## Services
- **Email Service**: Transactional email sending
- **SMS Service**: SMS notifications and verification
- **Payment Service**: Stripe integration for payments
- **Storage Service**: File upload to AWS S3/CloudFlare R2
- **Cache Service**: Redis caching layer
- **Queue Service**: Background job processing

## Usage
```bash
# Install the package
pnpm add @agenda-bella/api

# Import utilities
import { validateRequest, ApiClient, EmailService } from '@agenda-bella/api'
```

## Development
```bash
# Install dependencies
pnpm install

# Build package
pnpm build

# Run tests
pnpm test

# Generate types
pnpm types
```