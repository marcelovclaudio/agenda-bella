# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL DIRECTIVES

**⚠️ NEVER DOWNGRADE LIBRARY VERSIONS**
- NEVER reduce or regress any library version in package.json files
- Always maintain or upgrade library versions, never downgrade
- If a version needs to be changed, it must be an upgrade, never a downgrade
- This applies to ALL dependencies: dependencies, devDependencies, peerDependencies
- When using agents, ensure they follow this directive strictly

## Project Overview

Agenda Bella is a beauty and aesthetics marketplace monorepo that connects consumers to clinics and professionals for procedure booking and payment. The platform serves two main user types: Consumers (seeking aesthetic procedures) and Clinics/Professionals (offering services).

## Architecture

This is a **pnpm + Turborepo monorepo** with the following structure:

### Applications (`apps/`)

- **web**: Next.js 14+ main consumer application (App Router, SSR/SSG)
- **admin**: Vite + React administrative dashboard (SPA)
- **clinic**: Vite + React clinic management application (SPA)
- **api**: Express + TypeScript backend API with WebSocket support
- **landing**: Next.js 14+ marketing landing page (performance optimized)

### Packages (`packages/`)

- **ui**: Shared UI components with Tailwind CSS + shadcn/ui + Radix UI
- **security**: Authentication (JWT), authorization (CASL ACL), rate limiting, password security
- **audit**: Audit trail system, LGPD compliance, security events, data access tracking
- **database**: Prisma ORM + PostgreSQL + Redis + RabbitMQ connections and models
- **api**: Shared API services, Zod validations, middleware, types
- **typescript**: Shared TypeScript configurations for different project types
- **shared**: Utilities, Winston logger, React hooks, common types

### Core Technologies

- **Database**: PostgreSQL (primary), Redis (cache/sessions), RabbitMQ (message queues)
- **Authentication**: JWT with refresh tokens, CASL for ACL
- **UI**: Tailwind CSS, shadcn/ui, Radix UI
- **State Management**: Zustand/Jotai for frontend apps
- **API Integration**: TanStack Query for data fetching
- **Testing**: Jest/Vitest depending on the package
- **Deployment**: Docker containers with multi-stage builds

## Development Commands

### Initial Setup

```bash
# Install dependencies
pnpm install

# Start development environment (all apps)
pnpm dev

# Start Docker services (PostgreSQL, Redis, RabbitMQ)
pnpm dev:docker  # Uses docker/docker-compose.dev.yml
```

### Common Development Tasks

```bash
# Build all packages and apps
pnpm build

# Run linting across monorepo
pnpm lint
pnpm lint:fix

# Type checking
pnpm type-check

# Testing
pnpm test
pnpm test:watch
pnpm test:coverage

# Code formatting
pnpm format
pnpm format:check

# Clean all build artifacts and node_modules
pnpm clean
```

### Database Operations

```bash
# Generate Prisma client
turbo run db:generate

# Push schema changes to dev database
turbo run db:push

# Run migrations
turbo run db:migrate

# Seed database
turbo run db:seed
```

### Working with Specific Workspaces

```bash
# Run commands in specific workspace
pnpm --filter @agenda-bella/ui dev
pnpm --filter web dev
pnpm --filter api test

# Add dependencies to specific workspace
pnpm --filter @agenda-bella/ui add lucide-react
pnpm --filter api add express
```

## Package Dependencies and Relationships

### Internal Package Usage

- All apps depend on `@agenda-bella/ui` for components
- Frontend apps use `@agenda-bella/shared` for utilities and hooks
- API app uses `@agenda-bella/database`, `@agenda-bella/security`, `@agenda-bella/audit`
- All packages use `@agenda-bella/typescript` for TS configurations
- Use workspace protocol: `"@agenda-bella/ui": "workspace:*"`

### Security Integration

- Import auth middleware: `import { authenticate, authorize } from '@agenda-bella/security'`
- Log audit events: `import { auditAction, lgpdLog } from '@agenda-bella/audit'`
- Permission checks: `import { can } from '@agenda-bella/security'`

### UI Component Usage

```typescript
import { Button, Card, Modal } from '@agenda-bella/ui';
import { LoginForm, PermissionGate } from '@agenda-bella/ui/auth';
```

## Business Domain Context

### Core Entities

- **Users**: Consumers and clinic professionals with role-based permissions
- **Clinics**: Service providers with multiple professionals and procedures
- **Procedures**: Aesthetic services offered by clinics (with pricing, duration, descriptions)
- **Appointments**: Bookings made by consumers with payment processing
- **Reviews**: Verified reviews from consumers who completed procedures

### Key Business Flows

1. **Consumer Journey**: Discovery → Procedure/Clinic selection → Booking → Payment → Service delivery → Review
2. **Clinic Journey**: Profile setup → Procedure listing → Booking management → Service delivery → Payment processing
3. **Platform Operations**: User verification → Content moderation → Financial management → Compliance reporting

### Security & Compliance Requirements

- **LGPD Compliance**: All personal data access must be logged via audit package
- **PCI DSS**: Payment processing through secure gateway (escrow model)
- **RBAC**: Role-based access control using CASL for all user actions
- **Audit Trail**: All sensitive operations must be automatically logged

## Key Configuration Files

- **turbo.json**: Defines build pipeline, caching strategy, and task dependencies
- **pnpm-workspace.yaml**: Workspace configuration for apps and packages
- **package.json**: Root-level scripts and dependencies
- **docker/docker-compose.dev.yml**: Development environment services

## Development Workflow

### Adding New Features

1. Check `docs/tasks.md` for relevant task definitions and dependencies
2. Create/modify packages first, then integrate into apps
3. Always run tests and linting before committing
4. Use conventional commits (no AI/Claude mentions in commit messages)

### Testing Strategy

- **Unit Tests**: For all utility functions and business logic
- **Integration Tests**: For API endpoints and database operations
- **Component Tests**: For UI components with user interactions
- **E2E Tests**: For critical user flows (booking, payment, etc.)

### Security Considerations

- All API endpoints require authentication middleware
- Use CASL for fine-grained authorization checks
- Log all sensitive operations via audit package
- Validate all inputs using Zod schemas from api package
- Never log sensitive information (passwords, tokens, personal data)

### Performance Optimization

- Turborepo handles build caching automatically
- Use React.memo and useMemo for expensive computations
- Implement proper code splitting in Next.js apps
- Use Redis for session management and caching
- RabbitMQ for background job processing

## Environment Variables

Each app should have its own `.env.example` file. Common variables:

- Database connection strings (PostgreSQL, Redis, RabbitMQ)
- JWT secrets and refresh token settings
- Payment gateway credentials
- External service API keys
- Environment-specific feature flags
