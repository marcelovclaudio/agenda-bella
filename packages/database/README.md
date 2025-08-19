# Database Package

## Overview
Comprehensive database layer for Agenda Bella marketplace. Includes Prisma ORM schemas, database models, migrations, and connections to PostgreSQL, Redis, and RabbitMQ.

## Technology Stack
- **ORM**: Prisma with PostgreSQL
- **Cache**: Redis for session storage and caching
- **Message Queue**: RabbitMQ for background job processing
- **Migrations**: Prisma migrations with seeding
- **Connection Pooling**: pgBouncer-ready configuration

## Database Schema
- **Users**: Consumer and clinic owner accounts
- **Clinics**: Clinic profiles, services, and staff
- **Appointments**: Booking system with scheduling
- **Payments**: Transaction and billing records
- **Reviews**: Rating and review system
- **Notifications**: Message and alert storage
- **Audit**: Activity logs and compliance tracking

## Features
- Type-safe database queries with Prisma Client
- Redis caching layer for performance optimization
- RabbitMQ integration for async processing
- Database seeding for development and testing
- Comprehensive migration system
- Connection pooling and optimization
- LGPD compliance with data retention policies

## Models Overview
```prisma
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  role      Role     @default(CONSUMER)
  profile   Profile?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model Clinic {
  id          String      @id @default(cuid())
  name        String
  description String?
  services    Service[]
  staff       Staff[]
  createdAt   DateTime    @default(now())
  updatedAt   DateTime    @updatedAt
}
```

## Usage
```bash
# Install the package
pnpm add @agenda-bella/database

# Use in your application
import { prisma, redis, rabbitmq } from '@agenda-bella/database'
```

## Development
```bash
# Install dependencies
pnpm install

# Generate Prisma client
pnpm db:generate

# Run migrations
pnpm db:migrate

# Seed database
pnpm db:seed

# Reset database
pnpm db:reset

# Studio (database GUI)
pnpm db:studio
```

## Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `RABBITMQ_URL`: RabbitMQ connection string