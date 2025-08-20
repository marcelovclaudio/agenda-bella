# API Backend

## Overview

Backend API server for Agenda Bella marketplace. Built with Express.js and TypeScript, providing RESTful APIs and WebSocket support for real-time features.

## Technology Stack

- **Framework**: Express.js with TypeScript
- **Database**: PostgreSQL with Prisma ORM
- **Cache**: Redis for session storage and caching
- **Message Queue**: RabbitMQ for background jobs
- **Real-time**: WebSocket support for live notifications
- **Authentication**: JWT-based authentication with refresh tokens
- **Documentation**: OpenAPI/Swagger documentation

## Features

- RESTful API endpoints
- Real-time WebSocket connections
- User authentication and authorization
- Clinic and service management
- Appointment booking system
- Payment processing integration
- File upload and image processing
- Email and SMS notifications
- Background job processing
- Rate limiting and security middleware
- Comprehensive logging and monitoring

## API Modules

- **Auth**: Authentication and user management
- **Clinics**: Clinic profiles and services
- **Appointments**: Booking and scheduling
- **Payments**: Payment processing and billing
- **Notifications**: Email, SMS, and push notifications
- **Upload**: File and image handling
- **Analytics**: Platform metrics and reporting

## Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build

# Start production server
pnpm start

# Run database migrations
pnpm db:migrate

# Generate Prisma client
pnpm db:generate
```

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `RABBITMQ_URL`: RabbitMQ connection string
- `JWT_SECRET`: Secret for JWT token signing
- `JWT_REFRESH_SECRET`: Secret for refresh token signing
- `STRIPE_SECRET_KEY`: Stripe secret key for payments
- `AWS_ACCESS_KEY_ID`: AWS credentials for file storage
- `SMTP_HOST`: Email server configuration
