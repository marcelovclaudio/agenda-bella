# Admin Dashboard

## Overview
Administrative dashboard for Agenda Bella platform management. Built as a Single Page Application (SPA) using Vite and React for fast development and optimal performance.

## Technology Stack
- **Framework**: Vite + React 18
- **Architecture**: Single Page Application (SPA)
- **Styling**: Tailwind CSS with shared UI components
- **State Management**: React Query + Zustand
- **Authentication**: Role-based access control (RBAC)

## Features
- Platform analytics and metrics
- User management (consumers and clinic owners)
- Clinic verification and approval
- Content moderation and reporting
- Financial reporting and commission tracking
- System configuration and settings
- Audit trail monitoring
- LGPD compliance tools

## Target Users
- Platform administrators
- Support team members
- Compliance officers
- Financial analysts

## Access Control
- Super Admin: Full system access
- Admin: Limited administrative functions
- Support: User support and basic moderation
- Analyst: Read-only access to reports and analytics

## Development
```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build

# Preview production build
pnpm preview
```

## Environment Variables
- `VITE_API_URL`: Backend API endpoint
- `VITE_APP_ENV`: Application environment (development/staging/production)