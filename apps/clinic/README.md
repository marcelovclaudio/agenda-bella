# Clinic Management Application

## Overview
Dedicated clinic management application for healthcare providers and aesthetic clinics. Built as a Single Page Application (SPA) using Vite and React for optimal clinic workflow management.

## Technology Stack
- **Framework**: Vite + React 18
- **Architecture**: Single Page Application (SPA)
- **Styling**: Tailwind CSS with shared UI components
- **State Management**: React Query + Zustand
- **Real-time**: WebSocket integration for live notifications

## Features
- Clinic profile management
- Service catalog and pricing
- Appointment scheduling and calendar
- Patient management system
- Staff scheduling and management
- Financial dashboard and reporting
- Inventory management
- Marketing tools and promotions
- Integration with booking system
- Real-time notifications

## Target Users
- Clinic owners and managers
- Medical practitioners
- Administrative staff
- Receptionists

## User Roles
- Clinic Owner: Full clinic management access
- Manager: Operations and staff management
- Practitioner: Appointment and patient management
- Staff: Limited access to scheduling and patients

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
- `VITE_WS_URL`: WebSocket server endpoint
- `VITE_APP_ENV`: Application environment