# Web Application

## Overview
The main consumer-facing web application for Agenda Bella marketplace. Built with Next.js 14+ using App Router for optimal performance and SEO.

## Technology Stack
- **Framework**: Next.js 14+ with App Router
- **Rendering**: Server-Side Rendering (SSR) and Static Site Generation (SSG)
- **Styling**: Tailwind CSS with shared UI components
- **Authentication**: Integrated with security package
- **State Management**: React Query for server state, Zustand for client state

## Features
- User registration and authentication
- Service discovery and search
- Clinic profiles and reviews
- Appointment booking system
- Payment processing
- User dashboard and booking history
- Responsive design for mobile and desktop

## Target Users
- End consumers looking for aesthetic procedures
- Clients managing their appointments and preferences
- Users browsing and discovering new clinics and services

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
```

## Environment Variables
- `NEXT_PUBLIC_API_URL`: Backend API endpoint
- `NEXT_PUBLIC_STRIPE_KEY`: Stripe public key for payments
- `NEXTAUTH_SECRET`: NextAuth.js secret for session management