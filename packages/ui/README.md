# UI Package

## Overview
Shared UI component library for Agenda Bella applications. Built with React, Tailwind CSS, and modern component patterns to ensure consistency across all applications.

## Technology Stack
- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS with CSS-in-JS support
- **Component Library**: shadcn/ui + Radix UI primitives
- **Icons**: Lucide React + Heroicons
- **Animations**: Framer Motion for smooth transitions
- **Documentation**: Storybook for component documentation

## Components
- **Forms**: Input, Select, Checkbox, Radio, DatePicker, FormField
- **Navigation**: Button, Link, Breadcrumb, Pagination, Tabs
- **Layout**: Container, Grid, Stack, Card, Modal, Sidebar
- **Data Display**: Table, Badge, Avatar, Tooltip, Progress
- **Feedback**: Alert, Toast, Loading, Empty State, Error Boundary
- **Business**: AppointmentCard, ClinicCard, ServiceCard, ReviewCard

## Design System
- **Colors**: Primary, secondary, neutral, and semantic color palettes
- **Typography**: Heading and body text scales with proper line heights
- **Spacing**: Consistent spacing scale based on 4px grid
- **Breakpoints**: Mobile-first responsive design breakpoints
- **Shadows**: Elevation system with consistent shadow patterns

## Usage
```bash
# Install the package
pnpm add @agenda-bella/ui

# Import components
import { Button, Card, Input } from '@agenda-bella/ui'
```

## Development
```bash
# Install dependencies
pnpm install

# Start Storybook
pnpm storybook

# Build components
pnpm build

# Run tests
pnpm test

# Lint components
pnpm lint
```

## Theming
The UI package supports theme customization through CSS custom properties and Tailwind CSS configuration. Each application can override colors, fonts, and spacing while maintaining component consistency.