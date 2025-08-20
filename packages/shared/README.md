# Shared Utilities Package

## Overview

Common utilities, helper functions, React hooks, and shared types used across all Agenda Bella applications. Promotes code reuse and consistency throughout the monorepo.

## Technology Stack

- **Utilities**: Date/time, validation, formatting, and string utilities
- **Logging**: Winston logger with structured logging and multiple transports
- **React Hooks**: Custom hooks for common patterns and state management
- **Types**: Shared TypeScript interfaces and type definitions
- **Constants**: Application-wide constants and configuration

## Features

- Comprehensive utility functions for common operations
- Structured logging with Winston and custom formatters
- Custom React hooks for state management and side effects
- Shared TypeScript types and interfaces
- Date/time utilities with timezone support
- Input validation and sanitization helpers
- Formatting utilities for currency, phone numbers, etc.

## Utilities

```typescript
import {
  deepMerge,
  formatCurrency,
  formatPhone,
  generateSlug,
  truncateText,
  validateEmail,
} from '@agenda-bella/shared';

// Format currency in Brazilian Real
const price = formatCurrency(99.99, 'BRL'); // 'R$ 99,99'

// Format Brazilian phone number
const phone = formatPhone('11999887766'); // '(11) 9 9988-7766'

// Validate email address
const isValid = validateEmail('user@example.com'); // true

// Generate URL-friendly slug
const slug = generateSlug('Clínica de Estética'); // 'clinica-de-estetica'
```

## Logging

```typescript
import { logger } from '@agenda-bella/shared';

// Structured logging
logger.info('User logged in', {
  userId: 'user-123',
  timestamp: new Date(),
  ip: '192.168.1.1',
});

logger.error('Payment failed', {
  orderId: 'order-456',
  error: error.message,
  stack: error.stack,
});

// Custom logger with context
const userLogger = logger.child({ userId: 'user-123' });
userLogger.info('Appointment booked', { appointmentId: 'apt-789' });
```

## React Hooks

```typescript
import { useApi, useAsync, useDebounce, useForm, useLocalStorage } from '@agenda-bella/shared';

// Persistent local storage
const [settings, setSettings] = useLocalStorage('user-settings', {});

// Debounced search
const [searchTerm, setSearchTerm] = useState('');
const debouncedSearch = useDebounce(searchTerm, 300);

// Async operations
const { data, loading, error, execute } = useAsync(fetchUserData);

// Form management
const { values, errors, handleChange, handleSubmit } = useForm({
  initialValues: { email: '', password: '' },
  onSubmit: handleLogin,
});
```

## Shared Types

```typescript
// User types
export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  createdAt: Date;
  updatedAt: Date;
}

// API response types
export interface ApiResponse<T> {
  data: T;
  message: string;
  success: boolean;
  timestamp: Date;
}

// Form validation types
export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string[]>;
}
```

## Constants

```typescript
import { API_ENDPOINTS, APP_CONFIG, VALIDATION_RULES } from '@agenda-bella/shared';

// Application configuration
const { APP_NAME, VERSION, SUPPORT_EMAIL } = APP_CONFIG;

// API endpoints
const userEndpoint = API_ENDPOINTS.USERS.GET_BY_ID;

// Validation rules
const { PASSWORD_MIN_LENGTH, EMAIL_REGEX } = VALIDATION_RULES;
```

## Date/Time Utilities

```typescript
import { DateUtils } from '@agenda-bella/shared';

// Brazilian timezone handling
const now = DateUtils.nowInBrazil(); // Date in America/Sao_Paulo

// Format date for display
const formatted = DateUtils.formatForDisplay(date, 'pt-BR'); // '15 de março de 2024'

// Business hours validation
const isOpen = DateUtils.isWithinBusinessHours(date, '09:00', '18:00');

// Appointment scheduling utilities
const availableSlots = DateUtils.getAvailableSlots(date, duration, existingAppointments);
```

## Usage

```bash
# Install the package
pnpm add @agenda-bella/shared

# Import utilities
import { logger, formatCurrency, useLocalStorage } from '@agenda-bella/shared'
```

## Development

```bash
# Install dependencies
pnpm install

# Build package
pnpm build

# Run tests
pnpm test

# Type checking
pnpm type-check
```
