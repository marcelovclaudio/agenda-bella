# TypeScript Configuration Package

## Overview

Shared TypeScript configurations for different project types within the Agenda Bella monorepo. Provides consistent TypeScript settings, compiler options, and type checking across all applications and packages.

## Configuration Files

- **base.json**: Base configuration with common compiler options
- **react.json**: Configuration for React applications (web, admin, clinic, landing)
- **node.json**: Configuration for Node.js applications (api)
- **package.json**: Configuration for packages and libraries
- **nextjs.json**: Specific configuration for Next.js applications

## Features

- Strict type checking enabled
- Modern ES2022 target with appropriate module resolution
- Path mapping for monorepo packages
- Consistent import/export patterns
- Optimized for both development and production builds
- Support for React JSX and Node.js environments

## Usage

```bash
# Install the package
pnpm add -D @agenda-bella/typescript

# Extend in your tsconfig.json
{
  "extends": "@agenda-bella/typescript/react.json",
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## Configuration Types

- **React Apps**: Includes React types, JSX support, and DOM libraries
- **Node.js API**: Includes Node.js types and server-side configurations
- **Packages**: Library-focused configuration with declaration generation
- **Next.js**: Optimized for Next.js with App Router support

## Path Mapping

All configurations include workspace path mapping for seamless package imports:

```typescript
import { UserModel } from '@agenda-bella/database';
import { validateEmail } from '@agenda-bella/shared';
import { Button } from '@agenda-bella/ui';
```

## Development

```bash
# Install dependencies
pnpm install

# Build configurations
pnpm build

# Validate configurations
pnpm validate
```
