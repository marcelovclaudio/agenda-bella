# Audit Package

## Overview
Comprehensive audit trail and compliance system for Agenda Bella marketplace. Ensures LGPD compliance, tracks security events, monitors data access, and maintains detailed activity logs.

## Technology Stack
- **Logging**: Winston with structured logging
- **Storage**: PostgreSQL for audit trails with data retention
- **Compliance**: LGPD (Brazilian GDPR) compliance utilities
- **Monitoring**: Security event detection and alerting
- **Encryption**: Encrypted audit logs for sensitive operations

## Features
- Complete audit trail for all user and system actions
- LGPD compliance with data subject rights management
- Security event monitoring and alerting
- Data access tracking and consent management
- Automated data retention and deletion policies
- Compliance reporting and export capabilities
- Real-time security anomaly detection

## Audit Events
```typescript
import { AuditService, AuditEvent } from '@agenda-bella/audit'

// Log user action
await AuditService.log({
  action: 'USER_LOGIN',
  userId: 'user-123',
  resource: 'Authentication',
  metadata: { ip: '192.168.1.1', userAgent: 'Chrome' },
  timestamp: new Date()
})

// Log data access
await AuditService.logDataAccess({
  userId: 'user-123',
  dataType: 'PERSONAL_DATA',
  operation: 'READ',
  recordId: 'record-456',
  purpose: 'Service delivery'
})
```

## LGPD Compliance
```typescript
import { LGPDService, ConsentManager } from '@agenda-bella/audit'

// Track user consent
await ConsentManager.recordConsent({
  userId: 'user-123',
  consentType: 'DATA_PROCESSING',
  purpose: 'Service delivery and communication',
  granted: true,
  timestamp: new Date()
})

// Handle data subject requests
await LGPDService.handleDataRequest({
  userId: 'user-123',
  requestType: 'DATA_EXPORT',
  requestDate: new Date()
})

// Automated data deletion
await LGPDService.scheduleDataDeletion({
  userId: 'user-123',
  retentionPeriod: '7-years',
  dataTypes: ['APPOINTMENT_HISTORY', 'PAYMENT_DATA']
})
```

## Security Monitoring
```typescript
import { SecurityMonitor } from '@agenda-bella/audit'

// Monitor suspicious activities
SecurityMonitor.detectAnomalies({
  userId: 'user-123',
  actions: ['MULTIPLE_LOGIN_ATTEMPTS', 'DATA_EXPORT_REQUEST'],
  timeframe: '5-minutes'
})

// Alert on security events
SecurityMonitor.onSecurityEvent('BRUTE_FORCE_ATTACK', (event) => {
  // Send alert to security team
  SecurityMonitor.sendAlert(event)
})
```

## Audit Categories
- **Authentication**: Login, logout, password changes
- **Authorization**: Permission changes, role assignments
- **Data Access**: Personal data views, exports, modifications
- **Financial**: Payment processing, refunds, commission changes
- **Administrative**: User management, system configuration
- **Security**: Failed login attempts, suspicious activities

## Compliance Features
- **Data Subject Rights**: Access, rectification, erasure, portability
- **Consent Management**: Granular consent tracking and withdrawal
- **Data Retention**: Automated retention policies and deletion
- **Breach Detection**: Security incident detection and reporting
- **Compliance Reporting**: Automated compliance reports and metrics

## Usage
```bash
# Install the package
pnpm add @agenda-bella/audit

# Import utilities
import { AuditService, LGPDService, SecurityMonitor } from '@agenda-bella/audit'
```

## Development
```bash
# Install dependencies
pnpm install

# Build package
pnpm build

# Run tests
pnpm test

# Generate compliance report
pnpm compliance:report
```