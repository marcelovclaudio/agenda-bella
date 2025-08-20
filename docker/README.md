# Agenda Bella - Development Environment

This directory contains Docker configurations for running Agenda Bella's development environment with PostgreSQL, Redis, and RabbitMQ.

## Services

### PostgreSQL

- **Port**: 5432
- **Database**: `agenda_bella_dev`
- **Username**: `agenda_bella`
- **Password**: `agenda_bella_dev_password`
- **Features**:
  - Pre-configured schema with tables for users, clinics, appointments, payments, and audit logs
  - Sample data for development
  - LGPD compliance audit trails
  - Optimized indexes for performance

### Redis

- **Port**: 6379
- **Features**:
  - Session storage
  - Caching
  - Rate limiting
  - Persistence enabled for development
  - Keyspace notifications for session expiration

### RabbitMQ

- **AMQP Port**: 5672
- **Management UI**: http://localhost:15672
- **Username**: `agenda_bella`
- **Password**: `agenda_bella_dev_password`
- **Virtual Host**: `/agenda_bella`
- **Features**:
  - Pre-configured exchanges and queues
  - Email, SMS, and push notification queues
  - Payment processing queues
  - Audit log processing
  - WebSocket event distribution
  - Dead letter queue for failed messages

## Quick Start

### Prerequisites

- Docker
- Docker Compose

### Starting Services

```bash
# Start all services
./docker/start-dev.sh

# Or manually
docker-compose -f docker/docker-compose.dev.yml up -d
```

### Health Check

```bash
# Check service health
./docker/health-check.sh
```

### Stopping Services

```bash
docker-compose -f docker/docker-compose.dev.yml down
```

## Configuration Files

### PostgreSQL

- `postgres/init.sql` - Database schema and sample data
- Schema includes:
  - Users and authentication
  - Clinics and services
  - Appointment management
  - Payment processing with escrow
  - Audit logs for LGPD compliance
  - Session backup tables

### Redis

- `redis/redis.conf` - Redis configuration optimized for development
- Features:
  - Both RDB and AOF persistence
  - Memory management (256MB limit)
  - Keyspace notifications
  - Slow query logging

### RabbitMQ

- `rabbitmq/rabbitmq.conf` - RabbitMQ server configuration
- `rabbitmq/definitions.json` - Exchanges, queues, and bindings
- Queue structure:
  - `notifications.*` - Email, SMS, push notifications
  - `payments.*` - Payment processing and escrow
  - `audit.logs` - LGPD compliance logging
  - `appointments.*` - Reminders and confirmations
  - `websocket.events` - Real-time updates

## Environment Variables

Copy `.env.example` to `.env` and customize as needed:

```bash
cp docker/.env.example docker/.env
```

Key variables:

- Database connection strings
- Redis configuration
- RabbitMQ settings
- Application secrets
- External service configuration

## Development Workflow

### Database Operations

```bash
# Access PostgreSQL
docker exec -it agenda-bella-postgres-dev psql -U agenda_bella -d agenda_bella_dev

# Run migrations (when available)
docker exec -it agenda-bella-postgres-dev psql -U agenda_bella -d agenda_bella_dev -f /path/to/migration.sql

# Backup database
docker exec agenda-bella-postgres-dev pg_dump -U agenda_bella agenda_bella_dev > backup.sql
```

### Redis Operations

```bash
# Access Redis CLI
docker exec -it agenda-bella-redis-dev redis-cli

# Monitor Redis
docker exec -it agenda-bella-redis-dev redis-cli monitor

# Check memory usage
docker exec -it agenda-bella-redis-dev redis-cli info memory
```

### RabbitMQ Operations

```bash
# Access management UI
open http://localhost:15672

# List queues
docker exec agenda-bella-rabbitmq-dev rabbitmqctl list_queues -p /agenda_bella

# List exchanges
docker exec agenda-bella-rabbitmq-dev rabbitmqctl list_exchanges -p /agenda_bella

# Purge queue (for testing)
docker exec agenda-bella-rabbitmq-dev rabbitmqctl purge_queue notifications.email -p /agenda_bella
```

## Monitoring and Logs

### View Logs

```bash
# All services
docker-compose -f docker/docker-compose.dev.yml logs -f

# Specific service
docker-compose -f docker/docker-compose.dev.yml logs -f postgres
docker-compose -f docker/docker-compose.dev.yml logs -f redis
docker-compose -f docker/docker-compose.dev.yml logs -f rabbitmq
```

### Service Status

```bash
# Check running containers
docker-compose -f docker/docker-compose.dev.yml ps

# Check health status
docker-compose -f docker/docker-compose.dev.yml ps --format json | jq '.[].Health'
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 5432, 6379, 5672, and 15672 are not in use
2. **Permission errors**: Ensure Docker has proper file system permissions
3. **Memory issues**: Increase Docker memory allocation if services fail to start

### Reset Environment

```bash
# Stop and remove all containers and volumes
docker-compose -f docker/docker-compose.dev.yml down -v

# Remove unused volumes
docker volume prune

# Start fresh
./docker/start-dev.sh
```

### Check Connectivity

```bash
# Test from host
psql -h localhost -p 5432 -U agenda_bella -d agenda_bella_dev
redis-cli -h localhost -p 6379 ping
curl -u agenda_bella:agenda_bella_dev_password http://localhost:15672/api/overview
```

## Security Notes

- **Development Only**: These configurations are optimized for development and should not be used in production
- **Default Passwords**: Change all default passwords before deploying to any environment
- **Network Access**: Services are exposed on all interfaces for development convenience
- **Data Persistence**: Volumes are used to persist data between container restarts

## Next Steps

After starting the development environment:

1. Set up your application configuration to use these services
2. Run database migrations if available
3. Configure your application's message queue consumers
4. Set up monitoring and alerting for production environments
5. Implement proper backup strategies for production data
