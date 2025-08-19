#!/bin/bash

# Agenda Bella - Development Environment Health Check
set -e

echo "🏥 Checking Agenda Bella development environment health..."

cd "$(dirname "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if service is running
check_container() {
    local service_name=$1
    local container_name=$2
    
    if docker ps --format "table {{.Names}}" | grep -q "$container_name"; then
        echo -e "${GREEN}✅ $service_name container is running${NC}"
        return 0
    else
        echo -e "${RED}❌ $service_name container is not running${NC}"
        return 1
    fi
}

# Function to check service health
check_health() {
    local service_name=$1
    
    health_status=$(docker-compose -f docker-compose.dev.yml ps --format json | jq -r --arg service "$service_name" '.[] | select(.Service == $service) | .Health')
    
    if [ "$health_status" = "healthy" ]; then
        echo -e "${GREEN}✅ $service_name is healthy${NC}"
        return 0
    elif [ "$health_status" = "starting" ]; then
        echo -e "${YELLOW}⏳ $service_name is starting${NC}"
        return 1
    else
        echo -e "${RED}❌ $service_name is unhealthy${NC}"
        return 1
    fi
}

# Function to test database connection
test_postgres() {
    echo "🔍 Testing PostgreSQL connection..."
    if docker exec agenda-bella-postgres-dev psql -U agenda_bella -d agenda_bella_dev -c "SELECT 1;" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PostgreSQL connection successful${NC}"
        
        # Check if tables exist
        table_count=$(docker exec agenda-bella-postgres-dev psql -U agenda_bella -d agenda_bella_dev -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | xargs)
        echo -e "${GREEN}📊 Found $table_count tables in database${NC}"
        return 0
    else
        echo -e "${RED}❌ PostgreSQL connection failed${NC}"
        return 1
    fi
}

# Function to test Redis connection
test_redis() {
    echo "🔍 Testing Redis connection..."
    if docker exec agenda-bella-redis-dev redis-cli ping | grep -q "PONG"; then
        echo -e "${GREEN}✅ Redis connection successful${NC}"
        return 0
    else
        echo -e "${RED}❌ Redis connection failed${NC}"
        return 1
    fi
}

# Function to test RabbitMQ connection
test_rabbitmq() {
    echo "🔍 Testing RabbitMQ connection..."
    if docker exec agenda-bella-rabbitmq-dev rabbitmq-diagnostics ping > /dev/null 2>&1; then
        echo -e "${GREEN}✅ RabbitMQ connection successful${NC}"
        
        # Check queues
        queue_count=$(docker exec agenda-bella-rabbitmq-dev rabbitmqctl list_queues -p /agenda_bella --quiet 2>/dev/null | wc -l || echo "0")
        echo -e "${GREEN}📬 Found $queue_count queues configured${NC}"
        return 0
    else
        echo -e "${RED}❌ RabbitMQ connection failed${NC}"
        return 1
    fi
}

# Main health check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if Docker Compose is running
if ! docker-compose -f docker-compose.dev.yml ps --services > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose services are not running${NC}"
    echo "💡 Run: docker-compose -f docker/docker-compose.dev.yml up -d"
    exit 1
fi

# Check containers
check_container "PostgreSQL" "agenda-bella-postgres-dev"
postgres_container=$?

check_container "Redis" "agenda-bella-redis-dev"
redis_container=$?

check_container "RabbitMQ" "agenda-bella-rabbitmq-dev"
rabbitmq_container=$?

echo ""

# Check health status
if command -v jq > /dev/null 2>&1; then
    check_health "postgres"
    postgres_health=$?
    
    check_health "redis"
    redis_health=$?
    
    check_health "rabbitmq"
    rabbitmq_health=$?
    echo ""
else
    echo -e "${YELLOW}⚠️  jq not installed, skipping health checks${NC}"
    postgres_health=0
    redis_health=0
    rabbitmq_health=0
fi

# Test connections if containers are running
connection_tests=0
if [ $postgres_container -eq 0 ]; then
    test_postgres && connection_tests=$((connection_tests + 1))
fi

if [ $redis_container -eq 0 ]; then
    test_redis && connection_tests=$((connection_tests + 1))
fi

if [ $rabbitmq_container -eq 0 ]; then
    test_rabbitmq && connection_tests=$((connection_tests + 1))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Summary
if [ $connection_tests -eq 3 ]; then
    echo -e "${GREEN}🎉 All services are healthy and ready!${NC}"
    echo ""
    echo "🌐 Access URLs:"
    echo "   PostgreSQL:  localhost:5432"
    echo "   Redis:       localhost:6379"
    echo "   RabbitMQ UI: http://localhost:15672"
    exit 0
else
    echo -e "${RED}⚠️  Some services are not ready yet${NC}"
    echo ""
    echo "💡 Tips:"
    echo "   • Wait a few moments for services to start"
    echo "   • Check logs: docker-compose -f docker/docker-compose.dev.yml logs [service]"
    echo "   • Restart services: docker-compose -f docker/docker-compose.dev.yml restart"
    exit 1
fi