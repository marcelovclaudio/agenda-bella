#!/bin/bash

# Agenda Bella - Development Environment Startup Script
set -e

echo "🚀 Starting Agenda Bella development environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Navigate to the docker directory
cd "$(dirname "$0")"

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f docker-compose.dev.yml down --remove-orphans

# Pull latest images
echo "📥 Pulling latest images..."
docker-compose -f docker-compose.dev.yml pull

# Start services
echo "🔧 Starting services..."
docker-compose -f docker-compose.dev.yml up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."

# Function to check service health
check_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f docker-compose.dev.yml ps --services --filter "status=running" | grep -q "$service_name"; then
            if docker-compose -f docker-compose.dev.yml exec -T "$service_name" echo "Health check" > /dev/null 2>&1; then
                echo "✅ $service_name is ready"
                return 0
            fi
        fi
        echo "⏳ Waiting for $service_name... (attempt $attempt/$max_attempts)"
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to start properly"
    return 1
}

# Check each service
check_service postgres
check_service redis
check_service rabbitmq

echo ""
echo "🎉 Development environment is ready!"
echo ""
echo "📋 Service Information:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🗄️  PostgreSQL:    localhost:5432"
echo "   Database:       agenda_bella_dev"
echo "   Username:       agenda_bella"
echo "   Password:       agenda_bella_dev_password"
echo ""
echo "🔄 Redis:           localhost:6379"
echo "   No authentication required"
echo ""
echo "🐰 RabbitMQ:        localhost:5672 (AMQP)"
echo "   Management UI:   http://localhost:15672"
echo "   Username:        agenda_bella"
echo "   Password:        agenda_bella_dev_password"
echo "   Virtual Host:    /agenda_bella"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔍 To view logs:"
echo "   docker-compose -f docker/docker-compose.dev.yml logs -f [service_name]"
echo ""
echo "🛑 To stop:"
echo "   docker-compose -f docker/docker-compose.dev.yml down"
echo ""