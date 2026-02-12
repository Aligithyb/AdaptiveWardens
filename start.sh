#!/bin/bash

echo "=========================================="
echo "Starting AdaptiveWardens Honeypot..."
echo "=========================================="

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    exit 1
fi

# Create .env if needed
if [ ! -f .env ]; then
    echo "Creating .env from template..."
    cp .env.example .env
    echo "✓ Created .env file"
fi

# Build containers
echo ""
echo "Building containers..."
docker-compose build

# Start services
echo ""
echo "Starting services..."
docker-compose up -d

# Wait for services
echo ""
echo "Waiting for services to start..."
sleep 15

# Check health
echo ""
echo "Service Status:"
docker-compose ps

echo ""
echo "=========================================="
echo "✓ AdaptiveWardens is running!"
echo "=========================================="
echo ""
echo "Services:"
echo "  SSH Honeypot:     localhost:2222"
echo "  HTTP Honeypot:    localhost:8080"
echo "  Dashboard:        http://localhost:3000"
echo "  API:              http://localhost:8000"
echo ""
echo "Commands:"
echo "  View logs:        docker-compose logs -f"
echo "  Stop services:    docker-compose down"
echo "  Restart:          docker-compose restart"
echo ""
