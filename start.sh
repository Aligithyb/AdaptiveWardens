#!/bin/bash

echo "Starting AdaptiveWardens Honeypot..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    exit 1
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env from template..."
    cp .env.example .env
    echo "Please edit .env with your configuration"
    exit 1
fi

# Build and start containers
echo "Building containers..."
docker-compose build

echo "Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Check health
echo "Checking service health..."
docker-compose ps

echo ""
echo "AdaptiveWardens is running!"
echo ""
echo "Services:"
echo "  SSH Honeypot:     localhost:2222"
echo "  HTTP Honeypot:    localhost:8080"
echo "  Dashboard:        http://localhost:3000"
echo "  API:              http://localhost:8000"
echo ""
echo "View logs with: docker-compose logs -f"
echo "Stop with: docker-compose down"
