#!/bin/bash
echo "=========================================="
echo "Starting AdaptiveWardens Honeypot..."
echo "=========================================="

if ! command -v docker &> /dev/null; then
  echo "Error: Docker is not installed"
  exit 1
fi

if ! command -v docker-compose &> /dev/null; then
  echo "Error: Docker Compose is not installed"
  exit 1
fi

echo ""
echo "Building containers..."
docker-compose build --no-cache

echo ""
echo "Starting services..."
docker-compose up -d

echo ""
echo "Waiting for services to start..."
sleep 15

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
echo "  Sandbox API:      http://localhost:8001"
echo "  Dashboard:        http://localhost:3000"
echo ""
echo "Test with:"
echo "  ssh root@localhost -p 2222"
echo ""
echo "Commands:"
echo "  View logs:        docker-compose logs -f"
echo "  View SSH logs:    docker-compose logs -f ssh-frontend"
echo "  View API logs:    docker-compose logs -f sandbox-store"
echo "  View dashboard:   docker-compose logs -f dashboard-frontend"
echo "  Stop services:    ./stop.sh"
echo "  Restart:          docker-compose restart"
echo ""
