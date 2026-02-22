#!/bin/bash
echo "Stopping AdaptiveWardens Honeypot..."
docker-compose down

echo ""
echo "✓ Honeypot stopped."
echo ""
echo "To remove all data: docker-compose down -v"
