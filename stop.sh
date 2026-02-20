#!/bin/bash

echo "Stopping AdaptiveWardens Honeypot..."

docker-compose down

echo "Honeypot stopped."
echo "To remove all data, run: docker-compose down -v"
