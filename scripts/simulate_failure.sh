#!/bin/bash
# Failure Simulation Script for AdaptiveWardens

echo "=========================================="
echo "🚨 AdaptiveWardens Failure Simulation 🚨"
echo "=========================================="

echo "[1] Stopping ai-engine to simulate Gemini failure or container crash..."
docker-compose stop ai-engine
echo "ai-engine stopped. SSH Honeypot will now revert to safe fallback static mode."

echo ""
echo "Wait 10 seconds while attacker runs queries against the fallback system..."
sleep 10

echo ""
echo "[2] Restarting ai-engine to simulate recovery..."
docker-compose start ai-engine

echo ""
echo "[3] Simulating Sandbox Store DB Lock / Timeout (Pause container for 5s)"
docker-compose pause sandbox-store
sleep 5
docker-compose unpause sandbox-store
echo "Sandbox store recovered."

echo ""
echo "=========================================="
echo "✅ Simulation Complete. Services recovered."
echo "Check docker-compose logs ssh-frontend for timeout recovery details."
echo "=========================================="
