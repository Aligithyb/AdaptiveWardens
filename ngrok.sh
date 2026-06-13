#!/bin/bash
set -e

echo "=========================================="
echo "AdaptiveWardens - ngrok Tunnels"
echo "=========================================="
echo ""

if ! command -v ngrok &> /dev/null; then
  echo "Error: ngrok is not installed."
  echo "Install it: brew install ngrok"
  echo ""
  echo "Then sign up at https://ngrok.com and run:"
  echo "  ngrok config add-authtoken YOUR_TOKEN"
  exit 1
fi

if [ ! -f .env ]; then
  echo "Error: .env file not found."
  echo "Run: cp .env.example .env"
  exit 1
fi

echo "Starting ngrok tunnels..."
echo ""

# Kill any existing ngrok instances
pkill -f "ngrok http" 2>/dev/null || true
pkill -f "ngrok tcp"  2>/dev/null || true

# Dashboard tunnel (HTTP)
ngrok http 3000 --log=stdout > /tmp/ngrok_dashboard.log 2>&1 &

# SSH tunnel (TCP)
ngrok tcp 2222 --log=stdout > /tmp/ngrok_ssh.log 2>&1 &

sleep 3

echo ""
echo "Fetching tunnel URLs..."
echo ""

DASHBOARD_URL=$(curl -s http://127.0.0.1:4040/api/tunnels | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for t in data.get('tunnels', []):
        if t.get('proto') == 'https':
            print(t['public_url'])
except: pass
")

SSH_URL=$(curl -s http://127.0.0.1:4040/api/tunnels | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for t in data.get('tunnels', []):
        if t.get('proto') == 'tcp':
            print(t['public_url'])
except: pass
")

echo "=========================================="
echo "✓ Tunnels Active!"
echo "=========================================="
echo ""
echo "  Dashboard:     ${DASHBOARD_URL:-waiting...}"
echo "  SSH Honeypot:  ${SSH_URL:-waiting...}"
echo ""
echo "Open the Dashboard URL in your browser."
echo "Default password: gradproject2025"
echo ""
echo "Test SSH: ssh root@localhost -p 2222"
echo "Through tunnel: ssh root@<ssh_url_host> -p <ssh_url_port>"
echo ""
echo "Stop tunnels:  pkill -f ngrok"
echo ""

wait
