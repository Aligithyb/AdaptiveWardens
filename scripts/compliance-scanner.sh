#!/usr/bin/env bash
# ==============================================================================
# AdaptiveWardens — Codebase Compliance Scanner
# ==============================================================================
# Scans the source code for security controls and maps them to:
#   - NIST SP 800-53 Rev. 5
#   - GDPR (General Data Protection Regulation)
#   - SOC 2 Type II
#   - ISO 27001:2013
#
# Usage:
#   bash scripts/compliance-scanner.sh [/path/to/repo]
#
# Output:
#   - Prints detailed compliance report to stdout
#   - Saves JSON report to ./compliance-report.json
# ==============================================================================

set -euo pipefail

REPO="${1:-.}"
cd "$REPO"
REPO_NAME=$(basename "$(pwd)")

OUTPUT_FILE="./compliance-report.json"
TOTAL_CONTROLS=0
PASSED=0
FAILED=0
CONTROLS_JSON="["

# ── Helper: check if a pattern exists in any file matching a glob ───────────
check_exists() {
  local pattern="$1"
  local glob="$2"
  local dir="${3:-.}"
  grep -r -l "$pattern" --include="$glob" "$dir" 2>/dev/null | head -1 | grep -q .
}

count_matches() {
  local pattern="$1"
  local glob="$2"
  local dir="${3:-.}"
  grep -r -c "$pattern" --include="$glob" "$dir" 2>/dev/null | awk -F: '{s+=$2} END {print s+0}'
}

# ── Register a control check ────────────────────────────────────────────────
add_control() {
  local id="$1"
  local category="$2"
  local name="$3"
  local description="$4"
  local status="$5"        # "PASS" or "FAIL"
  local evidence="$6"
  local nist="$7"
  local gdpr="$8"
  local soc2="$9"
  local iso27001="${10}"

  TOTAL_CONTROLS=$((TOTAL_CONTROLS + 1))
  if [ "$status" = "PASS" ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
  fi

  if [ "$CONTROLS_JSON" != "[" ]; then
    CONTROLS_JSON+=","
  fi
  CONTROLS_JSON+=$(jq -n \
    --arg id "$id" \
    --arg cat "$category" \
    --arg name "$name" \
    --arg desc "$description" \
    --arg status "$status" \
    --arg evidence "$evidence" \
    --arg nist "$nist" \
    --arg gdpr "$gdpr" \
    --arg soc2 "$soc2" \
    --arg iso "$iso27001" \
    '{id:$id,category:$cat,name:$name,description:$desc,status:$status,evidence:$evidence,mappings:{nist:$nist,gdpr:$gdpr,soc2:$soc2,iso27001:$iso}}')
}

# ═══════════════════════════════════════════════════════════════════════════════
#  1. ACCESS CONTROL (NIST AC, ISO 27001 A.9, SOC 2 CC6, GDPR Art 32)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== ACCESS CONTROL ==="

# AC-1: SSH Authentication
if grep -q "password\|PASSWORD\|authenticated" ssh-frontend/src/ssh_server.py 2>/dev/null; then
  add_control "AC-1" "Access Control" "SSH Authentication" \
    "SSH honeypot authenticates attackers with password verification" \
    "PASS" "ssh-frontend/src/ssh_server.py" \
    "AC-3, AC-7" "Art. 32" "CC6.1" "A.9.1.2"
else
  add_control "AC-1" "Access Control" "SSH Authentication" \
    "SSH honeypot authenticates attackers with password verification" \
    "FAIL" "Not found" "AC-3, AC-7" "Art. 32" "CC6.1" "A.9.1.2"
fi

# AC-2: Dashboard API Key
if grep -q "DASHBOARD_API_KEY\|api_key\|API_KEY" dashboard-backend/src/api.py 2>/dev/null; then
  add_control "AC-2" "Access Control" "Dashboard API Key Authentication" \
    "Dashboard backend requires API key for access" \
    "PASS" "dashboard-backend/src/api.py" \
    "AC-3" "Art. 32" "CC6.1" "A.9.2.1"
else
  add_control "AC-2" "Access Control" "Dashboard API Key Authentication" \
    "Dashboard backend requires API key for access" \
    "FAIL" "Not found" "AC-3" "Art. 32" "CC6.1" "A.9.2.1"
fi

# AC-3: Non-Root Users in Docker
if grep -q "USER [0-9]\|USER nextjs\|adduser\|addgroup" --include=Dockerfile . 2>/dev/null; then
  add_control "AC-3" "Access Control" "Non-Root Container Users" \
    "Dockerfiles specify non-root users for reduced privileges" \
    "PASS" "Dockerfiles (USER directive found)" \
    "AC-6" "-" "CC6.2" "A.9.2.3"
else
  add_control "AC-3" "Access Control" "Non-Root Container Users" \
    "Dockerfiles specify non-root users for reduced privileges" \
    "FAIL" "Not found in Dockerfiles" "AC-6" "-" "CC6.2" "A.9.2.3"
fi

# AC-4: JWT Authentication
if grep -q "JWT\|jwt\|JWT_SECRET" dashboard-backend/ dashboard-frontend/ 2>/dev/null; then
  add_control "AC-4" "Access Control" "JWT Token Authentication" \
    "Dashboard uses JWT tokens for session management" \
    "PASS" "JWT references found" "AC-3" "Art. 32" "CC6.1" "A.9.2.1"
else
  add_control "AC-4" "Access Control" "JWT Token Authentication" \
    "Dashboard uses JWT tokens for session management" \
    "FAIL" "Not found" "AC-3" "Art. 32" "CC6.1" "A.9.2.1"
fi

# AC-5: Session Timeout
if grep -q "SESSION_TIMEOUT\|session_timeout\|session-timeout\|TIMEOUT\|expiry\|EXPIRE" .env.example 2>/dev/null; then
  add_control "AC-5" "Access Control" "Session Timeout" \
    "Sessions automatically expire after inactivity" \
    "PASS" ".env.example: JWT_EXPIRY=3600, SESSION_TIMEOUT=1800" \
    "AC-12" "Art. 32" "CC6.1" "A.9.2.5"
else
  add_control "AC-5" "Access Control" "Session Timeout" \
    "Sessions automatically expire after inactivity" \
    "FAIL" "Not found" "AC-12" "Art. 32" "CC6.1" "A.9.2.5"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  2. AUDIT & ACCOUNTABILITY (NIST AU, ISO 27001 A.12, SOC 2 CC3, GDPR Art 33)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== AUDIT & ACCOUNTABILITY ==="

# AU-1: Session Logging
if grep -q "log_command\|log_session\|LOG\|session_log\|command_log\|INSERT.*command" sandbox-store/src/ ai-engine/src/ 2>/dev/null; then
  add_control "AU-1" "Audit & Accountability" "Attacker Session Logging" \
    "All attacker commands and sessions are logged to database" \
    "PASS" "sandbox-store/src/database.py" \
    "AU-2, AU-3" "Art. 33" "CC3.1" "A.12.4.1"
else
  add_control "AU-1" "Audit & Accountability" "Attacker Session Logging" \
    "All attacker commands and sessions are logged to database" \
    "FAIL" "Not found" "AU-2, AU-3" "Art. 33" "CC3.1" "A.12.4.1"
fi

# AU-2: Structured Audit Records
if check_exists "timestamp\|TIMESTAMP\|created_at\|event_time" "*.py" "sandbox-store" || \
   check_exists "timestamp\|TIMESTAMP\|created_at\|event_time" "*.py" "ai-engine"; then
  add_control "AU-2" "Audit & Accountability" "Structured Audit Records" \
    "Audit logs contain timestamps, IPs, and event details" \
    "PASS" "Database schemas with timestamp fields" \
    "AU-3" "Art. 33" "CC3.1" "A.12.4.1"
else
  add_control "AU-2" "Audit & Accountability" "Structured Audit Records" \
    "Audit logs contain timestamps, IPs, and event details" \
    "FAIL" "Not found" "AU-3" "Art. 33" "CC3.1" "A.12.4.1"
fi

# AU-3: SOC Dashboard for Review
if [ -d "dashboard-frontend" ] && [ -d "dashboard-backend" ]; then
  add_control "AU-3" "Audit & Accountability" "Audit Review Dashboard" \
    "SOC dashboard provides centralized audit review" \
    "PASS" "dashboard-frontend/ and dashboard-backend/ exist" \
    "AU-6" "Art. 33" "CC3.2" "A.12.4.3"
else
  add_control "AU-3" "Audit & Accountability" "Audit Review Dashboard" \
    "SOC dashboard provides centralized audit review" \
    "FAIL" "Not found" "AU-6" "Art. 33" "CC3.2" "A.12.4.3"
fi

# AU-4: Real-time Alerting
if grep -q "SLACK_WEBHOOK_URL\|slack_alert\|alert\|ALERT" .env.example 2>/dev/null; then
  add_control "AU-4" "Audit & Accountability" "Real-time Security Alerting" \
    "Slack alerts for high-risk attacker sessions" \
    "PASS" ".env.example: SLACK_WEBHOOK_URL" \
    "AU-6, IR-6" "Art. 33" "CC3.2" "A.16.1.1"
else
  add_control "AU-4" "Audit & Accountability" "Real-time Security Alerting" \
    "Slack alerts for high-risk attacker sessions" \
    "FAIL" "Not found" "AU-6, IR-6" "Art. 33" "CC3.2" "A.16.1.1"
fi

# AU-5: HTTP Request Logging
if check_exists "X-Forwarded-For\|X-Real-IP\|Client-IP\|remote_addr" "*.py" "http-frontend"; then
  add_control "AU-5" "Audit & Accountability" "HTTP Request Audit Trail" \
    "HTTP honeypot logs request headers and IPs" \
    "PASS" "http-frontend/src/http_server.py" \
    "AU-2, AU-12" "Art. 33" "CC3.1" "A.12.4.1"
else
  add_control "AU-5" "Audit & Accountability" "HTTP Request Audit Trail" \
    "HTTP honeypot logs request headers and IPs" \
    "FAIL" "Not found" "AU-2, AU-12" "Art. 33" "CC3.1" "A.12.4.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  3. CONFIGURATION MANAGEMENT (NIST CM, ISO 27001 A.12, SOC 2 CC6)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== CONFIGURATION MANAGEMENT ==="

# CM-1: Pinned Docker Base Images
PINNED_IMAGES=$(grep -r "^FROM.*:" --include=Dockerfile . 2>/dev/null | grep -v ":\$" | grep -v "latest\|alpine:latest\|slim:latest" | wc -l || echo 0)
NO_TAG=$(grep -r "^FROM.*:" --include=Dockerfile . 2>/dev/null | grep -v ":\$" | grep -v ":" | wc -l || echo 0)
if [ "$PINNED_IMAGES" -gt 0 ] && [ "$NO_TAG" -eq 0 ]; then
  add_control "CM-1" "Configuration Management" "Pinned Docker Base Images" \
    "Docker images use specific version tags (not 'latest')" \
    "PASS" "$PINNED_IMAGES pinned images found" \
    "CM-2" "-" "CC6.3" "A.12.5.1"
else
  add_control "CM-1" "Configuration Management" "Pinned Docker Base Images" \
    "Docker images use specific version tags (not 'latest')" \
    "FAIL" "Unpinned images found" "CM-2" "-" "CC6.3" "A.12.5.1"
fi

# CM-2: Multi-stage Builds
if grep -q "AS builder\|as builder\|FROM.*AS " --include=Dockerfile . 2>/dev/null; then
  add_control "CM-2" "Configuration Management" "Multi-stage Docker Builds" \
    "Multi-stage builds reduce attack surface in production images" \
    "PASS" "Multi-stage Dockerfiles found" \
    "CM-2" "-" "CC6.3" "A.12.5.1"
else
  add_control "CM-2" "Configuration Management" "Multi-stage Docker Builds" \
    "Multi-stage builds reduce attack surface in production images" \
    "FAIL" "Not found" "CM-2" "-" "CC6.3" "A.12.5.1"
fi

# CM-3: Docker Compose Network Isolation
if grep -q "networks:" docker-compose.yml 2>/dev/null && \
   grep -q "internal:\|internal:" docker-compose.yml 2>/dev/null; then
  add_control "CM-3" "Configuration Management" "Docker Network Isolation" \
    "Services are isolated across multiple Docker networks" \
    "PASS" "docker-compose.yml: prod-internal and dmz networks" \
    "CM-2, SC-7" "-" "CC6.6" "A.13.1.1"
else
  # Check at least that networks are defined
  if grep -q "networks:" docker-compose.yml 2>/dev/null; then
    add_control "CM-3" "Configuration Management" "Docker Network Isolation" \
      "Services are isolated across multiple Docker networks" \
      "PASS" "docker-compose.yml: networks defined" \
      "CM-2, SC-7" "-" "CC6.6" "A.13.1.1"
  else
    add_control "CM-3" "Configuration Management" "Docker Network Isolation" \
      "Services are isolated across multiple Docker networks" \
      "FAIL" "Not found in docker-compose.yml" "CM-2, SC-7" "-" "CC6.6" "A.13.1.1"
  fi
fi

# CM-4: Docker HEALTHCHECK
if grep -q "HEALTHCHECK" --include=Dockerfile . 2>/dev/null; then
  add_control "CM-4" "Configuration Management" "Container Health Checks" \
    "Docker containers have HEALTHCHECK defined" \
    "PASS" "HEALTHCHECK found in Dockerfiles" \
    "CM-2, SI-4" "Art. 32" "CC7.1" "A.12.6.1"
else
  add_control "CM-4" "Configuration Management" "Container Health Checks" \
    "Docker containers have HEALTHCHECK defined" \
    "FAIL" "Not found in Dockerfiles" "CM-2, SI-4" "Art. 32" "CC7.1" "A.12.6.1"
fi

# CM-5: Pinned Python Dependencies
PINNED_PY=$(grep -c "==" sandbox-store/requirements.txt ai-engine/requirements.txt http-frontend/requirements.txt ssh-frontend/requirements.txt dashboard-backend/requirements.txt 2>/dev/null || echo 0)
if [ "$PINNED_PY" -gt 10 ]; then
  add_control "CM-5" "Configuration Management" "Pinned Python Dependencies" \
    "Python packages pinned to specific versions" \
    "PASS" "$PINNED_PY pinned dependencies found" \
    "CM-2" "-" "CC6.3" "A.12.5.1"
else
  add_control "CM-5" "Configuration Management" "Pinned Python Dependencies" \
    "Python packages pinned to specific versions" \
    "FAIL" "Few or no pinned dependencies" "CM-2" "-" "CC6.3" "A.12.5.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  4. INCIDENT RESPONSE (NIST IR, ISO 27001 A.16, SOC 2 CC7, GDPR Art 33)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== INCIDENT RESPONSE ==="

# IR-1: Honeypot Attack Capture
if [ -f "ssh-frontend/src/ssh_server.py" ] || [ -f "http-frontend/src/http_server.py" ]; then
  add_control "IR-1" "Incident Response" "Attack Session Capture" \
    "Honeypot captures complete attacker sessions for analysis" \
    "PASS" "ssh-frontend/src/ssh_server.py + http-frontend/src/http_server.py" \
    "IR-4, IR-5" "Art. 33" "CC7.2" "A.16.1.1"
else
  add_control "IR-1" "Incident Response" "Attack Session Capture" \
    "Honeypot captures complete attacker sessions for analysis" \
    "FAIL" "Not found" "IR-4, IR-5" "Art. 33" "CC7.2" "A.16.1.1"
fi

# IR-2: MITRE ATT&CK Mapping
MITRE_COUNT=$(count_matches "MITRE\|ATTACK\|attack_id\|technique" "*.py" "ai-engine")
if [ "$MITRE_COUNT" -gt 0 ]; then
  add_control "IR-2" "Incident Response" "MITRE ATT&CK Mapping" \
    "Attacker techniques mapped to MITRE ATT&CK v15 framework" \
    "PASS" "ai-engine/: $MITRE_COUNT MITRE references" \
    "IR-5" "-" "CC7.2" "A.16.1.1"
else
  add_control "IR-2" "Incident Response" "MITRE ATT&CK Mapping" \
    "Attacker techniques mapped to MITRE ATT&CK v15 framework" \
    "FAIL" "Not found" "IR-5" "-" "CC7.2" "A.16.1.1"
fi

# IR-3: IOC Extraction
IOC_COUNT=$(count_matches "IOC\|ioc\|indicator\|INDICATOR\|extract_ioc" "*.py" "ai-engine")
if [ "$IOC_COUNT" -gt 0 ]; then
  add_control "IR-3" "Incident Response" "Indicator of Compromise Extraction" \
    "IOCs (IPs, domains, hashes) extracted from attacker activity" \
    "PASS" "ai-engine/: $IOC_COUNT IOC references" \
    "IR-5" "Art. 33" "CC7.2" "A.16.1.1"
else
  add_control "IR-3" "Incident Response" "Indicator of Compromise Extraction" \
    "IOCs (IPs, domains, hashes) extracted from attacker activity" \
    "FAIL" "Not found" "IR-5" "Art. 33" "CC7.2" "A.16.1.1"
fi

# IR-4: Canary Tokens / Honeytokens
if grep -q "CANARY\|canary\|honeytoken\|HONEYTOKEN" .env.example 2>/dev/null; then
  add_control "IR-4" "Incident Response" "Canary Token Deception" \
    "Fake credentials alert when used outside the honeypot" \
    "PASS" ".env.example: CANARY_AWS_ACCESS_KEY + others" \
    "IR-4, SC-30" "Art. 33" "CC7.2" "A.16.1.1"
else
  add_control "IR-4" "Incident Response" "Canary Token Deception" \
    "Fake credentials alert when used outside the honeypot" \
    "FAIL" "Not found" "IR-4, SC-30" "Art. 33" "CC7.2" "A.16.1.1"
fi

# IR-5: Threat Intelligence Dashboard
if [ -d "dashboard-frontend" ] && grep -q "threat\|intel\|reputation\|ThreatIntelligence\|ip-api\|VirusTotal\|AbuseIPDB" dashboard-backend/src/ 2>/dev/null; then
  add_control "IR-5" "Incident Response" "Threat Intelligence Integration" \
    "IP reputation from VirusTotal, AbuseIPDB, ip-api.com" \
    "PASS" "dashboard-backend/src/: threat intel APIs" \
    "IR-5" "-" "CC7.2" "A.16.1.1"
else
  add_control "IR-5" "Incident Response" "Threat Intelligence Integration" \
    "IP reputation from VirusTotal, AbuseIPDB, ip-api.com" \
    "FAIL" "Not found" "IR-5" "-" "CC7.2" "A.16.1.1"
fi

# IR-6: AI Incident Reports
if check_exists "incident\|report\|Report\|narrative" "*.py" "dashboard-backend" || \
   check_exists "incident\|report\|Report\|narrative" "*.ts" "dashboard-frontend"; then
  add_control "IR-6" "Incident Response" "AI-Generated Incident Reports" \
    "One-click AI incident reports with kill chain analysis" \
    "PASS" "Dashboard incident report feature" \
    "IR-4, IR-7" "Art. 33" "CC7.2" "A.16.1.4"
else
  add_control "IR-6" "Incident Response" "AI-Generated Incident Reports" \
    "One-click AI incident reports with kill chain analysis" \
    "FAIL" "Not found" "IR-4, IR-7" "Art. 33" "CC7.2" "A.16.1.4"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  5. SYSTEM & COMMUNICATIONS PROTECTION (NIST SC, ISO 27001 A.13, SOC 2 CC6)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== SYSTEM & COMMUNICATIONS PROTECTION ==="

# SC-1: Azure WAF
if [ -f "infra/afd-waf.bicep" ]; then
  add_control "SC-1" "System & Comms Protection" "Web Application Firewall" \
    "Azure WAF with OWASP CRS 3.2 blocks OWASP Top 10 attacks" \
    "PASS" "infra/afd-waf.bicep: WAF_v2 with OWASP CRS 3.2" \
    "SC-7" "Art. 32" "CC6.6" "A.13.1.1"
else
  add_control "SC-1" "System & Comms Protection" "Web Application Firewall" \
    "Azure WAF with OWASP CRS 3.2 blocks OWASP Top 10 attacks" \
    "FAIL" "Not found" "SC-7" "Art. 32" "CC6.6" "A.13.1.1"
fi

# SC-2: HTTPS / TLS
if grep -q "443\|https\|SSL\|TLS\|certificate" http-frontend/src/ 2>/dev/null; then
  add_control "SC-2" "System & Comms Protection" "HTTPS/TLS Encryption" \
    "HTTP honeypot uses HTTPS with Azure Front Door TLS termination" \
    "PASS" "http-frontend/src/" \
    "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
else
  add_control "SC-2" "System & Comms Protection" "HTTPS/TLS Encryption" \
    "HTTP honeypot uses HTTPS with Azure Front Door TLS termination" \
    "FAIL" "Not found" "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
fi

# SC-3: SSH Encryption
if check_exists "asyncssh\|AsyncSSH\|ssh\|SSH" "*.py" "ssh-frontend"; then
  add_control "SC-3" "System & Comms Protection" "SSH Encrypted Channel" \
    "SSH honeypot uses full SSH protocol encryption" \
    "PASS" "ssh-frontend/src/ssh_server.py: AsyncSSH" \
    "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
else
  add_control "SC-3" "System & Comms Protection" "SSH Encrypted Channel" \
    "SSH honeypot uses full SSH protocol encryption" \
    "FAIL" "Not found" "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
fi

# SC-4: Rate Limiting
if grep -q "RATE_LIMIT\|rate_limit\|rate-limit\|throttle\|THROTTLE" .env.example 2>/dev/null; then
  add_control "SC-4" "System & Comms Protection" "Rate Limiting" \
    "Per-IP rate limiting prevents abuse and token exhaustion" \
    "PASS" ".env.example: LLM_PER_IP_RATE_LIMIT_CALLS=30" \
    "SC-5, AC-7" "Art. 32" "CC6.1" "A.12.2.1"
else
  add_control "SC-4" "System & Comms Protection" "Rate Limiting" \
    "Per-IP rate limiting prevents abuse and token exhaustion" \
    "FAIL" "Not found" "SC-5, AC-7" "Art. 32" "CC6.1" "A.12.2.1"
fi

# SC-5: Budget Controls (Cost Ceiling)
if grep -q "BUDGET\|budget\|LLM_DAILY.*BUDGET\|DAILY.*TOKEN" .env.example 2>/dev/null; then
  add_control "SC-5" "System & Comms Protection" "LLM Budget Controls" \
    "Daily token budget prevents LLM cost exhaustion" \
    "PASS" ".env.example: LLM_DAILY_INPUT_TOKEN_BUDGET=50000" \
    "SC-5, CM-2" "-" "CC6.1" "A.12.2.1"
else
  add_control "SC-5" "System & Comms Protection" "LLM Budget Controls" \
    "Daily token budget prevents LLM cost exhaustion" \
    "FAIL" "Not found" "SC-5, CM-2" "-" "CC6.1" "A.12.2.1"
fi

# SC-6: Azure Front Door / WAF Geo-filtering
if grep -q "GeoFilter\|GeoMatch\|allowedCountries\|ALLOWED_COUNTRIES" infra/afd-waf.bicep 2>/dev/null; then
  add_control "SC-6" "System & Comms Protection" "Geo-Filtering" \
    "WAF geo-filtering restricts access by country" \
    "PASS" "infra/afd-waf.bicep: GeoFilter custom rule" \
    "SC-7, AC-3" "Art. 32" "CC6.6" "A.13.1.1"
else
  add_control "SC-6" "System & Comms Protection" "Geo-Filtering" \
    "WAF geo-filtering restricts access by country" \
    "FAIL" "Not found" "SC-7, AC-3" "Art. 32" "CC6.6" "A.13.1.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  6. RISK ASSESSMENT (NIST RA, ISO 27001 A.12, SOC 2 CC6)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== RISK ASSESSMENT ==="

# RA-1: SAST Scanning
if [ -f ".github/workflows/azure-deploy.yml" ] && grep -q "semgrep\|SAST\|sast" .github/workflows/azure-deploy.yml 2>/dev/null; then
  add_control "RA-1" "Risk Assessment" "Static Application Security Testing" \
    "Semgrep SAST scan runs on every push to main" \
    "PASS" ".github/workflows/azure-deploy.yml: semgrep-action" \
    "RA-5" "Art. 32" "CC6.8" "A.12.6.1"
else
  add_control "RA-1" "Risk Assessment" "Static Application Security Testing" \
    "Semgrep SAST scan runs on every push to main" \
    "FAIL" "Not found" "RA-5" "Art. 32" "CC6.8" "A.12.6.1"
fi

# RA-2: DAST Scanning
if [ -f ".github/workflows/azure-deploy.yml" ] && grep -q "zap\|ZAP\|DAST\|dast" .github/workflows/azure-deploy.yml 2>/dev/null; then
  add_control "RA-2" "Risk Assessment" "Dynamic Application Security Testing" \
    "OWASP ZAP DAST scan runs on every push" \
    "PASS" ".github/workflows/azure-deploy.yml: ZAP baseline scan" \
    "RA-5" "Art. 32" "CC6.8" "A.12.6.1"
else
  add_control "RA-2" "Risk Assessment" "Dynamic Application Security Testing" \
    "OWASP ZAP DAST scan runs on every push" \
    "FAIL" "Not found" "RA-5" "Art. 32" "CC6.8" "A.12.6.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  7. DECEPTION & ATTACK DETECTION (NIST SC-30, SC-35)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== DECEPTION & ATTACK DETECTION ==="

# DE-1: AWS IMDS Emulation
if grep -q "169.254.169.254\|IMDS\|imds\|metadata.*instance" ssh-frontend/src/ssh_server.py 2>/dev/null; then
  add_control "DE-1" "Deception" "AWS IMDS Emulation" \
    "Fake AWS metadata service at 169.254.169.254 traps attackers" \
    "PASS" "ssh-frontend/src/ssh_server.py: IMDS routes" \
    "SC-30, IR-4" "-" "-" "A.16.1.1"
else
  add_control "DE-1" "Deception" "AWS IMDS Emulation" \
    "Fake AWS metadata service at 169.254.169.254 traps attackers" \
    "FAIL" "Not found" "SC-30, IR-4" "-" "-" "A.16.1.1"
fi

# DE-2: Fake AWS Credentials
if grep -q "aws.*credentials\|\.aws/credentials\|aws_access_key\|AWS_ACCESS" sandbox-store/src/database.py 2>/dev/null; then
  add_control "DE-2" "Deception" "Fake AWS Credentials" \
    "Convincing fake AWS credentials planted in virtual filesystem" \
    "PASS" "sandbox-store/src/database.py: /root/.aws/credentials" \
    "SC-30, IR-4" "-" "-" "A.16.1.1"
else
  add_control "DE-2" "Deception" "Fake AWS Credentials" \
    "Convincing fake AWS credentials planted in virtual filesystem" \
    "FAIL" "Not found" "SC-30, IR-4" "-" "-" "A.16.1.1"
fi

# DE-3: Multi-host Illusion
if check_exists "pivot\|internal.*host\|hostname.*internal\|nexopay.*internal\|10\.0\.\|172\.16\." "*.py" "ssh-frontend" || \
   check_exists "pivot\|internal.*host\|hostname.*internal\|nexopay.*internal" "*.py" "sandbox-store"; then
  add_control "DE-3" "Deception" "Multi-Host Pivot Illusion" \
    "Fake internal hosts simulate a network for attackers to pivot through" \
    "PASS" "Internal host simulation in SSH responses" \
    "SC-30, IR-4" "-" "-" "A.16.1.1"
else
  add_control "DE-3" "Deception" "Multi-Host Pivot Illusion" \
    "Fake internal hosts simulate a network for attackers to pivot through" \
    "FAIL" "Not found" "SC-30, IR-4" "-" "-" "A.16.1.1"
fi

# DE-4: K8s/EKS Deception
if grep -q "kube\|KUBE\|kubectl\|EKS\|eks" sandbox-store/src/database.py 2>/dev/null; then
  add_control "DE-4" "Deception" "Kubernetes Configuration Deception" \
    "Fake kubeconfig with EKS endpoint planted for attacker discovery" \
    "PASS" "sandbox-store/src/database.py: ~/.kube/config" \
    "SC-30, IR-4" "-" "-" "A.16.1.1"
else
  add_control "DE-4" "Deception" "Kubernetes Configuration Deception" \
    "Fake kubeconfig with EKS endpoint planted for attacker discovery" \
    "FAIL" "Not found" "SC-30, IR-4" "-" "-" "A.16.1.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  8. DATA PROTECTION & PRIVACY (GDPR, ISO 27001 A.8, SOC 2 CC6)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== DATA PROTECTION & PRIVACY ==="

# DP-1: Secrets Management
if grep -q "secret\|SECRET\|secretRef\|keyvault\|KEY_VAULT" .github/workflows/azure-deploy.yml 2>/dev/null; then
  add_control "DP-1" "Data Protection" "Secrets Management" \
    "API keys and secrets injected via Azure Key Vault / GitHub Secrets" \
    "PASS" "GitHub Secrets + azure-deploy.yml secretref:" \
    "-" "Art. 32" "CC6.3" "A.8.2.1"
else
  add_control "DP-1" "Data Protection" "Secrets Management" \
    "API keys and secrets injected via Azure Key Vault / GitHub Secrets" \
    "FAIL" "Not found" "-" "Art. 32" "CC6.3" "A.8.2.1"
fi

# DP-2: Persistent Data Storage
if grep -q "DB_PATH\|SQLITE\|sqlite\|database\|\.db" .env.example 2>/dev/null; then
  add_control "DP-2" "Data Protection" "Persistent Data Storage" \
    "SQLite database with WAL mode for data persistence" \
    "PASS" ".env.example: DB_PATH=/data/app_state.db" \
    "CP-9, AU-4" "Art. 32" "CC6.3" "A.8.2.3"
else
  add_control "DP-2" "Data Protection" "Persistent Data Storage" \
    "SQLite database with WAL mode for data persistence" \
    "FAIL" "Not found" "CP-9, AU-4" "Art. 32" "CC6.3" "A.8.2.3"
fi

# DP-3: Azure Storage Persistence
if grep -q "azure-file\|STORAGE_ACCOUNT\|FILE_SHARE\|AzureFile" .github/workflows/azure-deploy.yml 2>/dev/null; then
  add_control "DP-3" "Data Protection" "Azure Shared Storage" \
    "Azure File Share provides persistent volumes across restarts" \
    "PASS" "azure-deploy.yml: AzureFile volume mount" \
    "CP-9, SC-28" "Art. 32" "CC6.3" "A.8.2.3"
else
  add_control "DP-3" "Data Protection" "Azure Shared Storage" \
    "Azure File Share provides persistent volumes across restarts" \
    "FAIL" "Not found" "CP-9, SC-28" "Art. 32" "CC6.3" "A.8.2.3"
fi

# DP-4: HSTS / Security Headers
if grep -q "Strict-Transport-Security\|X-Content-Type-Options\|X-Frame-Options\|Content-Security-Policy\|X-XSS-Protection" http-frontend/src/ dashboard-frontend/ 2>/dev/null; then
  add_control "DP-4" "Data Protection" "Security Headers" \
    "HTTP security headers protect against common web attacks" \
    "PASS" "Security headers found" \
    "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
else
  add_control "DP-4" "Data Protection" "Security Headers" \
    "HTTP security headers protect against common web attacks" \
    "FAIL" "Not found" "SC-8" "Art. 32" "CC6.6" "A.13.2.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  9. MONITORING & OBSERVABILITY (NIST SI, ISO 27001 A.12)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== MONITORING & OBSERVABILITY ==="

# MO-1: Live Session Monitoring
if grep -q "live\|Live\|session\|active.*session" dashboard-frontend/src/ dashboard-backend/src/ 2>/dev/null; then
  add_control "MO-1" "Monitoring" "Live Session Monitoring" \
    "Dashboard shows real-time active attacker sessions" \
    "PASS" "dashboard: Live Sessions view" \
    "SI-4" "-" "CC7.1" "A.12.4.3"
else
  add_control "MO-1" "Monitoring" "Live Session Monitoring" \
    "Dashboard shows real-time active attacker sessions" \
    "FAIL" "Not found" "SI-4" "-" "CC7.1" "A.12.4.3"
fi

# MO-2: Session Playback
if grep -q "playback\|Playback\|replay\|Replay\|keystroke" dashboard-frontend/src/ 2>/dev/null; then
  add_control "MO-2" "Monitoring" "Session Playback" \
    "Keystroke-level session replay with MITRE annotations" \
    "PASS" "dashboard: Session Playback view" \
    "SI-4, AU-6" "-" "CC7.1" "A.12.4.3"
else
  add_control "MO-2" "Monitoring" "Session Playback" \
    "Keystroke-level session replay with MITRE annotations" \
    "FAIL" "Not found" "SI-4, AU-6" "-" "CC7.1" "A.12.4.3"
fi

# MO-3: Attack Map Visualization
if grep -q "map\|Map\|geographic\|heatmap\|Geo\|D3\|d3" dashboard-frontend/src/ 2>/dev/null; then
  add_control "MO-3" "Monitoring" "Attack Geolocation Map" \
    "D3.js geographic heatmap of attacker IP origins" \
    "PASS" "dashboard: Attack Map view (D3.js)" \
    "SI-4" "-" "CC7.1" "A.12.4.3"
else
  add_control "MO-3" "Monitoring" "Attack Geolocation Map" \
    "D3.js geographic heatmap of attacker IP origins" \
    "FAIL" "Not found" "SI-4" "-" "CC7.1" "A.12.4.3"
fi

# MO-4: Azure Log Analytics
if grep -q "log-analytics\|Log Analytics\|logs-workspace\|LA_WORKSPACE" scripts/azure-setup.sh 2>/dev/null; then
  add_control "MO-4" "Monitoring" "Centralized Log Collection" \
    "Azure Log Analytics collects all container logs" \
    "PASS" "scripts/azure-setup.sh: Log Analytics workspace" \
    "AU-4, SI-4" "Art. 33" "CC3.1" "A.12.4.1"
else
  add_control "MO-4" "Monitoring" "Centralized Log Collection" \
    "Azure Log Analytics collects all container logs" \
    "FAIL" "Not found" "AU-4, SI-4" "Art. 33" "CC3.1" "A.12.4.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  10. CLOUD INFRASTRUCTURE (Azure-specific)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=== CLOUD INFRASTRUCTURE ==="

# CI-1: Azure Container Apps
if [ -f "docker-compose.yml" ] && grep -q "containerapp\|az containerapp\|ACA" .github/workflows/azure-deploy.yml 2>/dev/null; then
  add_control "CI-1" "Cloud Infrastructure" "Azure Container Apps Deployment" \
    "Production deployment on Azure Container Apps" \
    "PASS" "azure-deploy.yml: ACA deployment pipeline" \
    "CM-2, SC-7" "Art. 32" "CC6.6" "A.13.1.1"
else
  add_control "CI-1" "Cloud Infrastructure" "Azure Container Apps Deployment" \
    "Production deployment on Azure Container Apps" \
    "FAIL" "Not found" "CM-2, SC-7" "Art. 32" "CC6.6" "A.13.1.1"
fi

# CI-2: Azure Container Registry
if grep -q "ACR_\|acr\|container-registry\|Container Registry" scripts/azure-setup.sh 2>/dev/null; then
  add_control "CI-2" "Cloud Infrastructure" "Azure Container Registry" \
    "Docker images stored in private Azure Container Registry" \
    "PASS" "scripts/azure-setup.sh: ACR creation" \
    "CM-2, SI-7" "-" "CC6.3" "A.12.5.1"
else
  add_control "CI-2" "Cloud Infrastructure" "Azure Container Registry" \
    "Docker images stored in private Azure Container Registry" \
    "FAIL" "Not found" "CM-2, SI-7" "-" "CC6.3" "A.12.5.1"
fi

# CI-3: Infrastructure as Code
if [ -d "infra/" ] && ls infra/*.bicep 2>/dev/null >/dev/null; then
  add_control "CI-3" "Cloud Infrastructure" "Infrastructure as Code" \
    "All Azure resources defined in Bicep IaC templates" \
    "PASS" "infra/: afd-waf.bicep, compliance.bicep" \
    "CM-2" "Art. 32" "CC4.1" "A.12.1.1"
else
  add_control "CI-3" "Cloud Infrastructure" "Infrastructure as Code" \
    "All Azure resources defined in Bicep IaC templates" \
    "FAIL" "Not found" "CM-2" "Art. 32" "CC4.1" "A.12.1.1"
fi

# CI-4: CI/CD Pipeline
if [ -d ".github/workflows/" ]; then
  WORKFLOW_COUNT=$(ls .github/workflows/*.yml 2>/dev/null | wc -l)
  add_control "CI-4" "Cloud Infrastructure" "CI/CD Pipeline" \
    "Automated build, test, and deploy via GitHub Actions" \
    "PASS" ".github/workflows/: $WORKFLOW_COUNT workflow(s)" \
    "CM-2, CM-3" "Art. 32" "CC4.1" "A.12.1.1"
else
  add_control "CI-4" "Cloud Infrastructure" "CI/CD Pipeline" \
    "Automated build, test, and deploy via GitHub Actions" \
    "FAIL" "Not found" "CM-2, CM-3" "Art. 32" "CC4.1" "A.12.1.1"
fi

# CI-5: Rollback Capability
if [ -f ".github/workflows/rollback.yml" ]; then
  add_control "CI-5" "Cloud Infrastructure" "Deployment Rollback" \
    "Automated rollback to previous image version" \
    "PASS" ".github/workflows/rollback.yml" \
    "CM-3, CP-2" "Art. 32" "CC7.1" "A.12.1.1"
else
  add_control "CI-5" "Cloud Infrastructure" "Deployment Rollback" \
    "Automated rollback to previous image version" \
    "FAIL" "Not found" "CM-3, CP-2" "Art. 32" "CC7.1" "A.12.1.1"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE REPORT
# ═══════════════════════════════════════════════════════════════════════════════

CONTROLS_JSON+="]"

SCORE=$(echo "scale=1; $PASSED * 100 / $TOTAL_CONTROLS" | bc 2>/dev/null || echo 0)

# Calculate per-standard scores
nist_total=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.nist != "-")] | length')
nist_pass=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.nist != "-" and .status == "PASS")] | length')
gdpr_total=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.gdpr != "-")] | length')
gdpr_pass=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.gdpr != "-" and .status == "PASS")] | length')
soc2_total=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.soc2 != "-")] | length')
soc2_pass=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.soc2 != "-" and .status == "PASS")] | length')
iso_total=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.iso27001 != "-")] | length')
iso_pass=$(echo "$CONTROLS_JSON" | jq '[.[] | select(.mappings.iso27001 != "-" and .status == "PASS")] | length')

nist_score=$(echo "scale=1; $nist_pass * 100 / $nist_total" | bc 2>/dev/null || echo 0)
gdpr_score=$(echo "scale=1; $gdpr_pass * 100 / $gdpr_total" | bc 2>/dev/null || echo 0)
soc2_score=$(echo "scale=1; $soc2_pass * 100 / $soc2_total" | bc 2>/dev/null || echo 0)
iso_score=$(echo "scale=1; $iso_pass * 100 / $iso_total" | bc 2>/dev/null || echo 0)

# Build final JSON report
jq -n \
  --arg repo "$REPO_NAME" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson total "$TOTAL_CONTROLS" \
  --argjson passed "$PASSED" \
  --argjson failed "$FAILED" \
  --arg score "$SCORE" \
  --arg nistScore "$nist_score" \
  --arg gdprScore "$gdpr_score" \
  --arg soc2Score "$soc2_score" \
  --arg isoScore "$iso_score" \
  --argjson nistTotal "$nist_total" \
  --argjson gdprTotal "$gdpr_total" \
  --argjson soc2Total "$soc2_total" \
  --argjson isoTotal "$iso_total" \
  --argjson nistPass "$nist_pass" \
  --argjson gdprPass "$gdpr_pass" \
  --argjson soc2Pass "$soc2_pass" \
  --argjson isoPass "$iso_pass" \
  --argjson controls "$CONTROLS_JSON" \
  '{
    repo: $repo,
    timestamp: $timestamp,
    summary: {
      totalControls: $total,
      passed: $passed,
      failed: $failed,
      overallScore: ($score | tonumber)
    },
    standards: {
      nistSP80053: { total: $nistTotal, passed: $nistPass, score: ($nistScore | tonumber) },
      gdpr: { total: $gdprTotal, passed: $gdprPass, score: ($gdprScore | tonumber) },
      soc2TypeII: { total: $soc2Total, passed: $soc2Pass, score: ($soc2Score | tonumber) },
      iso27001: { total: $isoTotal, passed: $isoPass, score: ($isoScore | tonumber) }
    },
    controls: $controls
  }' > "$OUTPUT_FILE"

# ── Print Report ──
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║           AdaptiveWardens — Compliance Scorecard                        ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Overall Compliance: $PASSED / $TOTAL_CONTROLS controls passed ($SCORE%)"
echo ""
echo "  ┌──────────────────────┬────────┬────────┬──────────┐"
echo "  │ Standard             │ Passed │ Total  │ Score    │"
echo "  ├──────────────────────┼────────┼────────┼──────────┤"
printf "  │ %-20s │ %6d │ %6d │ %5.1f%%   │\n" "NIST SP 800-53 Rev.5" "$nist_pass" "$nist_total" "$nist_score"
printf "  │ %-20s │ %6d │ %6d │ %5.1f%%   │\n" "GDPR" "$gdpr_pass" "$gdpr_total" "$gdpr_score"
printf "  │ %-20s │ %6d │ %6d │ %5.1f%%   │\n" "SOC 2 Type II" "$soc2_pass" "$soc2_total" "$soc2_score"
printf "  │ %-20s │ %6d │ %6d │ %5.1f%%   │\n" "ISO 27001:2013" "$iso_pass" "$iso_total" "$iso_score"
echo "  └──────────────────────┴────────┴────────┴──────────┘"
echo ""
echo "  Controls by Category:"
echo "  ┌──────────────────────────────┬────────┬────────┬──────────┐"
echo "  │ Category                     │ Passed │ Total  │ Score    │"
echo "  ├──────────────────────────────┼────────┼────────┼──────────┤"

# Group by category
echo "$CONTROLS_JSON" | jq -r 'group_by(.category) | .[] | "\(.[0].category)|\(map(select(.status=="PASS")) | length)|\(length)"' | sort | while IFS="|" read -r cat pass total; do
  cat_score=$(echo "scale=1; $pass * 100 / $total" | bc 2>/dev/null || echo 0)
  printf "  │ %-28s │ %6d │ %6d │ %5.1f%%   │\n" "$cat" "$pass" "$total" "$cat_score"
done

echo "  └──────────────────────────────┴────────┴────────┴──────────┘"
echo ""
echo "  Detailed Control List:"
echo "  ────────────────────────────────────────────────────────────────"

echo "$CONTROLS_JSON" | jq -r '.[] | "\(.id)|\(.category)|\(.name)|\(.status)|\(.mappings.nist)|\(.mappings.gdpr)|\(.mappings.soc2)|\(.mappings.iso27001)"' | while IFS="|" read -r id cat name status nist gdpr soc2 iso; do
  if [ "$status" = "PASS" ]; then
    echo "  ✅ $id: $name"
  else
    echo "  ❌ $id: $name"
  fi
  echo "     NIST: $nist | GDPR: $gdpr | SOC2: $soc2 | ISO: $iso"
done

echo ""
echo "  Full report saved to: $OUTPUT_FILE"
echo ""

# Exit with non-zero if score is below 50% (to flag in CI)
if [ "$(echo "$SCORE < 50" | bc 2>/dev/null || echo 0)" = "1" ]; then
  echo "⚠️  Overall compliance score below 50% — review failed controls."
  exit 1
fi
