# AdaptiveWardens Service Level Agreement (SLA) & Reliability

## Availability Target
AdaptiveWardens aims for a **99.9% uptime** strictly regarding the honeypot attack-surface logic.
- The `ssh-frontend` listener relies entirely on native network throughputs to sustain 24/7 availability.

## Latency Expectations
1. **Static Commands (`cd`, `pwd`, `ls`)**: < 50ms inside the internal API loop. 
2. **AI-Generated Commands (`wget`, `curl`, custom scripts)**: 1,500ms - 4,000ms latency limits. 
   - Note: Realistic command latency ensures higher fidelity, as commands like `wget` naturally take several seconds on live servers.
3. **Database Transactions**: Operations queue instantly via SQLite WAL architecture (<10ms execution).

## Behavior Under Failure
- **Gemini AI Outage**: If the primary LLM provider (Google Gemini) becomes inaccessible, rate-limited, or explicitly times out (15-second cap), the `ai-engine` degrades gracefully natively returning static fallback strings (e.g. `bash: command not found`). The attacker is never exposed to an architectural error.
- **Service Crashing**: The container layer (`docker-compose`) includes `restart: unless-stopped`. A crashed container automatically resurrects via health-check routines within 10-15 seconds. Wait states exist in the HTTP pipelines to naturally rebound API calls during recovery.
