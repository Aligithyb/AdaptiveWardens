# AdaptiveWardens

**An AI-driven, high-interaction honeypot that turns every attacker session into structured threat intelligence.**

AdaptiveWardens emulates a compromised Ubuntu 22.04 production server for a fictitious payments company ("NexoPay") and transforms every attacker connection into a complete SOC artefact: command transcripts, extracted IOCs, MITRE ATT&CK technique mappings, IP reputation scores, risk-scored one-click AI incident reports, and firewall-ready blocklists.

Unknown commands are answered by a tightly-budgeted LLM backend (DeepSeek by default) wrapped in deterministic short-circuits, a multi-layer SQLite cache, and a daily token ceiling — so a noisy attacker never blows up your bill. Novel commands that slip past the static MITRE regex rules are silently classified by the same LLM and cached globally, so the second attacker to run `echo cmV2ZXJzZQ== | base64 -d | bash` costs zero tokens.

---

## Highlights

- **Realistic SSH frontend.** AsyncSSH-backed PTY with a line editor that mirrors bash readline behaviour — arrow-key history, Ctrl-C / Ctrl-D / Ctrl-L, longest-common-prefix Tab completion, bare-name cwd completion, and persistent boot time / host key matched to Ubuntu 22.04 OpenSSH 8.9p1 algorithm sets.
- **Tiered response engine.** Three layers in priority order: (1) deterministic short-circuits for cheap, repetitive commands; (2) a SQLite-backed response cache with command-scoped keys and per-command TTLs; (3) the LLM as a last resort. Cache keys are normalised so `ls -la`, `ls -al`, and `ls -a -l` collide on one row.
- **Hybrid AI MITRE mapping.** Static regex rules (170+ patterns) cover the known playbook. When they miss — obfuscated payloads, novel tooling, encoded pipelines — the LLM classifies the command against MITRE ATT&CK v15 and the result is cached globally with no TTL. The second attacker to run the same novel command costs zero tokens.
- **One-click AI incident reports.** The Reports tab generates a full SOC narrative for any session in one click: executive summary, attacker objective, kill-chain ordered by tactic, notable IOCs, severity justification, and recommended remediation actions. Reports are cached by session content hash so re-clicking an unchanged closed session is instant and free. Results embed into the existing PDF export.
- **Threat Intelligence section.** A dedicated dashboard view enriches every unique attacker IP with VirusTotal reputation (engine breakdown), AbuseIPDB abuse score, and ASN / hosting-type detection (datacenter, Tor exit, VPN, ISP) from ip-api.com. All three sources are cached with per-source TTLs. Cross-session repeat-attacker correlation and a one-click firewall blocklist export are built in.
- **Hard cost ceiling.** A daily UTC token budget persisted to disk and a per-IP sliding-window rate limit. When either fires, all AI paths fall back to deterministic output — sessions stay alive and the bill stays flat.
- **Layered deception.** AWS IMDS (`169.254.169.254`) emulated end-to-end with canarytoken-bearing credentials. Multi-host illusion lets attackers `ssh` between `api-prod-01`, `db-primary`, and `cache-01` with distinct fingerprints. Story-consistency keeps running services, paths, and config files coherent across responses.
- **HTTP honeypot.** A second front-door on port 8080 captures opportunistic web scanning alongside SSH.
- **Slack alerts** with country-resolved attacker IPs out of the box.

---

## Architecture

```
                                      ┌───────────────────┐
       attacker ──SSH:2222──▶   ssh-frontend               │
       attacker ──HTTP:8080──▶  http-frontend ──────┐      │
                                      │             │      │
                                      ▼             ▼      │
                                ┌───────────┐  ┌──────────────┐
                                │ ai-engine │  │sandbox-store │
                                │           │  │              │
                                │ • tier-1  │  │ • sessions   │
                                │   determ. │  │ • commands   │
                                │ • cache   │  │ • IOCs       │
                                │ • LLM     │  │ • MITRE      │
                                │ • MITRE   │  │ • virtual FS │
                                │   hybrid  │  └──────────────┘
                                │ • reports │        ▲
                                └───────────┘        │
                                      ▲              │
                                      │         ┌────────────────┐
                                 DeepSeek       │dashboard-backend│
                                               │                │
                              VirusTotal ──────┤ • analytics    │
                              AbuseIPDB  ──────┤ • TI enrichment│
                              ip-api.com ──────┤ • AI reports   │
                                               │ • blocklist    │
                                               └────────────────┘
                                                       │
                                                       ▼
                                              dashboard-frontend
                                              (SOC analyst)
```

| Service              | Container            | Port | Role                                                                         |
|----------------------|----------------------|------|------------------------------------------------------------------------------|
| `ssh-frontend`       | auth-gateway         | 2222 | AsyncSSH honeypot, PTY line editor, per-attacker session state               |
| `http-frontend`      | web-gateway          | 8080 | HTTP honeypot for opportunistic scanners                                     |
| `ai-engine`          | inference-svc        | 8002 | Deterministic + cache + LLM tiers, budget gate, IOC extraction, MITRE hybrid, AI reports |
| `sandbox-store`      | app-state-store      | 8001 | SQLite-backed persistence, virtual filesystem, geo/IP enrichment             |
| `dashboard-backend`  | dashboard-backend    | 8003 | Aggregation API, threat intel enrichment, AI report generation               |
| `dashboard-frontend` | soc-dashboard        | 3000 | Next.js SOC console                                                          |

Two Docker networks isolate the blast radius:

- `prod-internal` — `internal: true`. Sandbox, AI engine, and dashboard-backend can only reach each other here.
- `dmz` — bridges public-facing front-ends and outbound traffic to DeepSeek / VirusTotal / AbuseIPDB / Slack / canarytokens.

See [`docs/architecture.md`](docs/architecture.md) for a full breakdown of service contracts, statelessness model, and trade-offs.

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/Aligithyb/AdaptiveWardens.git
cd AdaptiveWardens
```

### 2. Configure

```bash
cp .env.example .env
```

Minimum required edits in `.env`:

| Variable              | Where to get it                                           |
|-----------------------|-----------------------------------------------------------|
| `DEEPSEEK_API_KEY`    | https://platform.deepseek.com/api_keys                    |
| `VIRUSTOTAL_API_KEY`  | https://www.virustotal.com/gui/my-apikey (free tier)      |
| `ABUSEIPDB_API_KEY`   | https://www.abuseipdb.com/account/api (free tier)         |
| `SLACK_WEBHOOK_URL`   | Optional — see [Slack alerts](#slack-alerts)              |
| `CANARY_*`            | Optional — see [Deception layer](#deception-layer)        |

The platform works without the threat intel keys — VirusTotal and AbuseIPDB columns simply show `—` in the dashboard until keys are added.

### 3. Launch

```bash
./start.sh
```

Containers come up healthy in roughly 15–20 seconds. Verify:

```bash
docker compose ps
curl -s http://localhost:8002/health      # ai-engine
curl -s http://localhost:8001/health      # sandbox-store
curl -s http://localhost:8003/health      # dashboard-backend
ssh -p 2222 root@localhost                # any password works
```

Open the dashboard at <http://localhost:3000>.

---

## Configuration

The full configuration surface lives in `.env.example`. Variables you are most likely to tune:

### AI engine

| Variable                         | Default                      | Purpose                                                            |
|----------------------------------|------------------------------|--------------------------------------------------------------------|
| `DEEPSEEK_API_KEY`               | _required_                   | DeepSeek API credential.                                           |
| `DEEPSEEK_MODEL`                 | `deepseek-v4-flash`          | Override to point at a different model.                            |
| `DEEPSEEK_BASE_URL`              | `https://api.deepseek.com`   | Override for a self-hosted OpenAI-compatible endpoint.             |
| `LLM_DAILY_INPUT_TOKEN_BUDGET`   | `50000`                      | Hard daily ceiling on uncached input tokens. Resets at 00:00 UTC. |
| `LLM_DAILY_OUTPUT_TOKEN_BUDGET`  | `20000`                      | Hard daily ceiling on output tokens.                               |
| `LLM_PER_IP_RATE_LIMIT_CALLS`    | `30`                         | LLM calls allowed per attacker IP per window.                      |
| `LLM_PER_IP_RATE_LIMIT_WINDOW`   | `60`                         | Rate-limit window in seconds.                                      |

### Threat Intelligence

| Variable              | Default | Purpose                                                                    |
|-----------------------|---------|----------------------------------------------------------------------------|
| `VIRUSTOTAL_API_KEY`  | `""`    | VirusTotal free tier: 4 req/min, 500/day. Cache keeps usage well below limits. |
| `ABUSEIPDB_API_KEY`   | `""`    | AbuseIPDB free tier: 1000 checks/day. Cache makes this a non-issue.       |

### Honeypot session

| Variable               | Default | Purpose                                                |
|------------------------|---------|--------------------------------------------------------|
| `MAX_SESSIONS`         | `50`    | Concurrent SSH session ceiling.                        |
| `SESSION_TIMEOUT`      | `1800`  | Idle session timeout in seconds.                       |
| `ENABLE_RATE_LIMITING` | `true`  | Per-IP connection throttling at the SSH layer.         |

### Storage

| Variable          | Default              | Purpose                            |
|-------------------|----------------------|------------------------------------|
| `DB_PATH`         | `/data/app_state.db` | Sandbox-store SQLite location.     |
| `SQLITE_TIMEOUT`  | `30`                 | Per-statement busy timeout, secs.  |

---

## Dashboard

Available at <http://localhost:3000>. Eight views are accessible from the sidebar:

### Live Sessions
Real-time table of active SSH and HTTP attacker connections with country, protocol, risk score, and command count. Rows update every 5 seconds. Click any row to open the Session Playback panel below.

### Session Playback
Full keystroke-level replay of any selected session. Commands are displayed in sequence with per-command annotations for matched MITRE techniques, extracted IOCs, and suspicious-command flags.

### Attack Map
Geographic heatmap of inbound attacker IPs using a D3.js world map with zoom and pan. Country-level attack counts are colour-coded by intensity.

### IOC Summary
All Indicators of Compromise extracted from attacker commands and AI responses — IPs, domains, URLs, MD5/SHA256 hashes, file paths, SSH public keys, and triggered honeytokens. Filterable by type and confidence level.

### MITRE ATT&CK
Interactive technique grid showing detected MITRE ATT&CK techniques grouped by tactic. Detection counts and confidence scores drive colour intensity. Click a technique for the full detail panel and the commands that triggered it.

### Session Metrics
Aggregated statistics across all sessions: risk distribution, top source countries, top usernames and passwords attempted, protocol breakdown, and average session duration.

### Reports
Per-session export panel with four actions per row:

| Button | Output |
|--------|--------|
| **JSON** | Full session dump — commands, IOCs, techniques (download) |
| **CSV** | Command history with timestamps and exit codes (download) |
| **PDF** | Print-formatted HTML report via browser print dialog |
| **✨ AI Report** | One-click SOC incident report — see below |

**AI Incident Report** — clicking the sparkle icon sends the session's full structured data to the AI engine and returns a six-section analyst narrative:

1. **Executive Summary** — 2–3 sentences for management
2. **Attacker Objective** — inferred intent (reconnaissance, credential theft, persistence, etc.)
3. **Kill Chain** — tactics observed in attack-chain order with technique details
4. **Notable IOCs** — the most actionable indicators with significance notes
5. **Severity Justification** — evidence-backed explanation of the risk level
6. **Recommended Actions** — concrete defensive steps (block IP, rotate credentials, patch CVE, etc.)

Reports are cached by session content hash — re-clicking an unchanged closed session is instant. The AI summary is embedded into the PDF when saving.

### Threat Intelligence
Dedicated view that enriches every unique attacker IP with data from three sources:

**IP Intelligence table** — one row per unique attacker IP, sorted confirmed-malicious-first:

| Column | Source | Details |
|--------|--------|---------|
| Hosting type | ip-api.com | `Datacenter`, `Tor Exit`, `VPN/Proxy`, `ISP`, `Mobile ISP` |
| VT Score | VirusTotal | `12/91` — malicious/total engine count |
| Abuse % | AbuseIPDB | Confidence score with colour-coded progress badge |
| Sessions | Internal DB | Count of all sessions from this IP |

**IP Detail panel** — click any row to open a side panel with three tabs:
- **VirusTotal** — per-category engine counts (malicious / suspicious / harmless / undetected), tags, last analysis date, ASN / AS owner, VT reputation score
- **AbuseIPDB** — abuse confidence bar, total report count, distinct users, ISP, usage type, last reported timestamp
- **Session History** — full table of all sessions from this IP with risk levels, technique counts, and timestamps

**Blocklist export** — the "Blocklist" button in the toolbar downloads a plain-text file of all IPs where VT detections > 0 or AbuseIPDB confidence ≥ 50%, formatted for direct use with `iptables`, `ufw`, `firewalld`, or CIDR block lists.

All threat intelligence results are cached with per-source TTLs (24 h for VT and AbuseIPDB, 7 days for ip-api.com) in the shared SQLite database, so free-tier rate limits are never a concern in practice.

---

## AI Features in Depth

### Hybrid MITRE ATT&CK Mapping

Every command a honeypot attacker runs is classified against MITRE ATT&CK. The classification runs in two tiers:

1. **Regex tier** (`ai-engine/src/mitre.py`) — 170+ compiled patterns covering the known attacker playbook from Reconnaissance through Impact. Instant, free, high-confidence.
2. **LLM tier** (`ai-engine/src/mitre_ai.py`) — when the regex tier returns nothing (novel tools, obfuscated pipelines, encoded payloads), the LLM classifies the command against ATT&CK v15 and returns a JSON array of `{technique_id, technique_name, tactic, confidence, evidence}`. The result is written to a **global, no-TTL** `mitre_cache` table so the next attacker to run the same command pays nothing.

Budget and rate limits apply to tier-2 calls the same as shell-response calls. If the daily budget is exhausted, classification silently falls back to regex-only — no session is disrupted.

### One-Click AI Reports

Reports are generated by `ai-engine/src/report.py` via `POST /summarize-session`. The system prompt is tuned for a senior SOC analyst persona and requests structured JSON output with the six report keys. A deterministic fallback assembles the same structure from counts and tactic lists when the LLM is unavailable, so the button always returns something useful.

`dashboard-backend` caches the report in an `ai_reports` table keyed by `(session_id, content_hash)`. The content hash is an MD5 of the combined commands + techniques + IOCs JSON, so open/growing sessions get a fresh report when their data changes, while closed sessions serve instantly from cache.

---

## Cost and Budget Controls

Operating cost is dominated by LLM calls. AdaptiveWardens minimises this in four layers:

1. **Deterministic short-circuit** for the ~30 most common reconnaissance commands (`whoami`, `id`, `pwd`, `uname`, `echo …`, etc.). Free, instant, no tokens.
2. **Response cache** keyed by normalised command + scope (global / per-user / per-cwd) with per-command TTLs. Persisted to `/data/ai_cache.db` so container restarts don't trigger a cold-cache burst. Cached IOCs and MITRE results travel with the response so cache hits skip the extractor pass.
3. **MITRE classification cache** — global, no TTL. Novel command classifications are written once and served forever. The `mitre_cache` table in `ai_cache.db` is shared across all attacker IPs.
4. **DeepSeek prefix cache** — the system prompt is a module-level constant so DeepSeek's server-side prefix caching applies. Cached input tokens are ~50× cheaper than uncached.

On top of that, a **daily token budget** (persisted to `/data/llm_budget.db`) and a **per-IP sliding-window rate limit** form a circuit breaker. When either fires, all AI paths serve deterministic / static output for the rest of the UTC day — sessions stay open and the bill stays flat.

Indicative cost at default settings:

| Scenario                                   | Monthly LLM spend |
|--------------------------------------------|-------------------|
| Default budget ceilings, all caches warm   | ~$0.10            |
| Default ceilings, worst-case cold caches   | ~$0.40            |
| 10 k uncached attacker commands / month    | ~$0.35            |
| Hosting (Lightsail / EC2 t4g.small)        | $5 – $13          |

See [`docs/cost.md`](docs/cost.md) for the line-item breakdown.

---

## Observability

```bash
# Liveness
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health

# Shell response cache (hit rate, mitre cache hit rate)
curl http://localhost:8002/cache/stats
# → { "hits": 8421, "misses": 312, "bypassed": 78, "stores": 312,
#     "hit_rate": 0.96, "mitre_hits": 540, "mitre_misses": 38,
#     "mitre_hit_rate": 0.93 }

# Daily LLM spend + per-IP rate limiter
curl http://localhost:8002/budget/stats
# → { "budget": { "day_utc": "...", "input_tokens": 1234, "output_tokens": 412,
#                 "input_remaining": 48766, "output_remaining": 19588,
#                 "exhausted": false, "calls": 18, "blocked": 0 },
#     "rate_limit": { "tracked_ips": 4, "allowed": 18, "blocked": 0,
#                     "calls_per_window": 30, "window_seconds": 60 } }

# Threat intelligence cache contents
sqlite3 /var/lib/docker/volumes/adaptivewardens_sandbox-data/_data/app_state.db \
  "SELECT ioc_value, source_api, cached_at, expires_at FROM threat_intel_cache LIMIT 20;"
```

The dashboard surfaces the same data graphically; the endpoints exist so you can wire external alerts (e.g. PagerDuty when `budget.exhausted == true`).

---

## Deception Layer

### Canarytokens

Generate real tokens at <https://canarytokens.org/generate> and paste them into `.env`. When an attacker uses any of these credentials anywhere on the internet — not just inside the honeypot — canarytokens.org alerts you with their real source IP.

| Variable | Token type | Where it surfaces |
|----------|-----------|-------------------|
| `CANARY_AWS_ACCESS_KEY` / `CANARY_AWS_SECRET_KEY` | AWS Keys | `~/.aws/credentials`, IMDS responses, env vars |
| `CANARY_STRIPE_KEY` | Stripe Key | `/opt/nexopay/config/stripe.env` |
| `CANARY_DNS_HOSTNAME` | DNS | Referenced by `~/.bashrc`, surfaces in `nslookup` / `dig` |

If any are left blank, convincing-looking static values are used instead — alerts won't fire but the deception is intact.

### IMDS Emulation

The classic AWS Instance Metadata Service at `http://169.254.169.254/latest/meta-data/` is fully emulated, including IAM role credentials backed by your canary keys. Cloud enumeration scripts that scrape IMDS for lateral movement hit a live, instrumented target.

### Multi-Host Illusion

Three internal hosts respond to `ssh` from inside the honeypot — `api-prod-01`, `db-primary.nexopay.internal`, and `cache-01.nexopay.internal` — each with distinct host keys, banners, and process listings. Attackers can pivot between them; the dashboard records every hop.

### SSH Fingerprint Hardening

Server version string, KEX / cipher / MAC / host-key algorithm sets, and timing characteristics are aligned with Ubuntu 22.04's stock OpenSSH 8.9p1. `ssh -vvv` against the honeypot is indistinguishable from `ssh -vvv` against a real box. Boot time and host key persist under `/data` so container restarts don't reset "system uptime" to zero.

### Bash-Realistic PTY

The line editor reproduces the readline behaviours attackers use to fingerprint emulators: history with up/down arrows, longest-common-prefix Tab completion, bare-name completion against the cwd, trailing space after a single completion, and proper Ctrl-C / Ctrl-D / Ctrl-L handling.

---

## Slack Alerts

A Slack notification is sent when a session accumulates 5+ MITRE techniques (high-risk threshold), enriched with country (resolved via ip-api.com).

### Option 1 — Incoming Webhook (recommended)

1. Create an app at <https://api.slack.com/apps>.
2. Enable **Incoming Webhooks**, add one to your target channel.
3. Set `SLACK_WEBHOOK_URL` in `.env`.

### Option 2 — Bot Token

1. Add the `chat:write` scope to your app and install it in the workspace.
2. Set `SLACK_BOT_TOKEN` and `SLACK_CHANNEL` in `.env`.

---

## Operations

```bash
# Lifecycle
./start.sh                                    # bring everything up
./stop.sh                                     # tear everything down
docker compose ps                             # health overview
docker compose restart ai-engine              # restart a single service

# Logs
docker compose logs -f                        # everything
docker compose logs -f ssh-frontend           # one service
docker compose logs -f ai-engine sandbox-store

# Rebuild after code changes
docker compose build --no-cache
docker compose up -d

# Warm the threat intel cache for all known IPs
curl -s http://localhost:8003/api/threat-intel/ips | python3 -m json.tool

# Download today's blocklist
curl -O http://localhost:8003/api/threat-intel/blocklist

# Load test against the SSH honeypot
pip install asyncssh
./scripts/load_test_ssh.py -c 10 -n 50

# Failure-recovery drill
./scripts/simulate_failure.sh
```

---

## Production Deployment (AWS)

The defaults are tuned for a single small instance; the architecture scales horizontally if you outgrow that.

- **Compute.** A Lightsail $5/mo instance or an EC2 `t4g.small` (~$13/mo on ARM) handles steady-state honeypot traffic. The bottleneck is concurrent attackers, not throughput.
- **Persistence.** Mount the `sandbox-data` Docker volume on EBS (or Lightsail's persistent disk) — not instance store. Schedule a nightly `sqlite3 .backup` to S3 to capture the growing threat intel cache.
- **Networking.** Expose port 2222 (SSH) and port 80/443 reverse-proxied to 3000 (dashboard, with auth). Keep 8001 / 8002 / 8003 internal to the security group.
- **Egress allowlist.** Outbound from the `dmz` network should reach only:
  - `api.deepseek.com:443` — LLM calls
  - `www.virustotal.com:443` — threat intel (add if using VT)
  - `api.abuseipdb.com:443` — threat intel (add if using AbuseIPDB)
  - `ip-api.com:80` — geo/hosting detection
  - `hooks.slack.com:443` — alerts
  - `canarytokens.org:443` — canary tokens
- **Host SSH.** Move the real host's `sshd` off port 22 to a non-standard port, key-only. The honeypot can then bind 22 publicly for maximum attacker capture.
- **DNS.** A Route53 wildcard such as `*.honeypot.example.com` is the cleanest way to expose the multi-host illusion's auxiliary hostnames.

---

## Security and Responsible Use

- **Accept-all authentication is intentional.** The SSH server accepts any username/password to maximise attacker capture. Never run this on a port that real users could mistake for a production gateway.
- **The sandbox is virtual.** All filesystem and process state is SQLite-backed; there is no real execution surface on the host. Attackers cannot pivot off the container.
- **Outbound is restricted.** Only the AI engine and dashboard-backend egress to external APIs; the sandbox and ssh-frontend are confined to the `prod-internal` Docker network.
- **Threat intel data is cached locally.** IP reputation data from VirusTotal and AbuseIPDB is stored in your local SQLite database — it is not re-uploaded or shared anywhere.
- **Never commit `.env`** — it carries your DeepSeek key, Slack token, and threat intel API keys.
- **Coordinate with your provider.** Cloud abuse teams sometimes flag honeypot traffic; deploy on infrastructure where this is permitted and notify your provider if asked.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| AI engine returns `bash: …: command not found` for everything | DeepSeek key missing/invalid, or daily budget exhausted (`GET /budget/stats` will show `exhausted: true`). |
| AI Report button spins then fails | Dashboard-backend can't reach ai-engine. Check `docker compose logs dashboard-backend` for `AI engine unavailable`. |
| Threat Intel columns show `—` for all IPs | API keys missing from `.env`. Add `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY`. |
| Threat Intel tab loads slowly on first visit | Cold cache — each IP is being looked up live. Subsequent visits are instant from the 24 h cache. |
| Many sessions log no commands | The SSH client closed before requesting a PTY. One-shot `ssh user@host cmd` requests bypass the line editor. |
| Dashboard empty after a fresh start | The sandbox-store volume is fresh — SSH in first to generate data. |
| `docker compose ps` shows services as unhealthy | Health checks need 10–30 s. If still unhealthy after a minute, check `docker compose logs <service>`. |
| `ssh -vvv` shows different algorithms than Ubuntu 22.04 | The asyncssh build dropped support for one of the advertised algorithms — check the warning in `ssh-frontend` logs. |

---

## Project Structure

```
AdaptiveWardens/
├── .env.example                  Centralised configuration template
├── docker-compose.yml            Orchestrates the six services + two networks
├── ssh-frontend/                 AsyncSSH honeypot, PTY line editor, multi-host illusion
├── http-frontend/                Opportunistic HTTP scanner trap
├── ai-engine/
│   └── src/
│       ├── deterministic.py      Tier-1 short-circuits (~30 common commands)
│       ├── response_cache.py     Tier-2 SQLite cache + key normalisation + mitre_cache
│       ├── llm_provider.py       DeepSeek client, retries, sanitisation, budget gate
│       ├── budget.py             Daily token ceiling (persisted to llm_budget.db)
│       ├── rate_limit.py         Per-IP sliding-window limiter
│       ├── extractor.py          IOC extraction (regex + spaCy NER)
│       ├── mitre.py              170+ regex patterns → MITRE ATT&CK (tier-1)
│       ├── mitre_ai.py           LLM MITRE classifier for novel commands (tier-2)
│       ├── report.py             SOC incident report generator (6-section narrative)
│       └── api.py                FastAPI: /generate-response, /summarize-session
├── sandbox-store/                FastAPI: sessions, virtual FS, IOCs, MITRE, Slack/geo
│   └── schemas/
│       └── init_db.sql           SQLite schema (sessions, iocs, attack_techniques,
│                                  ai_reports, threat_intel_cache, …)
├── dashboard-backend/
│   └── src/
│       ├── api.py                Aggregation API + AI report + threat intel endpoints
│       └── threat_intel.py       VT / AbuseIPDB / ip-api.com clients + TTL cache
├── dashboard-frontend/
│   └── src/
│       ├── app/page.tsx          Root layout + view routing
│       └── components/
│           ├── Sidebar.tsx       Navigation (8 views)
│           ├── LiveSessions.tsx
│           ├── SessionPlayback.tsx
│           ├── AttackHeatmap.tsx
│           ├── IOCSummary.tsx
│           ├── MitreAttackMap.tsx
│           ├── MetricsStats.tsx
│           ├── Reports.tsx       Per-session export + AI incident report modal
│           └── ThreatIntelligence.tsx  IP reputation, ASN, blocklist export
├── scripts/                      load_test_ssh.py, simulate_failure.sh, …
├── docs/                         architecture.md, cost.md
├── start.sh / stop.sh            Lifecycle helpers
└── LICENSE
```

---

## License

MIT — see [`LICENSE`](LICENSE).
# Deployed via EC2 CI/CD
# CI/CD test Wed Jun 17 10:31:13 UTC 2026
# re-trigger
