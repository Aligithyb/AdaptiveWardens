# AdaptiveWardens

> **An AI-driven, high-interaction SSH honeypot that transforms every attacker session into structured threat intelligence.**

AdaptiveWardens emulates a compromised Ubuntu 22.04 production server for a fictitious payments company ("NexoPay"). Every attacker connection is captured and enriched into a complete SOC artefact: full keystroke transcripts, extracted IOCs, MITRE ATT&CK technique mappings, IP reputation scores, one-click AI incident reports, and firewall-ready blocklists — all surfaced through a real-time analyst dashboard.

---

## Table of Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [API Key Setup](#api-key-setup)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Dashboard](#dashboard)
- [AI Features In Depth](#ai-features-in-depth)
- [Deception Layer](#deception-layer)
- [Slack Alerts](#slack-alerts)
- [Observability](#observability)
- [Operations](#operations)
- [Production Deployment](#production-deployment)
- [Security and Responsible Use](#security-and-responsible-use)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Highlights

- **Realistic SSH frontend.** AsyncSSH-backed PTY with a line editor that mirrors bash readline behaviour — arrow-key history, `Ctrl-C` / `Ctrl-D` / `Ctrl-L`, longest-common-prefix Tab completion, and persistent boot time / host key aligned with Ubuntu 22.04 OpenSSH 8.9p1.
- **Three-tier response engine.** Requests resolve through: (1) deterministic short-circuits for common commands; (2) a normalised SQLite response cache; (3) the LLM as a last resort. Cache keys collapse flag variants so `ls -la`, `ls -al`, and `ls -a -l` resolve to a single cache row.
- **Hybrid MITRE ATT&CK mapping.** 170+ regex patterns cover the known attacker playbook. When they miss (obfuscated payloads, novel tooling, encoded pipelines), the LLM classifies the command against ATT&CK v15 and writes the result to a global, TTL-free cache. The second attacker to run the same novel command costs zero tokens.
- **One-click AI incident reports.** The Reports tab generates a complete SOC narrative per session: executive summary, inferred attacker objective, kill-chain in tactic order, notable IOCs, severity justification, and recommended remediation. Reports are cached by session content hash — re-clicking an unchanged closed session is instant.
- **Threat Intelligence enrichment.** Every unique attacker IP is enriched with VirusTotal reputation (engine breakdown), AbuseIPDB abuse score, and ASN / hosting-type classification from ip-api.com. All three sources are cached with per-source TTLs.
- **Hard token budget and rate limiting.** A daily UTC token ceiling persisted to disk and a per-IP sliding-window rate limiter act as a circuit breaker. When either fires, all AI paths fall back to deterministic output — sessions stay alive.
- **Layered deception.** AWS IMDS (`169.254.169.254`) emulated end-to-end with canarytoken-bearing credentials. A multi-host illusion lets attackers pivot between `api-prod-01`, `db-primary`, and `cache-01` with distinct host fingerprints and process listings.
- **HTTP honeypot.** A second entry point on port 8080 captures opportunistic web scanner traffic.
- **Slack alerts** with country-resolved attacker IPs, fired when a session accumulates 5+ MITRE techniques.
- **SOAR / SIEM integration.** Generic webhook on every new session (XSOAR, Tines, n8n, Splunk SOAR) and CEF-formatted export endpoints for syslog forwarders.

---

## Architecture

```
                                   ┌─────────────────────────┐
  attacker ── SSH:2222 ──▶         │      ssh-frontend        │
  attacker ── HTTP:8080 ──▶        │      http-frontend       │──┐
                                   └────────────┬────────────┘  │
                                                │               │
                              prod-internal     ▼               ▼
                              ┌────────────────────────────────────────┐
                              │                                        │
                         ┌────────────┐              ┌──────────────┐  │
                         │ ai-engine  │              │sandbox-store │  │
                         │            │              │              │  │
                         │ • tier-1   │              │ • sessions   │  │
                         │   determ.  │              │ • commands   │  │
                         │ • cache    │              │ • IOCs       │  │
                         │ • LLM      │              │ • MITRE      │  │
                         │ • MITRE    │              │ • virtual FS │  │
                         │   hybrid   │              └──────┬───────┘  │
                         │ • reports  │                     │          │
                         └────────────┘                     ▼          │
                                ▲               ┌────────────────────┐ │
                                │               │ dashboard-backend  │ │
                           DeepSeek             │                    │ │
                                                │ • analytics        │ │
                         VirusTotal ────────────│ • TI enrichment    │ │
                         AbuseIPDB  ────────────│ • AI reports       │ │
                         ip-api.com ────────────│ • blocklist export │ │
                                                └────────┬───────────┘ │
                                                         │             │
                                              └──────────┘             │
                                dmz ──────────────────────────────────-┘
                                                         ▼
                                              dashboard-frontend
                                              (SOC analyst console)
```

### Service Map

| Service              | Container         | Port | Role                                                                              |
|----------------------|-------------------|------|-----------------------------------------------------------------------------------|
| `ssh-frontend`       | auth-gateway      | 2222 | AsyncSSH honeypot, PTY line editor, per-attacker session state, multi-host illusion |
| `http-frontend`      | web-gateway       | 8080 | HTTP honeypot for opportunistic scanners                                          |
| `ai-engine`          | inference-svc     | 8002 | Deterministic + cache + LLM tiers, budget gate, IOC extraction, MITRE hybrid, AI reports |
| `sandbox-store`      | app-state-store   | 8001 | SQLite-backed persistence, virtual filesystem, geo/IP enrichment                  |
| `dashboard-backend`  | dashboard-backend | 8003 | Aggregation API, threat intel enrichment, AI report generation, SIEM/SOAR export |
| `dashboard-frontend` | soc-dashboard     | 3000 | Next.js SOC analyst console                                                       |

### Network Isolation

Two Docker networks isolate the blast radius:

- **`prod-internal`** (`internal: true`) — sandbox-store, ai-engine, and dashboard-backend communicate exclusively here. No external egress.
- **`dmz`** — bridges public-facing frontends to outbound traffic (DeepSeek, VirusTotal, AbuseIPDB, Slack, Canarytokens).

---

## How It Works

Understanding the data flow end-to-end helps when tuning the system or extending it.

### 1. Attacker Connection

An attacker SSHes to port 2222. The `ssh-frontend` service accepts any username and password, spawns a pseudo-terminal, and presents a convincing Ubuntu 22.04 bash prompt. A session record is opened in the `sandbox-store` with the source IP, timestamp, and geo-resolved country.

### 2. Command Processing Pipeline

Each command the attacker types passes through the following pipeline in order:

```
Command Input
     │
     ▼
┌─────────────────────────────────────┐
│  Tier 1: Deterministic Short-Circuit │  ← ~30 common recon commands (whoami, id, pwd…)
│  Instant, zero tokens               │
└─────────────────┬───────────────────┘
                  │ cache miss
                  ▼
┌─────────────────────────────────────┐
│  Tier 2: SQLite Response Cache      │  ← Normalised command key + scope (global/user/cwd)
│  Per-command TTLs, pre-cached IOCs  │
└─────────────────┬───────────────────┘
                  │ cache miss
                  ▼
┌─────────────────────────────────────┐
│  Tier 3: LLM (DeepSeek)            │  ← Budget gate + per-IP rate limiter checked first
│  Response cached on return          │
└─────────────────────────────────────┘
```

### 3. MITRE ATT&CK Classification

In parallel with response generation, every command is classified against MITRE ATT&CK v15:

- **Regex tier** — 170+ compiled patterns covering the known playbook, from Reconnaissance through Impact. Instant and free.
- **LLM tier** — triggered only when the regex tier returns nothing. The result is written to a global, TTL-free `mitre_cache` table so the next attacker to run the same novel command pays nothing.

### 4. IOC Extraction

After every LLM response, `extractor.py` parses both the command and the generated output for Indicators of Compromise using a combination of regex patterns and spaCy NER:

- IPv4 / IPv6 addresses, domain names, URLs
- MD5 / SHA256 / SHA1 hashes
- File paths, SSH public keys
- Triggered canarytoken references

Extracted IOCs are written to the `sandbox-store` and appear in the IOC Summary dashboard view.

### 5. Threat Intelligence Enrichment

For each unique attacker IP, `dashboard-backend` asynchronously queries three sources:

| Source      | Data                                        | Cache TTL |
|-------------|---------------------------------------------|-----------|
| VirusTotal  | Engine verdict breakdown, tags, ASN         | 24 hours  |
| AbuseIPDB   | Abuse confidence %, report count, ISP       | 24 hours  |
| ip-api.com  | Country, hosting type (Datacenter/Tor/VPN)  | 7 days    |

### 6. AI Incident Report Generation

Clicking **✨ AI Report** on any session sends its full structured data (commands, techniques, IOCs) to `ai-engine/src/report.py`. The LLM produces a six-section JSON narrative. The report is cached in an `ai_reports` table keyed by `(session_id, content_hash)` — re-clicking an unchanged closed session returns the cached copy instantly.

### 7. Dashboard

The Next.js frontend polls the `dashboard-backend` aggregation API and presents all session, IOC, MITRE, and threat intelligence data in real time across eight views.

---

## Project Structure

```
AdaptiveWardens/
├── .env.example                   Centralised configuration template
├── docker-compose.yml             Orchestrates the six services + two networks
├── start.sh / stop.sh             Lifecycle helpers
│
├── ssh-frontend/                  AsyncSSH honeypot, PTY line editor, multi-host illusion
├── http-frontend/                 Opportunistic HTTP scanner trap
│
├── ai-engine/
│   └── src/
│       ├── deterministic.py       Tier-1 short-circuits (~30 common commands)
│       ├── response_cache.py      Tier-2 SQLite cache, key normalisation, mitre_cache
│       ├── llm_provider.py        DeepSeek client, retries, sanitisation, budget gate
│       ├── budget.py              Daily token ceiling (persisted to llm_budget.db)
│       ├── rate_limit.py          Per-IP sliding-window rate limiter
│       ├── extractor.py           IOC extraction (regex + spaCy NER)
│       ├── mitre.py               170+ regex patterns → MITRE ATT&CK (tier-1)
│       ├── mitre_ai.py            LLM MITRE classifier for novel commands (tier-2)
│       ├── report.py              SOC incident report generator (six-section narrative)
│       └── api.py                 FastAPI: /generate-response, /summarize-session
│
├── sandbox-store/
│   └── schemas/
│       └── init_db.sql            SQLite schema (sessions, iocs, attack_techniques,
│                                  ai_reports, threat_intel_cache, …)
│
├── dashboard-backend/
│   └── src/
│       ├── api.py                 Aggregation API, AI report, threat intel, SOAR/SIEM endpoints
│       └── threat_intel.py        VirusTotal / AbuseIPDB / ip-api.com clients + TTL cache
│
├── dashboard-frontend/
│   └── src/
│       ├── app/page.tsx           Root layout + view routing
│       └── components/
│           ├── Sidebar.tsx
│           ├── LiveSessions.tsx
│           ├── SessionPlayback.tsx
│           ├── AttackHeatmap.tsx
│           ├── IOCSummary.tsx
│           ├── MitreAttackMap.tsx
│           ├── MetricsStats.tsx
│           ├── Reports.tsx        Per-session export + AI incident report modal
│           └── ThreatIntelligence.tsx
│
├── scripts/                       load_test_ssh.py, simulate_failure.sh
└── docs/                          architecture.md
```

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) v2+
- A [DeepSeek](https://platform.deepseek.com) account with API access (required)
- Optional: VirusTotal, AbuseIPDB, Slack, and Canarytokens accounts (see [API Key Setup](#api-key-setup))

---

## API Key Setup

This section covers exactly where to obtain and how to configure each external API key the platform can use.

### Required

#### DeepSeek (LLM Backend)

DeepSeek powers the shell response engine, MITRE classification, and AI report generation. Without this key the platform runs in deterministic-only mode — common commands work but novel inputs return a generic fallback.

1. Create an account at [platform.deepseek.com](https://platform.deepseek.com).
2. Navigate to **API Keys** → **Create new key**.
3. Copy the key and set it in `.env`:

```env
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

To use a self-hosted OpenAI-compatible endpoint instead (e.g. vLLM, LM Studio), also set:

```env
DEEPSEEK_BASE_URL=http://your-host:8000
DEEPSEEK_MODEL=your-model-name
```

---

### Optional — Threat Intelligence

The platform operates without threat intel keys; those dashboard columns simply show `—` until keys are added.

#### VirusTotal

VirusTotal enriches each attacker IP with engine verdict breakdown, tags, reputation score, and ASN data.

1. Create a free account at [virustotal.com](https://www.virustotal.com).
2. Go to your **Profile → API Key**.
3. Copy and set:

```env
VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Free tier limits: 4 requests/min, 500/day. The 24-hour SQLite cache keeps usage well below these limits.

#### AbuseIPDB

AbuseIPDB provides an IP abuse confidence score, total report count, ISP, and usage type.

1. Create a free account at [abuseipdb.com](https://www.abuseipdb.com).
2. Go to **Account → API** → **Create Key**.
3. Copy and set:

```env
ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Free tier limit: 1,000 checks/day. The 24-hour cache makes this a non-issue in practice.

---

### Optional — Alerting & Deception

#### Slack Alerts

See the [Slack Alerts](#slack-alerts) section for full setup instructions. Set either:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TXXX/BXXX/XXXX
# or
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_CHANNEL=#alerts
```

#### Canarytokens

Canarytokens alert you when an attacker uses harvested credentials *outside* the honeypot on the public internet.

1. Go to [canarytokens.org/generate](https://canarytokens.org/generate).
2. Generate an **AWS Keys** token → copy the Access Key ID and Secret.
3. Generate a **DNS** token → copy the hostname.
4. Set in `.env`:

```env
CANARY_AWS_ACCESS_KEY=AKIA...
CANARY_AWS_SECRET_KEY=...
CANARY_STRIPE_KEY=sk_live_...
CANARY_DNS_HOSTNAME=abc123.canarytokens.org
```

If left blank, convincing-looking static values are used — the deception remains intact but you won't receive alerts.

---

### Dashboard Security

The following variables are **required** before starting the dashboard in any environment:

```bash
# Generate a strong session secret
openssl rand -hex 32
```

```env
DASHBOARD_PASSWORD=choose-a-strong-password
SESSION_SECRET=<output of openssl rand -hex 32>
JWT_SECRET=<another strong random string>
```

---

## Configuration

All configuration lives in `.env`. Start from the template:

```bash
cp .env.example .env
```

### AI Engine

| Variable                        | Default                    | Description                                                          |
|---------------------------------|----------------------------|----------------------------------------------------------------------|
| `DEEPSEEK_API_KEY`              | _required_                 | DeepSeek API credential.                                             |
| `DEEPSEEK_MODEL`                | `deepseek-v4-flash`        | Model identifier — override to point at a different model.           |
| `DEEPSEEK_BASE_URL`             | `https://api.deepseek.com` | Override for a self-hosted OpenAI-compatible endpoint.               |
| `LLM_DAILY_INPUT_TOKEN_BUDGET`  | `50000`                    | Hard daily ceiling on uncached input tokens. Resets at 00:00 UTC.   |
| `LLM_DAILY_OUTPUT_TOKEN_BUDGET` | `20000`                    | Hard daily ceiling on output tokens.                                 |
| `LLM_PER_IP_RATE_LIMIT_CALLS`  | `30`                       | Maximum LLM calls allowed per attacker IP per window.                |
| `LLM_PER_IP_RATE_LIMIT_WINDOW` | `60`                       | Rate-limit sliding window in seconds.                                |

### Threat Intelligence

| Variable             | Default | Description                                                                          |
|----------------------|---------|--------------------------------------------------------------------------------------|
| `VIRUSTOTAL_API_KEY` | `""`    | VirusTotal free tier: 4 req/min, 500/day. Cache keeps usage well below limits.       |
| `ABUSEIPDB_API_KEY`  | `""`    | AbuseIPDB free tier: 1,000 checks/day. Cache makes this a non-issue.                |

### Honeypot Session

| Variable               | Default | Description                                              |
|------------------------|---------|----------------------------------------------------------|
| `MAX_SESSIONS`         | `50`    | Maximum concurrent SSH sessions.                         |
| `SESSION_TIMEOUT`      | `1800`  | Idle session timeout in seconds.                         |
| `ENABLE_RATE_LIMITING` | `true`  | Per-IP connection throttling at the SSH layer.           |

### HTTP Honeypot

| Variable                  | Default | Description                                                              |
|---------------------------|---------|--------------------------------------------------------------------------|
| `HTTP_SESSION_WINDOW`     | `300`   | Requests from the same IP within this window (seconds) group into one session. |
| `HTTP_MAX_CMDS_PER_SESSION` | `60`  | Stop logging requests after this many per session (still responds).       |

### Storage

| Variable         | Default              | Description                            |
|------------------|----------------------|----------------------------------------|
| `DB_PATH`        | `/data/app_state.db` | sandbox-store SQLite file location.    |
| `SQLITE_TIMEOUT` | `30`                 | Per-statement busy timeout in seconds. |

### Dashboard

| Variable              | Default                 | Description                                                       |
|-----------------------|-------------------------|-------------------------------------------------------------------|
| `DASHBOARD_PASSWORD`  | _required_              | Password for the dashboard login page.                            |
| `SESSION_SECRET`      | _required_              | Secret used to sign session cookies. Generate with `openssl rand -hex 32`. |
| `JWT_SECRET`          | _required_              | Secret for signing JWT tokens.                                    |
| `JWT_EXPIRY`          | `3600`                  | JWT expiry in seconds.                                            |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8003` | Public URL of the dashboard-backend, as seen by the browser.     |

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Aligithyb/-AdaptiveWardens.git
cd -AdaptiveWardens
```

### 2. Configure Environment

```bash
cp .env.example .env
```

At minimum, open `.env` and set:

```env
DEEPSEEK_API_KEY=your-key-here
DASHBOARD_PASSWORD=choose-a-strong-password
SESSION_SECRET=<openssl rand -hex 32>
JWT_SECRET=<another-strong-random-string>
```

### 3. Launch

```bash
./start.sh
```

Services come up healthy in roughly 15–20 seconds. Verify all services are running:

```bash
docker compose ps
curl -s http://localhost:8002/health      # ai-engine
curl -s http://localhost:8001/health      # sandbox-store
curl -s http://localhost:8003/health      # dashboard-backend
```

Test the SSH honeypot (any password is accepted):

```bash
ssh -p 2222 root@localhost
```

Open the SOC dashboard at [http://localhost:3000](http://localhost:3000).

---

## Dashboard

Available at [http://localhost:3000](http://localhost:3000). Eight views are accessible from the sidebar:

### Live Sessions

Real-time table of active SSH and HTTP attacker connections showing source country, protocol, risk score, and command count. Rows auto-refresh every 5 seconds. Click any row to open the Session Playback panel.

### Session Playback

Full keystroke-level replay of any session. Commands are displayed in sequence with per-command annotations: matched MITRE techniques, extracted IOCs, and suspicious-command flags.

### Attack Map

Geographic heatmap of inbound attacker IPs rendered on a D3.js world map with zoom and pan. Country-level attack counts are colour-coded by intensity.

### IOC Summary

All Indicators of Compromise extracted across sessions — IPs, domains, URLs, MD5/SHA256 hashes, file paths, SSH public keys, and triggered canarytoken references. Filterable by type and confidence level.

### MITRE ATT&CK

Interactive technique grid showing detected ATT&CK techniques grouped by tactic. Detection counts and confidence scores drive colour intensity. Click any technique cell for the full detail panel and the commands that triggered it.

### Session Metrics

Aggregated statistics across all sessions: risk distribution, top source countries, top attempted usernames and passwords, protocol breakdown, and average session duration.

### Reports

Per-session export panel with four actions per row:

| Action | Output |
|--------|--------|
| **JSON** | Full session dump — commands, IOCs, techniques (download) |
| **CSV** | Command history with timestamps and exit codes (download) |
| **PDF** | Print-formatted HTML report via browser print dialog |
| **✨ AI Report** | One-click SOC incident report (see below) |

**AI Incident Report** — clicking the sparkle icon sends the session's full structured data to the AI engine and returns a six-section analyst narrative:

1. **Executive Summary** — 2–3 sentences for management
2. **Attacker Objective** — inferred intent (reconnaissance, credential theft, persistence, etc.)
3. **Kill Chain** — tactics observed in attack-chain order with technique details
4. **Notable IOCs** — the most actionable indicators with significance notes
5. **Severity Justification** — evidence-backed explanation of the assigned risk level
6. **Recommended Actions** — concrete defensive steps (block IP, rotate credentials, patch CVE, etc.)

Reports are cached by session content hash — re-clicking an unchanged closed session is instant. The AI summary is embedded in the PDF when saved.

### Threat Intelligence

Dedicated view that enriches every unique attacker IP with data from three external sources.

**IP Intelligence table** — one row per unique attacker IP, sorted confirmed-malicious first:

| Column       | Source      | Details                                              |
|--------------|-------------|------------------------------------------------------|
| Hosting type | ip-api.com  | `Datacenter`, `Tor Exit`, `VPN/Proxy`, `ISP`, `Mobile ISP` |
| VT Score     | VirusTotal  | `12/91` — malicious engine count / total engines     |
| Abuse %      | AbuseIPDB   | Confidence score with colour-coded progress badge    |
| Sessions     | Internal DB | Total session count from this IP                     |

**IP Detail panel** — click any row to open a side panel with three tabs:

- **VirusTotal** — per-category engine counts, tags, last analysis date, ASN / AS owner, VT reputation score
- **AbuseIPDB** — abuse confidence bar, total report count, distinct reporters, ISP, usage type, last reported timestamp
- **Session History** — all sessions from this IP with risk levels, technique counts, and timestamps

**Blocklist export** — the **Blocklist** button downloads a plain-text file of all IPs where VirusTotal detections > 0 or AbuseIPDB confidence ≥ 50%, formatted for direct use with `iptables`, `ufw`, `firewalld`, or CIDR block lists.

---

## AI Features In Depth

### Hybrid MITRE ATT&CK Mapping

Every command is classified against MITRE ATT&CK in two tiers:

1. **Regex tier** (`ai-engine/src/mitre.py`) — 170+ compiled patterns covering the known attacker playbook from Reconnaissance through Impact. Instant, zero cost, high confidence.
2. **LLM tier** (`ai-engine/src/mitre_ai.py`) — activated only when the regex tier returns no match. The LLM returns a JSON array of `{technique_id, technique_name, tactic, confidence, evidence}` objects. The result is written to a **global, TTL-free** `mitre_cache` table — the second attacker to run the same novel command is served from cache at no cost.

Budget and rate limits apply to tier-2 calls identically to shell-response calls. If the daily budget is exhausted, classification silently falls back to regex-only — no session is disrupted.

### One-Click AI Reports

Reports are generated by `ai-engine/src/report.py` via `POST /summarize-session`. The system prompt is tuned for a senior SOC analyst persona and requests structured JSON output with six named keys.

A deterministic fallback assembles the same structure from session counts and tactic lists when the LLM is unavailable, so the report button always returns something useful.

`dashboard-backend` caches reports in an `ai_reports` table keyed by `(session_id, content_hash)`. The content hash is an MD5 of the combined commands + techniques + IOCs JSON, so open or growing sessions get a fresh report when their data changes, while closed sessions serve instantly from cache.

---

## Deception Layer

### Canarytokens

Generate real tokens at [canarytokens.org/generate](https://canarytokens.org/generate) and paste them into `.env`. When an attacker uses any of these credentials anywhere on the internet — not just inside the honeypot — canarytokens.org alerts you with their real source IP.

| Variable | Token type | Where it surfaces in the honeypot |
|----------|------------|-----------------------------------|
| `CANARY_AWS_ACCESS_KEY` / `CANARY_AWS_SECRET_KEY` | AWS Keys | `~/.aws/credentials`, IMDS responses, environment variables |
| `CANARY_STRIPE_KEY` | Stripe Key | `/opt/nexopay/config/stripe.env` |
| `CANARY_DNS_HOSTNAME` | DNS | Referenced in `~/.bashrc`, surfaces in `nslookup` / `dig` responses |

If any variable is left blank, convincing-looking static values are used — alerts won't fire, but the deception remains intact.

### IMDS Emulation

The AWS Instance Metadata Service at `http://169.254.169.254/latest/meta-data/` is fully emulated, including IAM role credentials backed by your canary keys. Cloud enumeration scripts that scrape IMDS for lateral movement hit a live, instrumented target.

### Multi-Host Illusion

Three internal hosts respond to `ssh` commands from inside the honeypot — `api-prod-01`, `db-primary.nexopay.internal`, and `cache-01.nexopay.internal` — each with distinct host keys, banners, and process listings. Attackers can pivot between them; the dashboard records every hop.

### SSH Fingerprint Hardening

Server version string, KEX / cipher / MAC / host-key algorithm sets, and timing characteristics are aligned with Ubuntu 22.04's stock OpenSSH 8.9p1. Running `ssh -vvv` against the honeypot is indistinguishable from connecting to a real Ubuntu server. Boot time and host key persist under `/data` so container restarts do not reset "system uptime" to zero.

### Bash-Realistic PTY

The line editor reproduces the readline behaviours attackers use to fingerprint emulators: history navigation with arrow keys, longest-common-prefix Tab completion, bare-name completion against the current working directory, trailing space after a single match, and correct `Ctrl-C` / `Ctrl-D` / `Ctrl-L` handling.

---

## Slack Alerts

A Slack notification fires when a session accumulates 5+ MITRE ATT&CK techniques, enriched with the country resolved via ip-api.com.

### Option 1 — Incoming Webhook (Recommended)

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps).
2. Enable **Incoming Webhooks** and add one to your target channel.
3. Copy the webhook URL and set it in `.env`:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TXXX/BXXX/XXXX
```

### Option 2 — Bot Token

1. Add the `chat:write` scope to your Slack app and install it in your workspace.
2. Set the bot token and target channel in `.env`:

```env
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_CHANNEL=#alerts
```

---

## Observability

### Health Checks

```bash
curl http://localhost:8001/health   # sandbox-store
curl http://localhost:8002/health   # ai-engine
curl http://localhost:8003/health   # dashboard-backend
```

### Cache Statistics

```bash
# Shell response cache — hit rate and MITRE cache hit rate
curl http://localhost:8002/cache/stats
# → { "hits": 8421, "misses": 312, "bypassed": 78, "stores": 312,
#     "hit_rate": 0.96, "mitre_hits": 540, "mitre_misses": 38,
#     "mitre_hit_rate": 0.93 }
```

### Token Budget and Rate Limiter

```bash
# Daily LLM spend and per-IP rate limiter status
curl http://localhost:8002/budget/stats
# → { "budget": { "day_utc": "2026-06-18", "input_tokens": 1234, "output_tokens": 412,
#                 "input_remaining": 48766, "output_remaining": 19588,
#                 "exhausted": false, "calls": 18, "blocked": 0 },
#     "rate_limit": { "tracked_ips": 4, "allowed": 18, "blocked": 0,
#                     "calls_per_window": 30, "window_seconds": 60 } }
```

> Wire an external alert (e.g. PagerDuty) to fire when `budget.exhausted == true`.

### Threat Intelligence Cache (SQLite)

```bash
sqlite3 /var/lib/docker/volumes/adaptivewardens_sandbox-data/_data/app_state.db \
  "SELECT ioc_value, source_api, cached_at, expires_at FROM threat_intel_cache LIMIT 20;"
```

---

## Operations

```bash
# Lifecycle
./start.sh                                     # Bring all services up
./stop.sh                                      # Tear everything down
docker compose ps                              # Health overview
docker compose restart ai-engine              # Restart a single service

# Logs
docker compose logs -f                         # Stream all services
docker compose logs -f ssh-frontend           # Stream one service
docker compose logs -f ai-engine sandbox-store

# Rebuild after code changes
docker compose build --no-cache
docker compose up -d

# Threat intelligence
curl -s http://localhost:8003/api/threat-intel/ips | python3 -m json.tool   # Warm cache for all IPs
curl -O http://localhost:8003/api/threat-intel/blocklist                    # Download today's blocklist

# SIEM / CEF export
curl http://localhost:8003/api/integrations/siem/cef?limit=200              # Bulk CEF export
curl http://localhost:8003/api/integrations/siem/cef/<session_id>           # Single session

# Testing
pip install asyncssh
./scripts/load_test_ssh.py -c 10 -n 50        # Load test with 10 concurrent clients, 50 commands each
./scripts/simulate_failure.sh                  # Failure-recovery drill
```

---

## Production Deployment

The following guide covers deploying AdaptiveWardens to a single Linux server (AWS used as the reference provider). The architecture scales horizontally if your threat volume outgrows a single instance.

### 1. Compute

A **Lightsail $5/mo** instance or an **EC2 `t4g.small`** (~$13/mo on ARM) handles steady-state honeypot traffic. The bottleneck is concurrent attacker sessions, not network throughput.

```bash
# On the server — install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 2. Clone and Configure

```bash
git clone https://github.com/Aligithyb/-AdaptiveWardens.git
cd -AdaptiveWardens
cp .env.example .env
```

Edit `.env` with your production values. At minimum, set all API keys, a strong `DASHBOARD_PASSWORD`, `SESSION_SECRET`, and `JWT_SECRET`. Set `NEXT_PUBLIC_API_URL` to your server's public domain or IP:

```env
NEXT_PUBLIC_API_URL=https://your-domain.com
```

### 3. Networking

Configure your cloud security group / firewall to expose only:

| Port | Service             | Visibility   |
|------|---------------------|--------------|
| 22   | Host SSH (management) | Your IP only |
| 2222 | SSH honeypot        | Public (0.0.0.0/0) |
| 80   | Dashboard (HTTP redirect) | Public |
| 443  | Dashboard (HTTPS via reverse proxy) | Public |
| 8001–8003 | Internal services | **Blocked** — internal only |

> Move the host's own `sshd` off port 22 (`/etc/ssh/sshd_config`: `Port 2200`) and bind the honeypot to port 22 for maximum attacker capture.

### 4. Reverse Proxy (Dashboard HTTPS)

Use nginx with Certbot to terminate TLS and proxy the dashboard:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 5. Persistence

Mount the `sandbox-data` Docker volume on a persistent disk (EBS or Lightsail block storage) — not instance store. Schedule a nightly backup:

```bash
# Add to crontab
0 2 * * * sqlite3 /var/lib/docker/volumes/adaptivewardens_sandbox-data/_data/app_state.db \
  ".backup '/backups/app_state_$(date +\%Y\%m\%d).db'"
```

Upload backups to S3:

```bash
aws s3 sync /backups/ s3://your-bucket/adaptivewardens-backups/
```

### 6. Egress Allowlist

Restrict outbound traffic from the server to only the required external endpoints:

| Destination              | Port | Purpose            |
|--------------------------|------|--------------------|
| `api.deepseek.com`       | 443  | LLM inference      |
| `www.virustotal.com`     | 443  | Threat intelligence |
| `api.abuseipdb.com`      | 443  | Threat intelligence |
| `ip-api.com`             | 80   | Geo / hosting detection |
| `hooks.slack.com`        | 443  | Alerts             |
| `canarytokens.org`       | 443  | Canary token callbacks |

### 7. Start

```bash
./start.sh
docker compose ps   # All services should be healthy within 30 seconds
```

### 8. DNS (Optional)

A Route53 wildcard record such as `*.honeypot.example.com` is the cleanest way to expose the multi-host illusion's auxiliary hostnames (`db-primary.nexopay.internal`, etc.) to DNS-querying attackers.

---

## Security and Responsible Use

- **Accept-all authentication is intentional.** The SSH server accepts any username and password combination to maximise attacker capture. Never deploy this on a port that real users could mistake for a production gateway.
- **The sandbox is virtual.** All filesystem and process state is SQLite-backed; there is no real code execution surface on the host. Attackers cannot pivot off the container.
- **Outbound is restricted.** Only the `ai-engine` and `dashboard-backend` services egress to external APIs. The `sandbox-store` and `ssh-frontend` are confined to the `prod-internal` Docker network and have no external egress.
- **Threat intel data stays local.** IP reputation data from VirusTotal and AbuseIPDB is stored in your local SQLite database. It is not re-uploaded or shared anywhere.
- **Never commit `.env`.** It carries your DeepSeek key, Slack token, dashboard credentials, and threat intelligence API keys. The `.gitignore` excludes it, but verify this before pushing.
- **Coordinate with your cloud provider.** Abuse teams sometimes flag honeypot traffic. Deploy on infrastructure where this is permitted and notify your provider if contacted.

---

## Troubleshooting

| Symptom | Likely Cause & Resolution |
|---------|--------------------------|
| AI engine returns `bash: command not found` for all inputs | DeepSeek key missing or invalid, or daily budget exhausted. Check `GET /budget/stats` for `"exhausted": true`. |
| AI Report button spins then fails | `dashboard-backend` cannot reach `ai-engine`. Check `docker compose logs dashboard-backend` for `AI engine unavailable`. |
| Threat Intelligence columns show `—` for all IPs | API keys missing from `.env`. Add `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY`. |
| Threat Intelligence tab is slow on first load | Cold cache — each IP is being looked up live. Subsequent visits are instant from the 24-hour cache. |
| Many sessions log zero commands | The SSH client closed before requesting a PTY. One-shot `ssh user@host <cmd>` requests bypass the line editor. |
| Dashboard is empty after a fresh start | The sandbox-store volume is fresh. SSH into the honeypot first to generate data. |
| `docker compose ps` shows services as `unhealthy` | Health checks need 10–30 s to pass. If still unhealthy after 60 s, check `docker compose logs <service>`. |
| `ssh -vvv` shows different algorithms than Ubuntu 22.04 | The asyncssh build may have dropped one of the advertised algorithms. Check the warning in `ssh-frontend` logs. |
| Dashboard login fails with 401 | `DASHBOARD_PASSWORD`, `SESSION_SECRET`, or `JWT_SECRET` not set in `.env`. Restart services after editing. |

---

## License

MIT — see [`LICENSE`](LICENSE).
