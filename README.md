# AdaptiveWardens

**An AI-driven, high-interaction honeypot for capturing and analysing real-world attacker behaviour.**

AdaptiveWardens emulates a compromised Ubuntu 22.04 production server for a fictitious payments company ("NexoPay") and turns every attacker session into structured intelligence: command transcripts, extracted IOCs, MITRE ATT&CK technique mappings, country/IP attribution, and risk-scored reports. Unknown commands are answered by a tightly-budgeted LLM backend (DeepSeek by default) wrapped in deterministic short-circuits, prefix caching, and a daily token ceiling so a single noisy attacker can never blow up your bill.

---

## Highlights

- **Realistic SSH frontend.** AsyncSSH-backed PTY with a line editor that mimics bash readline behaviour — arrow-key history, Ctrl-C / Ctrl-D / Ctrl-L, longest-common-prefix Tab completion, bare-name cwd completion, and persistent boot time / host key matched to Ubuntu 22.04 OpenSSH 8.9p1 algorithm sets.
- **Tiered response engine.** Three layers in order: (1) deterministic short-circuits for cheap, repetitive commands; (2) a SQLite-backed response cache with command-scoped keys and per-command TTLs; (3) the LLM as a last resort. Cache keys are normalized so `ls -la`, `ls -al`, and `ls -a -l` collide on one row.
- **Hard cost ceiling.** A daily UTC token budget persisted to disk and a per-IP sliding-window rate limit. When either fires, the AI engine serves deterministic / static fallbacks so sessions stay open and the bill stays flat.
- **Layered deception.** AWS IMDS (`169.254.169.254`) is emulated end-to-end with canarytoken-bearing credentials. Multi-host illusion lets attackers `ssh` between `api-prod-01`, `db-primary`, and `cache-01` with distinct fingerprints. Story-consistency keeps the running services, paths, and config files coherent across responses.
- **Live SOC dashboard.** Next.js front-end with attack heatmap, session playback, IOC summary, MITRE ATT&CK mapping, session metrics, and reports.
- **HTTP honeypot.** A second front-door on port 8080 captures opportunistic web scanning alongside SSH.
- **Slack alerts** with country-resolved attacker IPs out of the box.

---

## Architecture

```
                                      +-------------------+
       attacker ---SSH:2222--->   ssh-frontend            |
       attacker ---HTTP:8080--->  http-frontend ----+     |
                                      |             |     |
                                      v             v     |
                                +-----------+   +--------------+
                                | ai-engine |<->| sandbox-store|
                                +-----------+   +--------------+
                                      ^             ^
                                      |             |
                                +-----------+       |
                                | DeepSeek  |       |
                                +-----------+       |
                                                    v
                                            dashboard-backend
                                                    |
                                                    v
                                            dashboard-frontend ---> SOC analyst
```

| Service             | Container          | Port | Role                                                              |
| ------------------- | ------------------ | ---- | ----------------------------------------------------------------- |
| `ssh-frontend`      | auth-gateway       | 2222 | AsyncSSH honeypot, PTY line editor, per-attacker session state    |
| `http-frontend`     | web-gateway        | 8080 | HTTP honeypot for opportunistic scanners                          |
| `ai-engine`         | inference-svc      | 8002 | Deterministic + cache + LLM tiers, budget gate, IOC + MITRE       |
| `sandbox-store`     | app-state-store    | 8001 | SQLite-backed persistence, virtual filesystem, geo/IP enrichment  |
| `dashboard-backend` | dashboard-backend  | 8003 | Aggregation API consumed by the dashboard                         |
| `dashboard-frontend`| soc-dashboard      | 3000 | Next.js SOC console                                               |

Two Docker networks isolate the blast radius:

- `prod-internal` — `internal: true`. The sandbox, AI engine, and dashboard-backend can only reach each other here.
- `dmz` — bridges the public-facing front-ends and outbound traffic to DeepSeek / Slack / canarytokens.

See [`docs/architecture.md`](docs/architecture.md) for a full breakdown of the service contracts, statelessness model, and trade-offs.

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

| Variable             | Where to get it                                       |
| -------------------- | ----------------------------------------------------- |
| `DEEPSEEK_API_KEY`   | https://platform.deepseek.com/api_keys                |
| `SLACK_WEBHOOK_URL`  | Optional — see [Slack alerts](#slack-alerts) below    |
| `CANARY_*`           | Optional — see [Deception layer](#deception-layer)    |

### 3. Launch

```bash
./start.sh
```

Containers come up healthy in roughly 15–20 seconds. Verify:

```bash
docker compose ps
curl -s http://localhost:8002/health      # ai-engine
curl -s http://localhost:8001/health      # sandbox-store
ssh -p 2222 root@localhost                # any password works
```

Open the dashboard at <http://localhost:3000>.

---

## Configuration

The full configuration surface lives in `.env.example`. The variables you are most likely to tune:

### AI engine

| Variable                              | Default                  | Purpose                                                                 |
| ------------------------------------- | ------------------------ | ----------------------------------------------------------------------- |
| `DEEPSEEK_API_KEY`                    | _required_               | DeepSeek API credential.                                                |
| `DEEPSEEK_MODEL`                      | `deepseek-v4-flash`      | Override to point at a different model.                                 |
| `DEEPSEEK_BASE_URL`                   | `https://api.deepseek.com` | Override for a self-hosted OpenAI-compatible endpoint.                |
| `LLM_DAILY_INPUT_TOKEN_BUDGET`        | `50000`                  | Hard daily ceiling on uncached input tokens. Resets at 00:00 UTC.       |
| `LLM_DAILY_OUTPUT_TOKEN_BUDGET`       | `20000`                  | Hard daily ceiling on output tokens.                                    |
| `LLM_PER_IP_RATE_LIMIT_CALLS`         | `30`                     | LLM calls allowed per attacker IP per window.                           |
| `LLM_PER_IP_RATE_LIMIT_WINDOW`        | `60`                     | Rate-limit window in seconds.                                           |

### Honeypot session

| Variable               | Default | Purpose                                                |
| ---------------------- | ------- | ------------------------------------------------------ |
| `MAX_SESSIONS`         | `50`    | Concurrent SSH session ceiling.                        |
| `SESSION_TIMEOUT`      | `1800`  | Idle session timeout in seconds.                       |
| `ENABLE_RATE_LIMITING` | `true`  | Per-IP connection throttling at the SSH layer.         |

### Storage

| Variable          | Default              | Purpose                            |
| ----------------- | -------------------- | ---------------------------------- |
| `DB_PATH`         | `/data/app_state.db` | Sandbox-store SQLite location.     |
| `SQLITE_TIMEOUT`  | `30`                 | Per-statement busy timeout, secs.  |

---

## Deception layer

Several anti-detection features are wired in by default. Most are free; a few need optional configuration.

### Canarytokens

Generate real tokens at <https://canarytokens.org/generate> and paste them into `.env`. When an attacker uses any of these credentials anywhere on the internet — not just inside the honeypot — canarytokens.org alerts you with their real source IP.

| Variable                | Token type   | Where it surfaces                                                  |
| ----------------------- | ------------ | ------------------------------------------------------------------ |
| `CANARY_AWS_ACCESS_KEY` / `CANARY_AWS_SECRET_KEY` | AWS Keys | `~/.aws/credentials`, IMDS responses, env vars |
| `CANARY_STRIPE_KEY`     | Stripe Key   | `/opt/nexopay/config/stripe.env`                                   |
| `CANARY_DNS_HOSTNAME`   | DNS          | Referenced by `~/.bashrc`, surfaces in `nslookup` / `dig`          |

If any are left blank, convincing-looking static values are used instead — alerts won't fire but the deception is intact.

### IMDS emulation

The classic AWS Instance Metadata Service surface at `http://169.254.169.254/latest/meta-data/` is fully emulated, including IAM role credentials backed by your canary keys. Tooling that scrapes IMDS for lateral movement (mimikatz-for-cloud, cloud-enumerator scripts) hits a live target.

### Multi-host illusion

Three internal hosts respond to `ssh` from inside the honeypot — `api-prod-01`, `db-primary.nexopay.internal`, and `cache-01.nexopay.internal` — each with distinct host keys, banners, and process listings. Attackers can pivot between them; the dashboard records every hop.

### SSH fingerprint hardening

Server version string, KEX / cipher / MAC / host-key algorithm sets, and timing characteristics are aligned with Ubuntu 22.04's stock OpenSSH 8.9p1. `ssh -vvv` against the honeypot is indistinguishable from `ssh -vvv` against a real box. Boot time and host key persist under `/data` so container restarts don't reset "system uptime" to zero.

### Bash-realistic PTY

The line editor reproduces the readline behaviours attackers use to fingerprint emulators: history with up/down arrows, longest-common-prefix Tab completion, bare-name completion against the cwd, trailing space after a single completion, and proper handling of Ctrl-C / Ctrl-D / Ctrl-L.

---

## Cost and budget controls

Operating cost is dominated by LLM calls. AdaptiveWardens minimises this in three layers:

1. **Deterministic short-circuit** for the ~30 most common reconnaissance commands (`whoami`, `id`, `pwd`, `uname`, `echo …`, `which …`, etc.). Free, instant, no tokens.
2. **Response cache** keyed by normalized command + scope (global / per-user / per-cwd) with per-command TTLs. Persisted to `/data/ai_cache.db` so a restart doesn't trigger a cold-cache burst. Cached IOCs and MITRE results travel with the response so cache hits skip the extractor pass.
3. **DeepSeek prefix cache** — the system prompt is a module-level constant so DeepSeek's server-side prefix caching kicks in. Cached input tokens are ~50× cheaper than uncached.

On top of that, a **daily token budget** (persisted to `/data/llm_budget.db`) and a **per-IP sliding-window rate limit** form a circuit breaker. When either fires, `/generate-response` keeps returning sane deterministic / static output for the rest of the UTC day — sessions stay open and the attacker never sees a 500.

Indicative cost at default settings:

| Scenario                                  | Monthly LLM spend  |
| ----------------------------------------- | ------------------ |
| Default budget ceilings, all caches warm  | ~$0.10             |
| Default ceilings, worst-case cold caches  | ~$0.40             |
| 10k uncached attacker commands / month    | ~$0.35             |
| Hosting (Lightsail / EC2 t4g.small)       | $5 – $13           |

See [`docs/cost.md`](docs/cost.md) for the line-item breakdown.

---

## Observability

All AI engine and sandbox-store internals are exposed as JSON for scraping by Prometheus / Grafana / curl.

```bash
# Liveness
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health

# Cache effectiveness
curl http://localhost:8002/cache/stats
# → { "hits": 8421, "misses": 312, "bypassed": 78, "stores": 312, "hit_rate": 0.96 }

# Daily LLM spend + rate limiter
curl http://localhost:8002/budget/stats
# → { "budget": { "day_utc": "...", "input_tokens": 1234, "output_tokens": 412,
#               "input_remaining": 48766, "output_remaining": 19588,
#               "exhausted": false, "calls": 18, "blocked": 0 },
#     "rate_limit": { "tracked_ips": 4, "allowed": 18, "blocked": 0,
#                     "calls_per_window": 30, "window_seconds": 60 } }
```

The dashboard surfaces the same data graphically; the endpoints exist so you can wire alerts (e.g. PagerDuty when `budget.exhausted == true`).

---

## Dashboard

Available at <http://localhost:3000>:

- **Live Sessions** — real-time table of active SSH and HTTP attacker connections with country, risk score, and command count.
- **Attack Map** — geographic heatmap of inbound attacker IPs.
- **Session Playback** — full keystroke-level replay of any session, with per-command annotations for matched MITRE techniques and extracted IOCs.
- **IOC Summary** — extracted IPs, domains, URLs, file hashes, file paths, and named entities with severity ratings.
- **MITRE ATT&CK Mapping** — auto-mapped tactics and techniques per session, regex-matched against ~100 baked-in patterns spanning Reconnaissance through Impact.
- **Session Metrics** — totals, risk distribution, top countries, top usernames attempted.
- **Reports** — per-session narrative summaries.

---

## Slack alerts

A Slack notification is sent on every new session, enriched with country (resolved via `ip-api.com`).

### Option 1 — Incoming Webhook (recommended)

1. Create an app at <https://api.slack.com/apps>.
2. Enable **Incoming Webhooks**, add one to your target channel.
3. Set `SLACK_WEBHOOK_URL` in `.env`.

### Option 2 — Bot token

1. Add the `chat:write` scope to your app and install it in the workspace.
2. Set `SLACK_BOT_TOKEN` and `SLACK_CHANNEL` in `.env`.

---

## Operations

```bash
# Lifecycle
./start.sh                                   # bring everything up
./stop.sh                                    # tear everything down
docker compose ps                            # health overview
docker compose restart ai-engine             # restart a single service

# Logs
docker compose logs -f                       # everything
docker compose logs -f ssh-frontend          # one service
docker compose logs -f ai-engine sandbox-store

# Rebuild after code changes
docker compose build --no-cache
docker compose up -d

# Load test against the SSH honeypot
pip install asyncssh
./scripts/load_test_ssh.py -c 10 -n 50

# Failure-recovery drill
./scripts/simulate_failure.sh
```

---

## Production deployment notes (AWS)

The defaults are tuned for a single small instance; the architecture scales horizontally if you outgrow that.

- **Compute.** A Lightsail $5/mo instance or an EC2 `t4g.small` (~$13/mo on ARM) is enough for steady-state honeypot traffic. The bottleneck is concurrent attackers, not throughput.
- **Persistence.** Mount the Docker `sandbox-data` volume on an EBS volume (or Lightsail's persistent disk) — not instance store. Schedule a nightly `sqlite3 .backup` to S3.
- **Networking.** Expose port 2222 (SSH) and port 80/443 reverse-proxied to 3000 (dashboard, with auth). Keep 8001 / 8002 / 8003 internal to the security group.
- **Egress allowlist.** Outbound from the `dmz` network should reach only:
  - `api.deepseek.com:443`
  - `ip-api.com:80`
  - `hooks.slack.com:443`
  - `canarytokens.org:443` (if you use canary tokens)
- **Host SSH.** Move the real host's `sshd` off port 22 to a non-standard port, key-only. The honeypot can then bind 22 publicly for maximum attacker capture if that's your goal.
- **DNS.** A `Route53` wildcard such as `*.honeypot.example.com` is the cleanest way to expose the multi-host illusion's auxiliary hostnames.

---

## Security and responsible use

- **Accept-all authentication is intentional.** The SSH server accepts any username/password to maximise attacker capture. Never run this on a port that real users could mistake for a production gateway without explicit routing.
- **The sandbox is virtual.** All filesystem and process state is SQLite-backed; there is no real execution surface on the host. Attackers cannot pivot off the container.
- **Outbound is restricted.** Only the AI engine and dashboard egress; the sandbox and ssh-frontend are confined to the `prod-internal` Docker network.
- **Never commit `.env`** — it carries your DeepSeek key and Slack token.
- **Coordinate with your provider.** Cloud abuse teams sometimes flag honeypot traffic; deploy on infrastructure where this is permitted and notify your provider if asked.

---

## Troubleshooting

| Symptom                                                | Likely cause                                                                                                        |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| AI engine returns `bash: …: command not found` for everything | DeepSeek key missing/invalid, or daily budget exhausted (`/budget/stats` will show `exhausted: true`).        |
| Many sessions log no commands                          | The SSH client closed before requesting a PTY. The line editor only runs in PTY mode; one-shot `ssh user@host cmd` requests bypass it. |
| Dashboard empty after a fresh start                    | The sandbox-store volume is fresh — connect from SSH first to generate data.                                        |
| `docker compose ps` shows services as unhealthy        | Health checks need 10–30 seconds. If unhealthy after a minute, check `docker compose logs <service>`.               |
| `ssh -vvv` shows different algorithms than Ubuntu 22.04 | The asyncssh build dropped support for one of the advertised algorithms — check the warning in `ssh-frontend` logs. |

---

## Project structure

```
AdaptiveWardens/
├── .env.example             Centralised configuration template
├── docker-compose.yml       Orchestrates the six services + two networks
├── ssh-frontend/            AsyncSSH honeypot, PTY line editor, multi-host illusion
├── http-frontend/           Opportunistic HTTP scanner trap
├── ai-engine/               FastAPI: deterministic + cache + LLM tiers, budget gate
│   └── src/
│       ├── deterministic.py     Tier-1 short-circuits
│       ├── response_cache.py    Tier-2 SQLite cache + key normalization
│       ├── llm_provider.py      DeepSeek client, retries, output sanitization
│       ├── budget.py            Daily token ceiling
│       ├── rate_limit.py        Per-IP sliding-window limiter
│       ├── extractor.py         IOC extraction (regex + spaCy NER)
│       ├── mitre.py             ATT&CK mapping
│       └── api.py
├── sandbox-store/           FastAPI: sessions, virtual FS, IOCs, MITRE, Slack/geo
├── dashboard-backend/       Aggregation API for the SOC dashboard
├── dashboard-frontend/      Next.js SOC console
├── scripts/                 load_test_ssh.py, simulate_failure.sh, …
├── docs/                    architecture.md, cost.md
├── start.sh / stop.sh       Lifecycle helpers
└── LICENSE
```

---

## License

MIT — see [`LICENSE`](LICENSE).
