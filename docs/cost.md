# AdaptiveWardens Cost Awareness

Operating a high-interaction, AI-supported honeypot implies recurring scaling costs mostly dictated by language model usage.

## AI Engine Costs (DeepSeek - default)
AdaptiveWardens uses `deepseek-v4-flash` in non-thinking mode via DeepSeek's OpenAI-compatible API.
- **Input (cache miss)**: $0.14 / 1M tokens
- **Input (cache hit)**: $0.0028 / 1M tokens
- **Output**: $0.28 / 1M tokens
- **Average Interaction Metric**: ~150 prompt tokens + ~50 output tokens per SSH command.
- **Per-call cost**: ~$0.000035 uncached; ~$0.000014 with server-side prefix caching.
- **Monthly Approximation**: 10,000 attacker commands ≈ **$0.10 - $0.35 / month**.

*(Note: The in-process 5-minute `ResponseCache` short-circuits repeated commands entirely, dropping the effective rate further.)*

## Budget Circuit Breaker
A hard daily ceiling on LLM token spend is enforced in `ai-engine/src/budget.py`
and persisted to `/data/llm_budget.db`, so a redeploy can't reset the day's
counter mid-attack. Defaults:

- `LLM_DAILY_INPUT_TOKEN_BUDGET=50000` (≈ $0.007/day worst case at uncached prices)
- `LLM_DAILY_OUTPUT_TOKEN_BUDGET=20000` (≈ $0.006/day)
- `LLM_PER_IP_RATE_LIMIT_CALLS=30` per `LLM_PER_IP_RATE_LIMIT_WINDOW=60s`

When either daily ceiling is hit, `/generate-response` keeps returning sane
deterministic / static output for the rest of the UTC day — sessions stay open
and attackers never see a 500. Counters reset at 00:00 UTC. Inspect live state
via `GET /budget/stats` on the AI engine.

Cache-key normalization in `response_cache.py` collapses whitespace and sorts
short-flag clusters for common reconnaissance verbs (`ls`, `ps`, `du`, `df`,
`find`, `grep`, …), so `ls -la`, `ls -al`, `ls -a -l` all collide on one row.
Real-world cache hit rate climbs noticeably with this alone.


## Hosting and Infrastructure
The microservices require minimal computational resources:
- **Minimum Requirements**: 1 vCPU, 1 GB RAM. 
- **Standard Cloud VM (AWS T3.micro / DigitalOcean Basic droplet)**: ~$4 - $6 per month.
- **Storage**: Highly dependent on the amount of collected attacker logs. SQLite scales natively on disk. 25GB volume is recommended ($2 - $5 per month).

## Summary
The total monthly cost footprint for running an independent cluster of AdaptiveWardens is **~$5.00** assuming basic VPS allocation.
