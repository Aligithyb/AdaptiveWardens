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


## Hosting and Infrastructure
The microservices require minimal computational resources:
- **Minimum Requirements**: 1 vCPU, 1 GB RAM. 
- **Standard Cloud VM (AWS T3.micro / DigitalOcean Basic droplet)**: ~$4 - $6 per month.
- **Storage**: Highly dependent on the amount of collected attacker logs. SQLite scales natively on disk. 25GB volume is recommended ($2 - $5 per month).

## Summary
The total monthly cost footprint for running an independent cluster of AdaptiveWardens is **~$5.00** assuming basic VPS allocation.
