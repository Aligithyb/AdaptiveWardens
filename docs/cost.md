# AdaptiveWardens Cost Awareness

Operating a high-interaction, AI-supported honeypot implies recurring scaling costs mostly dictated by language model usage.

## AI Engine Costs (Google Gemini)
AdaptiveWardens leverages `gemini-2.5-flash-lite`, the most efficient tier available under the Gemini umbrella.
- **Estimated Prompt Cost**: $0.075 / 1 Million Tokens.
- **Estimated Response Cost**: $0.30 / 1 Million Tokens.
- **Average Interaction Metric**: A standard SSH command + its session context uses about 150 prompt tokens and generates 50 output tokens.
- **Monthly Approximation**: Simulating 10,000 distinct AI-triggered attacker commands costs approximately **$0.02 - $0.05 per month**.

*(Note: Cache collisions naturally reduce cost to $0.00 since repeated commands fetch cached data without hitting Gemini).*

## Hosting and Infrastructure
The microservices require minimal computational resources:
- **Minimum Requirements**: 1 vCPU, 1 GB RAM. 
- **Standard Cloud VM (AWS T3.micro / DigitalOcean Basic droplet)**: ~$4 - $6 per month.
- **Storage**: Highly dependent on the amount of collected attacker logs. SQLite scales natively on disk. 25GB volume is recommended ($2 - $5 per month).

## Summary
The total monthly cost footprint for running an independent cluster of AdaptiveWardens is **~$5.00** assuming basic VPS allocation.
