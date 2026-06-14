# Azure Container Apps Deployment Reference

## Secret Store

### GitHub Repository Secrets

| Secret | Description | Source |
|--------|-------------|--------|
| `AZURE_CREDENTIALS` | Service Principal JSON for az login | Run `scripts/azure-setup.sh` |
| `ACR_NAME` | Azure Container Registry name | `awregistry` |
| `ACR_LOGIN_SERVER` | ACR login server hostname | `awregistry.azurecr.io` |
| `ACR_USERNAME` | ACR admin username | Same as `ACR_NAME` |
| `ACR_PASSWORD` | ACR admin password | `scripts/azure-setup.sh` stores in Key Vault |
| `AZURE_RG` | Resource group name | `AdaptiveWardens` |
| `AZURE_ACA_ENV` | ACA Environment name | `aw-ca-env` |
| `STORAGE_ACCOUNT` | Storage account for file share | `awstorage` |
| `STORAGE_KEY` | Storage account access key | From `az storage account keys list` |
| `FILE_SHARE` | File share name for /data | `awdata` |
| `DEEPSEEK_API_KEY` | DeepSeek API key | https://platform.deepseek.com/api_keys |
| `DEEPSEEK_MODEL` | DeepSeek model name | `deepseek-v4-flash` |
| `DEEPSEEK_BASE_URL` | DeepSeek API base URL | `https://api.deepseek.com` |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | From Slack app config |
| `SLACK_BOT_TOKEN` | Slack bot token | From Slack app (optional if webhook used) |
| `SLACK_CHANNEL` | Slack channel for alerts | `#alerts` |
| `CANARY_AWS_ACCESS_KEY` | Canarytoken AWS key | https://canarytokens.org |
| `CANARY_AWS_SECRET_KEY` | Canarytoken AWS secret | https://canarytokens.org |
| `CANARY_STRIPE_KEY` | Canarytoken Stripe key | https://canarytokens.org |
| `CANARY_DNS_HOSTNAME` | Canarytoken DNS hostname | https://canarytokens.org |
| `JWT_SECRET` | JWT signing secret | Change from default |
| `DASHBOARD_API_KEY` | Dashboard API key for backend auth | Random string |
| `LLM_DAILY_INPUT_TOKEN_BUDGET` | Daily LLM input token cap | `50000` |
| `LLM_DAILY_OUTPUT_TOKEN_BUDGET` | Daily LLM output token cap | `20000` |
| `LLM_PER_IP_RATE_LIMIT_CALLS` | Per-IP LLM calls per window | `30` |
| `LLM_PER_IP_RATE_LIMIT_WINDOW` | Per-IP rate limit window (s) | `60` |

### Environment Variables (no secret — safe in workflow)

| Variable | Value |
|----------|-------|
| `PYTHONUNBUFFERED` | `1` (all Python services) |
| `NODE_ENV` | `production` (dashboard-frontend only) |

### Internal Service DNS (ACA environment)

| Service | Container App Name | Internal URL | Port |
|---------|-------------------|--------------|------|
| sandbox-store | `aw-sandbox-store` | `http://aw-sandbox-store` | 8001 |
| ai-engine | `aw-ai-engine` | `http://aw-ai-engine` | 8002 |
| dashboard-backend | `aw-dashboard-backend` | `http://aw-dashboard-backend` | 8003 |
| ssh-frontend | `aw-ssh-frontend` | (external TCP) | 2222 |
| http-frontend | `aw-http-frontend` | (external HTTP) | 8080 |
| dashboard-frontend | `aw-dashboard-frontend` | (external HTTP) | 3000 |

## Deploy Scenarios

### First-time deployment

```bash
# 1. Run setup script
export AZURE_LOCATION=westeurope
bash scripts/azure-setup.sh

# 2. Add all required GitHub Secrets from the output checklist

# 3. Push to main — the azure-deploy.yml workflow auto-runs
git push origin main
```

### Subsequent deployments

Push to `main` triggers the workflow automatically. The workflow detects existing container apps and uses `az containerapp update` instead of `create`.

### Rollback

```bash
# In GitHub UI: Actions → Rollback Container App → "Run workflow"
# Input the service name and the previous git SHA tag
```

Or via CLI:
```bash
az containerapp update \
  --name aw-http-frontend \
  --resource-group AdaptiveWardens \
  --image awregistry.azurecr.io/http-frontend:<previous-sha>
```

### Quick verification only

```bash
# Trigger azure-deploy.yml with verify_only=true
# This skips build & deploy, just checks all 6 services' provisioning state
```

## Cost Estimate

### Azure Resources (monthly)

| Resource | SKU | Estimated Cost/Month |
|----------|-----|---------------------|
| Resource Group | — | Free |
| Container Registry | Basic | $5.00 |
| Log Analytics | Per GB 2018 | ~$3.00 (minimal ingest) |
| ACA Environment | Consumption | Free (VNet integration = $0) |
| Container Apps (6) | Consumption (always-on) | ~$36.00 ($6 each × 6) |
| Storage Account | Standard LRS | ~$1.00 |
| File Share (10 GB) | Standard | ~$1.00 |
| Key Vault | Standard | $0.06/10K ops |
| **Total** | | **~$46.00/month** |

### Container App compute (Consumption plan)

| Service | vCPU | Memory | Monthly (always-on) |
|---------|------|--------|-------------------|
| sandbox-store | 0.5 | 1.0 Gi | ~$6.00 |
| ai-engine | 1.0 | 2.0 Gi | ~$12.00 |
| ssh-frontend | 1.0 | 2.0 Gi | ~$12.00 |
| http-frontend | 0.5 | 1.0 Gi | ~$6.00 |
| dashboard-backend | 0.5 | 1.0 Gi | ~$6.00 |
| dashboard-frontend | 0.5 | 1.0 Gi | ~$6.00 |

### LLM Token Cost (DeepSeek v4)

| Budget | Monthly Tokens | Cost |
|--------|---------------|------|
| Default (50K input / 20K output/day) | 1.5M / 600K | $0.40 worst case |
| Max aggressive (1M / 500K/day) | 30M / 15M | ~$10.00 |

**Total worst-case monthly: ~$56.00** (infra $46 + burst LLM $10)

## Final File Tree (changes)

```
AdaptiveWardens/
├── .dockerignore                          # NEW — root-level fallback
├── .github/
│   └── workflows/
│       ├── azure-deploy.yml               # NEW — ACA build + deploy
│       ├── deploy.yml                     # UNCHANGED — existing VM deploy
│       └── rollback.yml                   # NEW — manual rollback
├── ssh-frontend/
│   └── .dockerignore                     # NEW
├── http-frontend/
│   └── .dockerignore                     # NEW
├── ai-engine/
│   └── .dockerignore                     # NEW
├── sandbox-store/
│   └── .dockerignore                     # NEW
├── dashboard-backend/
│   └── .dockerignore                     # NEW
├── dashboard-frontend/
│   ├── .dockerignore                     # NEW
│   ├── Dockerfile                        # REWRITTEN — multi-stage build
│   └── next.config.mjs                   # MODIFIED — added output:'standalone'
├── docs/
│   └── aca-deployment-reference.md       # NEW — this file
└── scripts/
    └── azure-setup.sh                    # NEW — idempotent infra setup
```
