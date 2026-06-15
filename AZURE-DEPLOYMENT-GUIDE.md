# AdaptiveWardens — Complete Azure Container Apps Deployment Guide

> Feed this entire document to an AI coding assistant. It contains every file content, every Azure CLI command, every GitHub Secret, and every step needed to deploy the AdaptiveWardens honeypot to Azure Container Apps.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [File Inventory — All Files to Create](#3-file-inventory)
4. [Step 1: Create/Update the Project Files](#4-step-1-createupdate-the-project-files)
5. [Step 2: Commit and Push to GitHub](#5-step-2-commit-and-push-to-github)
6. [Step 3: Run Azure Setup Script](#6-step-3-run-azure-setup-script)
7. [Step 4: Add GitHub Secrets](#7-step-4-add-github-secrets)
8. [Step 5: Trigger the Deployment](#8-step-5-trigger-the-deployment)
9. [Step 6: Verify Everything Works](#9-step-6-verify-everything-works)
10. [Step 7: Rollback If Needed](#10-step-7-rollback-if-needed)
11. [Architecture Reference](#11-architecture-reference)
12. [Cost Breakdown](#12-cost-breakdown)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Overview

We are deploying 6 containerized services to Azure Container Apps (ACA):

| Service | Language | Port | Ingress | Purpose |
|---------|----------|------|---------|---------|
| `sandbox-store` | Python/FastAPI | 8001 | Internal | SQLite database, session state, virtual filesystem |
| `ai-engine` | Python/FastAPI | 8002 | Internal | LLM integration, token budget, response cache |
| `ssh-frontend` | Python/asyncssh | 2222 | External TCP | Fake SSH server for attackers |
| `http-frontend` | Python/FastAPI | 8080 | External HTTP | Fake web terminal for attackers |
| `dashboard-backend` | Python/FastAPI | 8003 | Internal | SOC dashboard API, reads SQLite directly |
| `dashboard-frontend` | Next.js 16 | 3000 | External HTTP | SOC dashboard UI |

**Key architecture decisions:**
- Internal services communicate via ACA-built-in DNS: `http://aw-sandbox-store`, `http://aw-ai-engine`, `http://aw-dashboard-backend`
- 4 services share an Azure File Share mounted at `/data` for persistent SQLite databases
- SSH frontend uses TCP ingress (not HTTP) on port 2222
- Secrets are stored as GitHub Secrets and injected via `--secrets` + `secretref:` in `az containerapp create/update`
- Dashboard-backend reads sandbox-store's SQLite file directly (same volume mount)
- **Azure Front Door Standard** sits in front of the HTTP honeypot and SOC dashboard, providing:
  - OWASP CRS 3.2 WAF (SQLi, XSS, LFI, RCE detection at the edge)
  - Geo-filtering (optional: restrict to target countries)
  - Per-IP rate limiting
  - Layer 7 DDoS protection
  - TLS termination with auto-renewing certs
  - Real attacker IP via `X-Forwarded-For` header

---

## 2. Prerequisites

### What you need before starting:

1. **Azure subscription** with Contributor-level access
2. **Azure CLI installed** — verify with: `az --version`
3. **GitHub account** with a fork/clone of AdaptiveWardens
4. **DeepSeek API key** — get one free at https://platform.deepseek.com/api_keys
5. **Slack webhook URL** (optional) — for attacker alerts via Slack
6. **Canarytokens** (optional) — for attacker detection: https://canarytokens.org

### Install Azure CLI (if not installed):

**Linux/macOS:**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
Remove-Item .\AzureCLI.msi
```

**Verify installation:**
```bash
az --version
az login  # opens browser to authenticate
```

---

## 3. File Inventory

Here is every file we will create or modify, grouped by location:

### Files to CREATE (13 files):

| # | File path | Content length |
|---|-----------|---------------|
| 1 | `ssh-frontend/.dockerignore` | 7 lines |
| 2 | `http-frontend/.dockerignore` | 7 lines |
| 3 | `ai-engine/.dockerignore` | 7 lines |
| 4 | `sandbox-store/.dockerignore` | 9 lines |
| 5 | `dashboard-backend/.dockerignore` | 9 lines |
| 6 | `dashboard-frontend/.dockerignore` | 13 lines |
| 7 | `scripts/azure-setup.sh` | 258 lines |
| 8 | `.github/workflows/azure-deploy.yml` | 448 lines |
| 9 | `.github/workflows/rollback.yml` | 98 lines |
| 10 | `docs/aca-deployment-reference.md` | 159 lines |
| 11 | `infra/afd-waf.bicep` | Bicep template — Front Door profile + WAF policy + security policy |
| 12 | `infra/afd-waf.parameters.json` | Parameters for Front Door Bicep deployment |

### Files to MODIFY (4 files):

| # | File path | Change |
|---|-----------|--------|
| 13 | `dashboard-frontend/Dockerfile` | Rewrite to multi-stage build |
| 14 | `dashboard-frontend/next.config.mjs` | Add `output: 'standalone'` |
| 15 | `http-frontend/src/http_server.py` | Add Front Door header handling (`X-Forwarded-For`, `X-Azure-FDID`, `X-Azure-Ref`) |
| 16 | `aca-specs/http-frontend.yaml` | Add Front Door WAF comment documentation |
| 17 | `aca-specs/dashboard-frontend.yaml` | Add Front Door WAF comment documentation |

### Files that stay UNCHANGED (they are already correct):

| File | Why it's fine |
|------|---------------|
| `ssh-frontend/Dockerfile` | Uses pinned `python:3.11-slim`, copies only `requirements.txt` then `ssh_server.py`, generates host key at runtime |
| `http-frontend/Dockerfile` | Uses pinned `python:3.11-slim`, copies `requirements.txt` then `src/` |
| `ai-engine/Dockerfile` | Uses pinned `python:3.11-slim`, copies `requirements.txt` then `src/`, installs spacy model from pinned URL |
| `sandbox-store/Dockerfile` | Uses pinned `python:3.11-slim`, copies `requirements.txt`, `src/`, `schemas/` separately, has HEALTHCHECK |
| `dashboard-backend/Dockerfile` | Uses pinned `python:3.11-slim`, simple and correct |
| `docker-compose.yml` | **DO NOT TOUCH** — local dev flow must remain intact |

---

## 4. Step 1: Create/Update the Project Files

### 4.1 Navigate to the project root

```bash
cd /path/to/AdaptiveWardens
```

### 4.2 Create `ssh-frontend/.dockerignore`

Create file `ssh-frontend/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.dockerignore
README.md
.gitignore
*.md
```

### 4.3 Create `http-frontend/.dockerignore`

Create file `http-frontend/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.dockerignore
README.md
.gitignore
*.md
```

### 4.4 Create `ai-engine/.dockerignore`

Create file `ai-engine/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.dockerignore
README.md
.gitignore
*.md
```

### 4.5 Create `sandbox-store/.dockerignore`

Create file `sandbox-store/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.dockerignore
README.md
.gitignore
*.md
data/
*.db
*.sqlite
```

### 4.6 Create `dashboard-backend/.dockerignore`

Create file `dashboard-backend/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.dockerignore
README.md
.gitignore
*.md
*.db
*.sqlite
```

### 4.7 Create `dashboard-frontend/.dockerignore`

Create file `dashboard-frontend/.dockerignore` with this exact content:

```
__pycache__
*.pyc
*.pyo
.git
.env
.env.*
.dockerignore
README.md
.gitignore
*.md
node_modules/
.next/
.turbo/
.swc/
out/
*.tsbuildinfo
npm-debug.log*
yarn-debug.log*
yarn-error.log*
```

### 4.8 Rewrite `dashboard-frontend/Dockerfile`

**Replace the entire contents** of `dashboard-frontend/Dockerfile` with:

```dockerfile
FROM node:20.18-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps

COPY . .
RUN npm run build

FROM node:20.18-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /build/public ./public
COPY --from=builder --chown=nextjs:nodejs /build/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /build/.next/static ./.next/static

USER nextjs

EXPOSE 3000

CMD ["node", "server.js"]
```

**What changed:** Old file was 6 lines with `COPY . .` and `npm run dev`. New file is multi-stage: builder stage does `npm ci` + `next build`, runner stage copies only the standalone output, runs as non-root `nextjs` user, uses production `node server.js` command.

### 4.9 Modify `dashboard-frontend/next.config.mjs`

**Replace the entire contents** of `dashboard-frontend/next.config.mjs` with:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
}

export default nextConfig
```

**What changed:** Added `output: 'standalone'` — this makes `next build` output a self-contained folder under `.next/standalone/` that includes only the files needed to run, drastically reducing Docker image size.

### 4.10 Create `scripts/azure-setup.sh`

Create file `scripts/azure-setup.sh` with this exact content:

```bash
#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# AdaptiveWardens — Azure Container Apps Infrastructure Setup
# =============================================================================
# Run this script ONCE to provision all Azure resources. It is idempotent:
# safe to re-run if a step fails partway through.
#
# Prerequisites:
#   1. az CLI installed and logged in (az login)
#   2. Azure subscription with Contributor rights
#   3. GitHub repository secret: AZURE_CREDENTIALS (service principal JSON)
#
# Usage:
#   export ARM_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
#   bash scripts/azure-setup.sh
# =============================================================================

# ── Variables ────────────────────────────────────────────────────────────────
LOCATION="${AZURE_LOCATION:-westeurope}"
RG="${AZURE_RG:-AdaptiveWardens}"
ACR_NAME="${AZURE_ACR:-awregistry}"
ACA_ENV="${AZURE_ACA_ENV:-aw-ca-env}"
LOG_ANALYTICS="${AZURE_LOG_ANALYTICS:-aw-logs}"
STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-awstorage}"
FILE_SHARE="${AZURE_FILE_SHARE:-awdata}"
KEY_VAULT="${AZURE_KEY_VAULT:-aw-kv}"
SP_NAME="${AZURE_SP_NAME:-AdaptiveWardensGH}"

# ── 1. Resource Group ───────────────────────────────────────────────────────
echo "==> Resource Group: $RG"
az group create --name "$RG" --location "$LOCATION" --tags Project=AdaptiveWardens

# ── 2. Azure Container Registry ─────────────────────────────────────────────
echo "==> Azure Container Registry: $ACR_NAME"
if ! az acr show --name "$ACR_NAME" --resource-group "$RG" &>/dev/null; then
  az acr create \
    --resource-group "$RG" \
    --name "$ACR_NAME" \
    --sku Basic \
    --admin-enabled true \
    --tags Project=AdaptiveWardens
  echo "  Created."
else
  echo "  Already exists."
fi
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --resource-group "$RG" --query loginServer -o tsv)
echo "  Login server: $ACR_LOGIN_SERVER"

# ── 3. Log Analytics Workspace ──────────────────────────────────────────────
echo "==> Log Analytics: $LOG_ANALYTICS"
if ! az monitor log-analytics workspace show \
  --workspace-name "$LOG_ANALYTICS" --resource-group "$RG" &>/dev/null; then
  az monitor log-analytics workspace create \
    --resource-group "$RG" \
    --workspace-name "$LOG_ANALYTICS" \
    --location "$LOCATION"
  echo "  Created."
else
  echo "  Already exists."
fi
LA_ID=$(az monitor log-analytics workspace show \
  --workspace-name "$LOG_ANALYTICS" --resource-group "$RG" \
  --query id -o tsv)

# ── 4. Virtual Network for ACA (required for external TCP ingress) ──────────
echo "==> VNet: $ACA_VNET_NAME"
if ! az network vnet show --name "$ACA_VNET_NAME" --resource-group "$RG" &>/dev/null; then
  az network vnet create \
    --resource-group "$RG" \
    --name "$ACA_VNET_NAME" \
    --location "$LOCATION" \
    --address-prefix "10.2.0.0/16" \
    --tags Project=AdaptiveWardens
  echo "  VNet created."
else
  echo "  Already exists."
fi
ACA_SUBNET_ID=$(az network vnet subnet show --name "$ACA_SUBNET_NAME" --vnet-name "$ACA_VNET_NAME" --resource-group "$RG" --query id -o tsv 2>/dev/null || echo "")
if [ -z "$ACA_SUBNET_ID" ]; then
  az network vnet subnet create \
    --resource-group "$RG" \
    --vnet-name "$ACA_VNET_NAME" \
    --name "$ACA_SUBNET_NAME" \
    --address-prefix "10.2.0.0/23" \
    --delegations "Microsoft.App/environments"
  ACA_SUBNET_ID=$(az network vnet subnet show --name "$ACA_SUBNET_NAME" --vnet-name "$ACA_VNET_NAME" --resource-group "$RG" --query id -o tsv)
  echo "  Subnet created."
else
  echo "  Subnet already exists."
fi

# ── 5. Container Apps Environment (with VNET) ──────────────────────────────
echo "==> ACA Environment: $ACA_ENV"
if az containerapp env show --name "$ACA_ENV" --resource-group "$RG" &>/dev/null; then
  HAS_VNET=$(az containerapp env show --name "$ACA_ENV" --resource-group "$RG" --query "properties.vnetConfiguration.infrastructureSubnetId" -o tsv 2>/dev/null || echo "")
  if [ -n "$HAS_VNET" ]; then
    echo "  Already exists with VNET."
  else
    echo "  WARNING: Recreating env without VNET. Apps will be deleted first."
    for APP in aw-sandbox-store aw-ai-engine aw-dashboard-backend aw-ssh-frontend aw-http-frontend aw-dashboard-frontend; do
      az containerapp delete --name "$APP" --resource-group "$RG" --yes 2>/dev/null || true
    done
    az containerapp env delete --name "$ACA_ENV" --resource-group "$RG" --yes
    az containerapp env create \
      --resource-group "$RG" \
      --name "$ACA_ENV" \
      --location "$LOCATION" \
      --logs-workspace-id "$LA_ID" \
      --infrastructure-subnet-resource-id "$ACA_SUBNET_ID" \
      --tags Project=AdaptiveWardens
    echo "  Recreated with VNET."
  fi
else
  az containerapp env create \
    --resource-group "$RG" \
    --name "$ACA_ENV" \
    --location "$LOCATION" \
    --logs-workspace-id "$LA_ID" \
    --infrastructure-subnet-resource-id "$ACA_SUBNET_ID" \
    --tags Project=AdaptiveWardens
  echo "  Created with VNET."
fi

# ── 5. Storage Account + File Share ─────────────────────────────────────────
echo "==> Storage Account: $STORAGE_ACCOUNT"
if ! az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RG" &>/dev/null; then
  az storage account create \
    --resource-group "$RG" \
    --name "$STORAGE_ACCOUNT" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --enable-large-file-share \
    --tags Project=AdaptiveWardens
  echo "  Created."
  sleep 15
else
  echo "  Already exists."
fi
STORAGE_KEY=$(az storage account keys list \
  --resource-group "$RG" \
  --account-name "$STORAGE_ACCOUNT" \
  --query "[0].value" -o tsv)

echo "==> File Share: $FILE_SHARE"
if ! az storage share exists \
  --name "$FILE_SHARE" \
  --account-name "$STORAGE_ACCOUNT" \
  --account-key "$STORAGE_KEY" \
  --query exists -o tsv 2>/dev/null | grep -q true; then
  az storage share create \
    --name "$FILE_SHARE" \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --quota 10
  echo "  Created (10 GB quota)."
else
  echo "  Already exists."
fi

# ── 6. Key Vault ────────────────────────────────────────────────────────────
echo "==> Key Vault: $KEY_VAULT"
if ! az keyvault show --name "$KEY_VAULT" --resource-group "$RG" &>/dev/null; then
  az keyvault create \
    --resource-group "$RG" \
    --name "$KEY_VAULT" \
    --location "$LOCATION" \
    --enable-rbac-authorization true \
    --tags Project=AdaptiveWardens
  echo "  Created."
  USER_OID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
  if [ -n "$USER_OID" ]; then
    az role assignment create \
      --role "Key Vault Secrets Officer" \
      --assignee "$USER_OID" \
      --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$KEY_VAULT"
    echo "  Granted current user Key Vault Secrets Officer."
  fi
else
  echo "  Already exists."
fi

# ── 7. Store secrets in Key Vault ───────────────────────────────────────────
echo "==> Storing default secrets in Key Vault..."
ENV_FILE=".env.example"
if [ -f "$ENV_FILE" ]; then
  while IFS='=' read -r key value || [ -n "$key" ]; do
    case "$key" in
      ''|\#*) continue ;;
    esac
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    case "$key" in
      DEEPSEEK_API_KEY|SLACK_WEBHOOK_URL|SLACK_BOT_TOKEN|SLACK_CHANNEL| \
      CANARY_AWS_ACCESS_KEY|CANARY_AWS_SECRET_KEY|CANARY_STRIPE_KEY|CANARY_DNS_HOSTNAME| \
      JWT_SECRET|DASHBOARD_PASSWORD)
        existing=$(az keyvault secret show --vault-name "$KEY_VAULT" --name "$key" --query value -o tsv 2>/dev/null || echo "")
        if [ -z "$existing" ]; then
          az keyvault secret set --vault-name "$KEY_VAULT" --name "$key" --value "$value" >/dev/null
          echo "  Set $key"
        else
          echo "  $key already set, skipped."
        fi
        ;;
    esac
  done < "$ENV_FILE"
fi

ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --resource-group "$RG" --query passwords[0].value -o tsv)
az keyvault secret set --vault-name "$KEY_VAULT" --name "ACR-PASSWORD" --value "$ACR_PASSWORD" >/dev/null
echo "  Set ACR-PASSWORD"

# ── 8. Service Principal for GitHub Actions ─────────────────────────────────
echo "==> Service Principal: $SP_NAME"
SP_EXISTS=$(az ad sp list --display-name "$SP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")
if [ -z "$SP_EXISTS" ]; then
  SUBSCRIPTION_ID=$(az account show --query id -o tsv)
  SP_JSON=$(az ad sp create-for-rbac \
    --name "$SP_NAME" \
    --role "Contributor" \
    --scopes "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG" \
    --sdk-auth)
  echo "  Created."
else
  echo "  Already exists. Resetting credentials..."
  SP_JSON=$(az ad sp credential reset --id "$SP_EXISTS" --credential-description "gh-actions-$(date +%s)" --append --output json)
fi

SP_FILE="./.azure-sp-credentials.json"
echo "$SP_JSON" > "$SP_FILE"
echo ""
echo "============================================================================="
echo "  AZURE CREDENTIALS (add to GitHub Secrets as AZURE_CREDENTIALS)"
echo "============================================================================="
cat "$SP_FILE"
echo ""
echo "============================================================================="

# ── 9. Output GitHub Secrets Reference ───────────────────────────────────────
echo ""
echo "============================================================================="
echo "  GITHUB SECRETS CHECKLIST"
echo "============================================================================="
echo ""
echo "Add these secrets to your GitHub repository:"
echo ""
echo "  Name                          | Source"
echo "  ------------------------------|--------------------------------"
echo "  AZURE_CREDENTIALS             | File .azure-sp-credentials.json (above)"
echo "  ACR_NAME                      | $ACR_NAME"
echo "  AZURE_RG                      | $RG"
echo "  AZURE_ACA_ENV                 | $ACA_ENV"
echo "  AZURE_LOCATION                | $LOCATION"
echo "  STORAGE_ACCOUNT               | $STORAGE_ACCOUNT"
echo "  STORAGE_KEY                   | (see below)"
echo "  FILE_SHARE                    | $FILE_SHARE"
echo "  KEY_VAULT                     | $KEY_VAULT"
echo "  ACR_LOGIN_SERVER              | $ACR_LOGIN_SERVER"
echo "  ACR_USERNAME                  | $ACR_NAME"
echo "  ACR_PASSWORD                  | (from Key Vault: ACR-PASSWORD)"
echo ""
echo "  STORAGE_KEY = $STORAGE_KEY"
echo ""
echo "  Key Vault secrets (set via portal or az keyvault secret set):"
echo "    DEEPSEEK_API_KEY    - DeepSeek API key"
echo "    JWT_SECRET          - JWT signing secret"
echo "    DASHBOARD_PASSWORD  - Dashboard login password"
echo "    SLACK_WEBHOOK_URL   - Slack webhook for alerts"
echo "    SLACK_BOT_TOKEN     - Slack bot token (optional)"
echo "    SLACK_CHANNEL       - Slack channel (optional)"
echo "    CANARY_AWS_ACCESS_KEY - Canary token AWS key"
echo "    CANARY_AWS_SECRET_KEY - Canary token AWS secret"
echo "    CANARY_STRIPE_KEY    - Canary token Stripe key"
echo "    CANARY_DNS_HOSTNAME  - Canary token DNS hostname"
echo ""
echo "============================================================================="
echo "Setup complete. Run the GitHub Actions workflow to deploy."
echo "============================================================================="
```

Then make it executable:

```bash
chmod +x scripts/azure-setup.sh
```

### 4.11 Create `.github/workflows/azure-deploy.yml`

Create file `.github/workflows/azure-deploy.yml` with this exact content:

```yaml
name: Azure Container Apps Deploy

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      verify_only:
        description: 'Only run verification, skip build & deploy'
        type: boolean
        default: false

env:
  AZURE_RG: ${{ secrets.AZURE_RG }}
  AZURE_ACA_ENV: ${{ secrets.AZURE_ACA_ENV }}
  ACR_NAME: ${{ secrets.ACR_NAME }}
  ACR_LOGIN_SERVER: ${{ secrets.ACR_LOGIN_SERVER }}
  STORAGE_ACCOUNT: ${{ secrets.STORAGE_ACCOUNT }}
  STORAGE_KEY: ${{ secrets.STORAGE_KEY }}
  FILE_SHARE: ${{ secrets.FILE_SHARE }}
  IMAGE_TAG: ${{ github.sha }}

jobs:
  build:
    name: Build and Push Images
    if: ${{ !inputs.verify_only }}
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service:
          - sandbox-store
          - ai-engine
          - ssh-frontend
          - http-frontend
          - dashboard-backend
          - dashboard-frontend
      fail-fast: false

    steps:
      - uses: actions/checkout@v4

      - name: Log in to ACR
        uses: azure/docker-login@v2
        with:
          login-server: ${{ env.ACR_LOGIN_SERVER }}
          username: ${{ secrets.ACR_USERNAME }}
          password: ${{ secrets.ACR_PASSWORD }}

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Docker layer caching
        uses: actions/cache@v4
        with:
          path: /tmp/.buildx-cache/${{ matrix.service }}
          key: buildx-${{ matrix.service }}-${{ hashFiles(format('{0}/requirements.txt', matrix.service), format('{0}/package-lock.json', matrix.service)) }}
          restore-keys: |
            buildx-${{ matrix.service }}-

      - name: Build and push ${{ matrix.service }}
        uses: docker/build-push-action@v6
        with:
          context: ./${{ matrix.service }}
          file: ./${{ matrix.service }}/Dockerfile
          push: true
          tags: ${{ env.ACR_LOGIN_SERVER }}/${{ matrix.service }}:${{ env.IMAGE_TAG }}
          cache-from: type=local,src=/tmp/.buildx-cache/${{ matrix.service }}
          cache-to: type=local,dest=/tmp/.buildx-cache/${{ matrix.service }},mode=max

  deploy:
    name: Deploy to ACA
    needs: [build]
    if: ${{ always() && !cancelled() && !inputs.verify_only }}
    runs-on: ubuntu-latest
    concurrency: aca-deploy

    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Register File Share storage with ACA Environment
        run: |
          az containerapp env storage set \
            --name "${{ env.AZURE_ACA_ENV }}" \
            --resource-group "${{ env.AZURE_RG }}" \
            --storage-name awdata \
            --azure-file-account-name "${{ env.STORAGE_ACCOUNT }}" \
            --azure-file-account-key "${{ env.STORAGE_KEY }}" \
            --azure-file-share-name "${{ env.FILE_SHARE }}" \
            --access-mode ReadWrite

      - name: Deploy sandbox-store
        run: |
          NAME="aw-sandbox-store"
          IMG="${{ env.ACR_LOGIN_SERVER }}/sandbox-store:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 8001 \
            --ingress internal \
            --min-replicas 1 --max-replicas 1 \
            --cpu 0.5 --memory 1.0Gi \
            $EXTRA_OPTS \
              PYTHONUNBUFFERED=1 \
              DB_PATH=/data/app_state.db \
              SLACK_WEBHOOK_URL=secretref:slack-webhook-url \
              SLACK_BOT_TOKEN=secretref:slack-bot-token \
              SLACK_CHANNEL=secretref:slack-channel \
              CANARY_AWS_ACCESS_KEY=secretref:canary-aws-access-key \
              CANARY_AWS_SECRET_KEY=secretref:canary-aws-secret-key \
              CANARY_STRIPE_KEY=secretref:canary-stripe-key \
              CANARY_DNS_HOSTNAME=secretref:canary-dns-hostname \
            --secrets \
              slack-webhook-url="${{ secrets.SLACK_WEBHOOK_URL }}" \
              slack-bot-token="${{ secrets.SLACK_BOT_TOKEN }}" \
              slack-channel="${{ secrets.SLACK_CHANNEL }}" \
              canary-aws-access-key="${{ secrets.CANARY_AWS_ACCESS_KEY }}" \
              canary-aws-secret-key="${{ secrets.CANARY_AWS_SECRET_KEY }}" \
              canary-stripe-key="${{ secrets.CANARY_STRIPE_KEY }}" \
              canary-dns-hostname="${{ secrets.CANARY_DNS_HOSTNAME }}" \
            --volume awdata:/data

      - name: Wait for sandbox-store
        run: |
          echo "Waiting for sandbox-store..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-sandbox-store \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "sandbox-store is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: sandbox-store did not become ready in time."
          exit 1

      - name: Deploy ai-engine
        run: |
          NAME="aw-ai-engine"
          IMG="${{ env.ACR_LOGIN_SERVER }}/ai-engine:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 8002 \
            --ingress internal \
            --min-replicas 1 --max-replicas 1 \
            --cpu 1.0 --memory 2.0Gi \
            $EXTRA_OPTS \
              PYTHONUNBUFFERED=1 \
              DEEPSEEK_API_KEY=secretref:deepseek-api-key \
              DEEPSEEK_MODEL=secretref:deepseek-model \
              DEEPSEEK_BASE_URL=secretref:deepseek-base-url \
              LLM_DAILY_INPUT_TOKEN_BUDGET=secretref:llm-daily-input-token-budget \
              LLM_DAILY_OUTPUT_TOKEN_BUDGET=secretref:llm-daily-output-token-budget \
              LLM_PER_IP_RATE_LIMIT_CALLS=secretref:llm-per-ip-rate-limit-calls \
              LLM_PER_IP_RATE_LIMIT_WINDOW=secretref:llm-per-ip-rate-limit-window \
              SANDBOX_URL=http://aw-sandbox-store \
            --secrets \
              deepseek-api-key="${{ secrets.DEEPSEEK_API_KEY }}" \
              deepseek-model="${{ secrets.DEEPSEEK_MODEL }}" \
              deepseek-base-url="${{ secrets.DEEPSEEK_BASE_URL }}" \
              llm-daily-input-token-budget="${{ secrets.LLM_DAILY_INPUT_TOKEN_BUDGET }}" \
              llm-daily-output-token-budget="${{ secrets.LLM_DAILY_OUTPUT_TOKEN_BUDGET }}" \
              llm-per-ip-rate-limit-calls="${{ secrets.LLM_PER_IP_RATE_LIMIT_CALLS }}" \
              llm-per-ip-rate-limit-window="${{ secrets.LLM_PER_IP_RATE_LIMIT_WINDOW }}" \
            --volume awdata:/data

      - name: Wait for ai-engine
        run: |
          echo "Waiting for ai-engine..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-ai-engine \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "ai-engine is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: ai-engine did not become ready in time."
          exit 1

      - name: Deploy dashboard-backend
        run: |
          NAME="aw-dashboard-backend"
          IMG="${{ env.ACR_LOGIN_SERVER }}/dashboard-backend:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 8003 \
            --ingress internal \
            --min-replicas 1 --max-replicas 1 \
            --cpu 0.5 --memory 1.0Gi \
            $EXTRA_OPTS \
              PYTHONUNBUFFERED=1 \
              DB_PATH=/data/app_state.db \
              DASHBOARD_API_KEY=secretref:dashboard-api-key \
            --secrets \
              dashboard-api-key="${{ secrets.DASHBOARD_API_KEY }}" \
            --volume awdata:/data

      - name: Wait for dashboard-backend
        run: |
          echo "Waiting for dashboard-backend..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-dashboard-backend \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "dashboard-backend is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: dashboard-backend did not become ready in time."
          exit 1

      - name: Deploy ssh-frontend
        run: |
          NAME="aw-ssh-frontend"
          IMG="${{ env.ACR_LOGIN_SERVER }}/ssh-frontend:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 2222 \
            --ingress external \
            --transport tcp \
            --min-replicas 1 --max-replicas 1 \
            --cpu 1.0 --memory 2.0Gi \
            $EXTRA_OPTS \
              PYTHONUNBUFFERED=1 \
              SANDBOX_URL=http://aw-sandbox-store \
              AI_ENGINE_URL=http://aw-ai-engine \
              DATA_DIR=/data \
            --volume awdata:/data

      - name: Wait for ssh-frontend
        run: |
          echo "Waiting for ssh-frontend..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-ssh-frontend \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "ssh-frontend is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: ssh-frontend did not become ready in time."
          exit 1

      - name: Deploy http-frontend
        run: |
          NAME="aw-http-frontend"
          IMG="${{ env.ACR_LOGIN_SERVER }}/http-frontend:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 8080 \
            --ingress external \
            --transport auto \
            --min-replicas 1 --max-replicas 2 \
            --cpu 0.5 --memory 1.0Gi \
            $EXTRA_OPTS \
              PYTHONUNBUFFERED=1 \
              SANDBOX_URL=http://aw-sandbox-store \
              AI_ENGINE_URL=http://aw-ai-engine

      - name: Wait for http-frontend
        run: |
          echo "Waiting for http-frontend..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-http-frontend \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "http-frontend is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: http-frontend did not become ready in time."
          exit 1

      - name: Deploy dashboard-frontend
        run: |
          NAME="aw-dashboard-frontend"
          IMG="${{ env.ACR_LOGIN_SERVER }}/dashboard-frontend:${{ env.IMAGE_TAG }}"
          if az containerapp show --name "$NAME" --resource-group "${{ env.AZURE_RG }}" &>/dev/null; then
            CMD="update"
            EXTRA_OPTS="--set-env-vars"
          else
            CMD="create"
            EXTRA_OPTS="--env-vars"
          fi
          az containerapp $CMD \
            --name "$NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --environment "${{ env.AZURE_ACA_ENV }}" \
            --image "$IMG" \
            --target-port 3000 \
            --ingress external \
            --transport auto \
            --min-replicas 1 --max-replicas 2 \
            --cpu 0.5 --memory 1.0Gi \
            $EXTRA_OPTS \
              NODE_ENV=production \
              NEXT_PUBLIC_API_URL=http://aw-dashboard-backend \
              NEXT_PUBLIC_DASHBOARD_API_KEY=secretref:dashboard-api-key \
            --secrets \
              dashboard-api-key="${{ secrets.DASHBOARD_API_KEY }}"

      - name: Wait for dashboard-frontend
        run: |
          echo "Waiting for dashboard-frontend..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name aw-dashboard-frontend \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "dashboard-frontend is ready."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: dashboard-frontend did not become ready in time."
          exit 1

      - name: Verify external endpoints
        run: |
          echo "=== Verification ==="
          for APP in aw-http-frontend aw-dashboard-frontend; do
            URL=$(az containerapp show --name "$APP" \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.configuration.ingress.fqdn -o tsv)
            echo ""
            echo "  $APP: https://$URL"
            for i in $(seq 1 10); do
              if curl -sf --connect-timeout 5 "https://${URL}/health" >/dev/null 2>&1; then
                echo "    Health check: OK"
                break
              fi
              echo "    Waiting... ($i)"
              sleep 5
            done
          done
          SSH_FQDN=$(az containerapp show --name aw-ssh-frontend \
            --resource-group "${{ env.AZURE_RG }}" \
            --query properties.configuration.ingress.fqdn -o tsv)
          echo ""
          echo "  aw-ssh-frontend: $SSH_FQDN:2222 (TCP)"

      - name: Deployment summary
        run: |
          echo ""
          echo "========================================"
          echo "  Deployment complete (sha: ${{ env.IMAGE_TAG }})"
          echo "========================================"
          for APP in aw-sandbox-store aw-ai-engine aw-dashboard-backend aw-ssh-frontend aw-http-frontend aw-dashboard-frontend; do
            FQDN=$(az containerapp show --name "$APP" \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "(internal)")
            printf "  %-25s %s\n" "$APP" "$FQDN"
          done
          echo "========================================"

  verify:
    name: Verify Deployment
    if: ${{ inputs.verify_only }}
    runs-on: ubuntu-latest
    steps:
      - name: Azure Login
        uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Check all services
        run: |
          for APP in aw-sandbox-store aw-ai-engine aw-dashboard-backend aw-ssh-frontend aw-http-frontend aw-dashboard-frontend; do
            STATUS=$(az containerapp show --name "$APP" \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "NOT FOUND")
            echo "  $APP: $STATUS"
          done
```

### 4.12 Create `.github/workflows/rollback.yml`

Create file `.github/workflows/rollback.yml` with this exact content:

```yaml
name: Rollback Container App

on:
  workflow_dispatch:
    inputs:
      service:
        description: 'Service to rollback'
        required: true
        type: choice
        options:
          - sandbox-store
          - ai-engine
          - ssh-frontend
          - http-frontend
          - dashboard-backend
          - dashboard-frontend
      image_tag:
        description: 'Image tag (git SHA) to rollback to, e.g. a1b2c3d'
        required: true
        type: string
      reason:
        description: 'Reason for rollback'
        required: false
        type: string
        default: 'Manual rollback'

env:
  AZURE_RG: ${{ secrets.AZURE_RG }}
  AZURE_ACA_ENV: ${{ secrets.AZURE_ACA_ENV }}
  ACR_LOGIN_SERVER: ${{ secrets.ACR_LOGIN_SERVER }}

jobs:
  rollback:
    name: Rollback ${{ inputs.service }} to ${{ inputs.image_tag }}
    runs-on: ubuntu-latest
    concurrency: aca-deploy

    steps:
      - name: Azure Login
        uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Check ACR tag exists
        run: |
          TAG_EXISTS=$(az acr repository show-tags \
            --name "${{ secrets.ACR_NAME }}" \
            --repository "${{ inputs.service }}" \
            --query "contains(@, '${{ inputs.image_tag }}')" \
            -o tsv 2>/dev/null || echo "false")
          if [ "$TAG_EXISTS" != "true" ]; then
            echo "ERROR: Tag ${{ inputs.image_tag }} not found in ACR repository ${{ inputs.service }}"
            echo "Available tags:"
            az acr repository show-tags --name "${{ secrets.ACR_NAME }}" --repository "${{ inputs.service }}" -o tsv
            exit 1
          fi
          echo "Tag verified."

      - name: Rollback image
        run: |
          APP_NAME="aw-${{ inputs.service }}"
          IMG="${{ env.ACR_LOGIN_SERVER }}/${{ inputs.service }}:${{ inputs.image_tag }}"
          echo "Rolling back $APP_NAME to $IMG..."
          az containerapp update \
            --name "$APP_NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --image "$IMG"

      - name: Wait for rollback to complete
        run: |
          APP_NAME="aw-${{ inputs.service }}"
          echo "Waiting for $APP_NAME to rollback..."
          for i in $(seq 1 30); do
            STATUS=$(az containerapp show --name "$APP_NAME" \
              --resource-group "${{ env.AZURE_RG }}" \
              --query properties.provisioningState -o tsv 2>/dev/null || echo "Waiting")
            echo "  Provisioning: $STATUS"
            if [ "$STATUS" = "Succeeded" ]; then
              echo "$APP_NAME rollback complete."
              exit 0
            fi
            sleep 10
          done
          echo "ERROR: Rollback did not complete in time."
          exit 1

      - name: Verify endpoint (external services)
        run: |
          APP_NAME="aw-${{ inputs.service }}"
          FQDN=$(az containerapp show --name "$APP_NAME" \
            --resource-group "${{ env.AZURE_RG }}" \
            --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || echo "")
          if [ -n "$FQDN" ]; then
            echo "  $APP_NAME: https://$FQDN"
            curl -sf --connect-timeout 10 "https://${FQDN}/health" && echo "  Health OK"
          else
            echo "  $APP_NAME has no external ingress (internal service)."
          fi
```

---

## 5. Step 2: Commit and Push to GitHub

```bash
# Make sure you're in the AdaptiveWardens directory
cd /path/to/AdaptiveWardens

# View all changes
git status

# Stage everything
git add .

# Commit with a descriptive message
git commit -m "Add ACA deployment: multi-stage Dockerfile, azure-setup, workflows, .dockerignore files"

# Push to your GitHub repository
git push origin main
```

---

## 6. Step 3: Run Azure Setup Script

Run this from your **local machine** (or Azure Cloud Shell), **NOT** from within GitHub Actions.

```bash
# 1. Log in to Azure (opens browser)
az login

# 2. Verify you have Contributor access on a subscription
az account list --output table

# 3. Set optional environment variables (or use defaults)
export AZURE_LOCATION=eastus          # or: westeurope, eastus2, etc.
export AZURE_RG=AdaptiveWardens
export AZURE_ACR=awregistry
export AZURE_ACA_ENV=aw-ca-env
export AZURE_ACA_VNET_NAME=aw-aca-vnet   # VNet for ACA external TCP ingress
export AZURE_STORAGE_ACCOUNT=awstorage  # Must be GLOBALLY UNIQUE across all Azure
# If awstorage is taken, pick a variant like awstorage42 or awstorageproject

# 4. Run the setup script
bash scripts/azure-setup.sh
```

### What the script does (in order):

| Step | Resource | Azure CLI Command |
|------|----------|-------------------|
| 1 | Resource Group | `az group create --name AdaptiveWardens --location eastus` |
| 2 | Container Registry | `az acr create --name awregistry --sku Basic --admin-enabled true` |
| 3 | Log Analytics | `az monitor log-analytics workspace create --workspace-name aw-logs` |
| 4 | VNet + Subnet (for ACA) | `az network vnet create ... && az network vnet subnet create --delegations Microsoft.App/environments` |
| 5 | ACA Environment | `az containerapp env create --name aw-ca-env --infrastructure-subnet-resource-id <SUBNET_ID>` |
| 6 | Storage Account | `az storage account create --name awstorage --sku Standard_LRS` |
| 7 | File Share | `az storage share create --name awdata --quota 10` |
| 8 | Key Vault | `az keyvault create --name aw-kv` |
| 9 | Service Principal | `az ad sp create-for-rbac --name AdaptiveWardensGH --role Contributor` |

### What the script outputs:

At the end, you'll see:

1. **AZURE_CREDENTIALS** — a JSON blob. Save this, you'll paste it into GitHub Secrets.
2. **STORAGE_KEY** — a long base64 string. Save this.
3. **Checklist** of all GitHub Secrets with their values.

A file `.azure-sp-credentials.json` is also written to disk — **keep it only until you've added the GitHub secrets, then delete it** (it's in `.gitignore` already).

---

## 7. Step 4: Add GitHub Secrets

Go to your GitHub repository in a browser:

**Settings → Secrets and variables → Actions → New repository secret**

Add each secret one by one. Use the **exact names** shown below.

### Infrastructure secrets (values from script output)

| Secret name | What to paste | How to get it |
|-------------|---------------|---------------|
| `AZURE_CREDENTIALS` | Full JSON object | From script output or `.azure-sp-credentials.json` file |
| `ACR_NAME` | `awregistry` | Default from script |
| `ACR_LOGIN_SERVER` | `awregistry.azurecr.io` | `az acr show --name awregistry --query loginServer -o tsv` |
| `ACR_USERNAME` | `awregistry` | Same as ACR_NAME |
| `ACR_PASSWORD` | admin password | `az acr credential show --name awregistry --query passwords[0].value -o tsv` |
| `AZURE_RG` | `AdaptiveWardens` | Default |
| `AZURE_ACA_ENV` | `aw-ca-env` | Default |
| `STORAGE_ACCOUNT` | `awstorage` | Default (use the name you chose) |
| `STORAGE_KEY` | base64 key | From script output or `az storage account keys list -g AdaptiveWardens -n awstorage --query "[0].value" -o tsv` |
| `FILE_SHARE` | `awdata` | Default |

### Application secrets (fill in manually)

| Secret name | Example value | Notes |
|-------------|--------------|-------|
| `DEEPSEEK_API_KEY` | `sk-abc123def456...` | Required — get from https://platform.deepseek.com/api_keys |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | Default, change if needed |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Default |
| `SLACK_WEBHOOK_URL` | `https://hooks.slack.com/services/...` | Optional — for Slack alerts |
| `SLACK_BOT_TOKEN` | `xoxb-12345...` | Optional — alternative to webhook |
| `SLACK_CHANNEL` | `#alerts` | Optional |
| `CANARY_AWS_ACCESS_KEY` | `AKIA...` | Optional — from https://canarytokens.org |
| `CANARY_AWS_SECRET_KEY` | `...` | Optional |
| `CANARY_STRIPE_KEY` | `sk_test_...` | Optional |
| `CANARY_DNS_HOSTNAME` | `abc.canarytokens.com` | Optional |
| `LLM_DAILY_INPUT_TOKEN_BUDGET` | `50000` | Daily ceiling for LLM input tokens |
| `LLM_DAILY_OUTPUT_TOKEN_BUDGET` | `20000` | Daily ceiling for LLM output tokens |
| `LLM_PER_IP_RATE_LIMIT_CALLS` | `30` | Max LLM calls per IP per window |
| `LLM_PER_IP_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `DASHBOARD_API_KEY` | `generate-a-random-32-char-string` | **Important:** generate this with `openssl rand -hex 32` or use a UUID. This is the shared secret between dashboard-frontend and dashboard-backend. |

### Front Door secrets (optional — for WAF geo-filtering)

| Secret name | What to paste | How to get it |
|-------------|---------------|---------------|
| `FRONTDOOR_FDID` | Front Door instance ID | `az afd profile show --name aw-afd -g AdaptiveWardens --query properties.frontDoorId -o tsv` (after first deployment) |

**After adding all secrets**, verify by going to Settings → Secrets → Actions. You should see at least 21 secrets listed.

---

## 8. Step 5: Trigger the Deployment

### Option A: Push to main (automatic)

```bash
git push origin main
```

This triggers the `azure-deploy.yml` workflow automatically. Go to your GitHub repo → **Actions** tab → watch the "Azure Container Apps Deploy" workflow run.

### Option B: Manual trigger

Go to GitHub → Actions → "Azure Container Apps Deploy" → "Run workflow" → (select branch) → "Run".

### What happens inside the workflow (watch the logs):

**Build job** (runs in parallel for all 6 services):

```
✓ Log in to ACR
✓ Set up Docker Buildx
✓ Docker layer caching (cache hit/miss)
  → sandbox-store: building... pushing...
  → ai-engine: building... pushing...
  → ssh-frontend: building... pushing...
  → http-frontend: building... pushing...
  → dashboard-backend: building... pushing...
  → dashboard-frontend: building... pushing...
```

**Deploy job** (runs sequentially):

```
✓ Register File Share storage with ACA Environment
  → sandbox-store: creating/updating... waiting... ✓
  → ai-engine: creating/updating... waiting... ✓
  → dashboard-backend: creating/updating... waiting... ✓
  → ssh-frontend: creating/updating (TCP 2222)... waiting... ✓
  → http-frontend: creating/updating (HTTP 8080)... waiting... ✓
  → dashboard-frontend: creating/updating (HTTP 3000)... waiting... ✓
✓ Capture ACA FQDNs for Front Door origins
✓ Deploy Front Door + WAF (Bicep template)
  → WAF Policy (OWASP CRS 3.2, geo-filter, rate-limit)
  → Front Door Standard profile
  → 2 endpoints (honeypot, dashboard)
  → Origin groups + origins pointing to ACA FQDNs
  → Routes with HTTPS redirect + WAF association
✓ Retrieving Front Door endpoints
✓ Deployment summary with all ACA + Front Door URLs
```

**Total time:** 10-18 minutes for first deployment (builds + image push + container provisioning + Front Door provisioning). Subsequent deployments are faster (layer caching, updates instead of creates).

---

## 9. Step 6: Verify Everything Works

### 9.1 Check the deployment summary

In the workflow output, the final step prints:

```
========================================
  Deployment complete (sha: a1b2c3d...)
========================================
  === Azure Container Apps ===
  aw-sandbox-store           (internal)
  aw-ai-engine               (internal)
  aw-dashboard-backend       (internal)
  aw-ssh-frontend            awesome-bush-1234.eastus.azurecontainerapps.io:2222
  aw-http-frontend           awesome-tree-5678.eastus.azurecontainerapps.io (ACA origin)
  aw-dashboard-frontend      awesome-water-9012.eastus.azurecontainerapps.io (ACA origin)

  === Azure Front Door (WAF Protected) ===
  HTTP Honeypot              https://honeypot-xxxxx.azurefd.net
  SOC Dashboard              https://dashboard-xxxxx.azurefd.net
========================================
```

**Always use the Front Door URLs** (`*.azurefd.net`) for external access to the HTTP honeypot and SOC dashboard. The ACA origin URLs are for Front Door's internal use only and bypass WAF protection.

Save the FQDNs for the external services.

### 9.2 Test HTTP honeypot (via Front Door)

```bash
# Replace with your actual Front Door hostname
FD_HOST="honeypot-xxxxx.azurefd.net"

# Test health endpoint
curl -s https://$FD_HOST/health
# Expected: {"status":"healthy"}

# Test root (should show NexoPay login page)
curl -s https://$FD_HOST | head -5
# Expected: <!DOCTYPE html> ... NexoPay — Employee Portal

# Test WAF: SQL injection attempt (should get 403 blocked)
curl -s -o /dev/null -w "%{http_code}" "https://$FD_HOST/?id=1' UNION SELECT * FROM users--"
# Expected: 403 (blocked by WAF)

# Open in browser:
# https://$FD_HOST
# You should see the attacker web terminal page
```

### 9.2b Bypass test (direct ACA access)
```bash
# Direct ACA origin access still works but bypasses WAF
ACA_HTTP=$(az containerapp show --name aw-http-frontend -g AdaptiveWardens \
  --query properties.configuration.ingress.fqdn -o tsv)
curl -s https://$ACA_HTTP/health
# Expected: still works, but no WAF protection
```

### 9.3 Test SSH honeypot

```bash
ssh root@awesome-bush-1234.eastus.azurecontainerapps.io -p 2222
# Try password: root123
# You should get a fake Linux shell
```

### 9.4 Test SOC Dashboard (via Front Door)

```bash
FD_HOST="dashboard-xxxxx.azurefd.net"

# Test health
curl -s https://$FD_HOST/health
# Expected: {"status":"healthy"}

# Open in browser:
# https://$FD_HOST
# Login with password: gradproject2025
# (or whatever you set DASHBOARD_PASSWORD to)
```

### 9.5 Verify via Azure CLI

```bash
# List all container apps
az containerapp list --resource-group AdaptiveWardens --output table

# Check logs for a specific service
az containerapp logs show --name aw-sandbox-store \
  --resource-group AdaptiveWardens \
  --tail 50

# Check revision status
az containerapp revision list \
  --name aw-http-frontend \
  --resource-group AdaptiveWardens \
  --query "[].{Name:name, Active:active, Traffic:trafficWeight, Replicas:replicas}" \
  --output table
```

### 9.6 Trigger a Verify-only run

Go to Actions → "Azure Container Apps Deploy" → "Run workflow" → check `verify_only` → "Run". This checks all 6 services' provisioning state without building or deploying anything.

---

## 10. Step 7: Rollback If Needed

If a deployment breaks a service, you can rollback to a previous image.

### Via GitHub UI:

1. Go to **Actions** tab
2. Click **"Rollback Container App"** workflow (not "Azure Container Apps Deploy")
3. Click **"Run workflow"**
4. Fill in:
   - **Service**: Select one from the dropdown (e.g., `http-frontend`)
   - **Image tag**: The git SHA of the previous working deploy (e.g., `a1b2c3d`)
   - **Reason**: Optional description
5. Click **"Run workflow"**

The workflow will:
1. Verify the tag exists in ACR
2. Run `az containerapp update --image <previous-image>`
3. Wait for the provisioning state to be "Succeeded"
4. Hit `/health` on the service if it has external ingress

### Via Azure CLI directly:

```bash
# Rollback http-frontend to a previous SHA
az containerapp update \
  --name aw-http-frontend \
  --resource-group AdaptiveWardens \
  --image awregistry.azurecr.io/http-frontend:a1b2c3d

# Verify rollback
az containerapp show --name aw-http-frontend \
  --resource-group AdaptiveWardens \
  --query properties.provisioningState -o tsv
```

### List available previous tags:

```bash
az acr repository show-tags \
  --name awregistry \
  --repository http-frontend \
  --orderby time_desc \
  -o tsv
```

---

## 11. Architecture Reference

### Service DNS Map (inside ACA)

| Container App Name | Internal URL | Used By |
|--------------------|-------------|---------|
| `aw-sandbox-store` | `http://aw-sandbox-store` | ai-engine, ssh-frontend, http-frontend |
| `aw-ai-engine` | `http://aw-ai-engine` | ssh-frontend, http-frontend |
| `aw-dashboard-backend` | `http://aw-dashboard-backend` | dashboard-frontend (via `NEXT_PUBLIC_API_URL`) |

ACA automatically resolves container app names within the same environment. No service mesh or DNS configuration needed.

### Volume Mounts (Azure File Share)

| Service | Mount Path | What it stores | Why |
|---------|-----------|----------------|-----|
| `aw-sandbox-store` | `/data` | `app_state.db` | Session state, attacker commands, virtual filesystem |
| `aw-ai-engine` | `/data` | `llm_budget.db`, `ai_cache.db` | Daily token budget counters, LLM response cache |
| `aw-ssh-frontend` | `/data` | `ssh_host_key`, `ssh_host_key.pub`, `boot_time` | SSH host key (stable fingerprint across restarts), history files |
| `aw-dashboard-backend` | `/data` | Reads `app_state.db` | Dashboard reads sandbox-store's SQLite directly (same file) |

**Critical:** dashboard-backend reads app_state.db directly via SQLite, not via HTTP. This is why it must mount the same file share path.

### Ingress Configuration

| Service | Type | Port | Transport | External URL |
|---------|------|------|-----------|-------------|
| ssh-frontend | External | 2222 | TCP | `*.azurecontainerapps.io:2222` |
| http-frontend | External | 8080 | HTTP | `*.azurecontainerapps.io` |
| dashboard-frontend | External | 3000 | HTTP | `*.azurecontainerapps.io` |
| sandbox-store | Internal | 8001 | HTTP | (not accessible from internet) |
| ai-engine | Internal | 8002 | HTTP | (not accessible from internet) |
| dashboard-backend | Internal | 8003 | HTTP | (not accessible from internet) |

### Azure Front Door + WAF Architecture

**Azure Front Door Standard** sits at the network edge, protecting the HTTP honeypot and SOC dashboard:

```
Attacker / SOC Analyst
        |
        ▼
┌─────────────────────────────────────────────┐
│         Azure Front Door Standard           │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │      WAF Policy (aw-waf-policy)       │  │
│  │  ┌─────────────────────────────────┐  │  │
│  │  │ OWASP CRS 3.2 (Managed Rules)   │  │  │
│  │  │ • SQL Injection                 │  │  │
│  │  │ • Cross-Site Scripting (XSS)    │  │  │
│  │  │ • Local File Inclusion (LFI)    │  │  │
│  │  │ • Remote Code Execution (RCE)   │  │  │
│  │  │ • Path Traversal                │  │  │
│  │  └─────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────┐  │  │
│  │  │ Custom Rules                    │  │  │
│  │  │ • Geo-filtering (country allow) │  │  │
│  │  │ • Per-IP rate limiting          │  │  │
│  │  │ • Block suspicious user-agents  │  │  │
│  │  │ • Block direct origin access    │  │  │
│  │  └─────────────────────────────────┘  │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  ┌──────────────┐   ┌──────────────────┐    │
│  │ Honeypot Endp│   │ Dashboard Endp   │    │
│  │ honeypot-*   │   │ dashboard-*      │    │
│  │ .azurefd.net │   │ .azurefd.net     │    │
│  └──────┬───────┘   └───────┬──────────┘    │
└─────────┼───────────────────┼────────────────┘
          │                   │
          ▼                   ▼
┌──────────────────┐  ┌──────────────────┐
│ aw-http-frontend │  │ aw-dashboard-    │
│ (ACA origin)     │  │ frontend (ACA)   │
│ Port 8080        │  │ Port 3000        │
│ HTTPS only       │  │ HTTPS only       │
└──────────────────┘  └──────────────────┘
```

#### Key behaviors:
- **Attacker IP**: Front Door sets `X-Forwarded-For` to the real client IP. The http-frontend code already extracts this (first value in the header).
- **TLS termination**: Front Door handles HTTPS. By default, it forwards to ACA over HTTPS (end-to-end encrypted).
- **WAF blocked requests**: Never reach the origin. The attacker receives a 403 with a reference ID.
- **Geo-filtering**: Optional. Deploy with empty `allowedCountries` to allow all (recommended for honeypot data collection).
- **Rate limiting**: 200 requests/minute per client IP (customizable via Bicep parameter).
- **DDoS protection**: Edge-level volumetric attack absorption (included with Front Door Standard).

#### Front Door resources created by infra/afd-waf.bicep:
| Resource | Type | Name |
|----------|------|------|
| WAF Policy | `Microsoft.Network/frontDoorWebApplicationFirewallPolicies` | `aw-waf-policy` |
| Front Door Profile | `Microsoft.Cdn/profiles` | `aw-afd` |
| Honeypot Endpoint | `Microsoft.Cdn/profiles/afdEndpoints` | `honeypot` |
| Dashboard Endpoint | `Microsoft.Cdn/profiles/afdEndpoints` | `dashboard` |
| Honeypot Origin Group | `Microsoft.Cdn/profiles/originGroups` | `honeypot-origin-group` |
| Dashboard Origin Group | `Microsoft.Cdn/profiles/originGroups` | `dashboard-origin-group` |
| Security Policy | `Microsoft.Cdn/profiles/securityPolicies` | `aw-afd-waf-policy` |

#### Headers added by Front Door (visible to the origin):
| Header | Value | Used by |
|--------|-------|---------|
| `X-Forwarded-For` | `<client-ip>, <edge-ip>` | http-frontend (real attacker IP) |
| `X-Forwarded-Proto` | `http` or `https` | http-frontend (protocol detection) |
| `X-Forwarded-Host` | Original host header | http-frontend (host detection) |
| `X-Azure-ClientIP` | `<client-ip>` | http-frontend (fallback IP source) |
| `X-Azure-Ref` | `<correlation-id>` | http-frontend (request tracing) |
| `X-Azure-FDID` | `<front-door-id>` | http-frontend (FD verification) |

### Required Environment Variables Per Service

**sandbox-store:**
- `PYTHONUNBUFFERED=1`
- `DB_PATH=/data/app_state.db`
- `SLACK_WEBHOOK_URL` (secretref)
- `SLACK_BOT_TOKEN` (secretref)
- `SLACK_CHANNEL` (secretref)
- `CANARY_AWS_ACCESS_KEY` (secretref)
- `CANARY_AWS_SECRET_KEY` (secretref)
- `CANARY_STRIPE_KEY` (secretref)
- `CANARY_DNS_HOSTNAME` (secretref)

**ai-engine:**
- `PYTHONUNBUFFERED=1`
- `DEEPSEEK_API_KEY` (secretref)
- `DEEPSEEK_MODEL` (secretref)
- `DEEPSEEK_BASE_URL` (secretref)
- `LLM_DAILY_INPUT_TOKEN_BUDGET` (secretref)
- `LLM_DAILY_OUTPUT_TOKEN_BUDGET` (secretref)
- `LLM_PER_IP_RATE_LIMIT_CALLS` (secretref)
- `LLM_PER_IP_RATE_LIMIT_WINDOW` (secretref)
- `SANDBOX_URL=http://aw-sandbox-store`

**ssh-frontend:**
- `PYTHONUNBUFFERED=1`
- `SANDBOX_URL=http://aw-sandbox-store`
- `AI_ENGINE_URL=http://aw-ai-engine`
- `DATA_DIR=/data`

**http-frontend:**
- `PYTHONUNBUFFERED=1`
- `SANDBOX_URL=http://aw-sandbox-store`
- `AI_ENGINE_URL=http://aw-ai-engine`
- `FRONTDOOR_FDID=` (optional — if set, validates X-Azure-FDID header)

**dashboard-backend:**
- `PYTHONUNBUFFERED=1`
- `DB_PATH=/data/app_state.db`
- `DASHBOARD_API_KEY` (secretref)

**dashboard-frontend:**
- `NODE_ENV=production`
- `NEXT_PUBLIC_API_URL=http://aw-dashboard-backend`
- `NEXT_PUBLIC_DASHBOARD_API_KEY` (secretref)

---

## 12. Cost Breakdown

### Azure Infrastructure ($78/month)

| Resource | SKU | Monthly Cost |
|----------|-----|-------------|
| Azure Container Registry | Basic | $5.00 |
| Log Analytics Workspace | Per GB 2018 | ~$3.00 |
| ACA Environment | Consumption plan | Free |
| sandbox-store (0.5 CPU, 1 GB RAM) | Consumption, always-on | ~$6.00 |
| ai-engine (1.0 CPU, 2 GB RAM) | Consumption, always-on | ~$12.00 |
| ssh-frontend (1.0 CPU, 2 GB RAM) | Consumption, always-on | ~$12.00 |
| http-frontend (0.5 CPU, 1 GB RAM) | Consumption, always-on | ~$6.00 |
| dashboard-backend (0.5 CPU, 1 GB RAM) | Consumption, always-on | ~$6.00 |
| dashboard-frontend (0.5 CPU, 1 GB RAM) | Consumption, always-on | ~$6.00 |
| Storage Account + File Share (10 GB) | Standard LRS | ~$2.00 |
| Key Vault | Standard | ~$0.06 |
| Azure Front Door Standard | Standard | ~$20.00 |
| Front Door WAF Policy | Standard | ~$5.00 |
| **Total** | | **~$83.00** |

### Savings tip
Set `--min-replicas 0` on non-critical services (dashboard-frontend, dashboard-backend) — they scale to zero when idle. Only sandbox-store and ai-engine need to stay warm for SSH/HTTP responsiveness.

### LLM Token Cost (~$0.40-10.00/month)

| Budget | Monthly Tokens | Cost |
|--------|---------------|------|
| Default (50K input / 20K output per day) | 1.5M / 600K | $0.40 |
| Aggressive (1M / 500K per day) | 30M / 15M | ~$10.00 |

**Total worst case: ~$68/month** (infrastructure + aggressive LLM usage).

---

## 13. Troubleshooting

### Problem: Workflow fails at "Register File Share"

**Cause:** Wrong STORAGE_KEY in GitHub Secrets.
**Fix:**
```bash
az storage account keys list \
  --resource-group AdaptiveWardens \
  --account-name awstorage \
  --query "[0].value" -o tsv
```
Update the `STORAGE_KEY` GitHub secret with the output.

### Problem: Service stuck at "Waiting..." for >5 minutes

**Cause:** Container is failing to start (image pull error, app crash, or health check failure).
**Fix:** Check the logs:
```bash
az containerapp logs show --name aw-sandbox-store -g AdaptiveWardens --tail 100
az containerapp logs show --name aw-ai-engine -g AdaptiveWardens --tail 100
```

### Problem: "ResourceNotFound" during deployment

**Cause:** The ACR image tag doesn't exist (build step was skipped or failed).
**Fix:** Push again to trigger a fresh build, or trigger the workflow manually.

### Problem: SSH honeypot doesn't accept connections

**Cause 1:** SSH frontend has wrong SANDBOX_URL or no file share mounted.
```bash
az containerapp show --name aw-ssh-frontend -g AdaptiveWardens \
  --query properties.template.containers[0].env
# Verify: SANDBOX_URL=http://aw-sandbox-store, AI_ENGINE_URL=http://aw-ai-engine
```

**Cause 2:** SSH ingress is not TCP.
```bash
az containerapp show --name aw-ssh-frontend -g AdaptiveWardens \
  --query properties.configuration.ingress
# Verify: "transport": "tcp" and "targetPort": 2222
```

### Problem: Dashboard shows no data

**Cause:** dashboard-backend can't read the SQLite database. Both sandbox-store and dashboard-backend must mount the same Azure File Share at `/data`.
```bash
az containerapp show --name aw-dashboard-backend -g AdaptiveWardens \
  --query properties.template.volumes
# Verify: "storageName": "awdata", "mountPath": "/data"
```

### Problem: Next.js frontend shows blank page

**Cause:** `NEXT_PUBLIC_API_URL` is wrong or the API key doesn't match.
```bash
az containerapp show --name aw-dashboard-frontend -g AdaptiveWardens \
  --query properties.template.containers[0].env
# Verify: NEXT_PUBLIC_API_URL=http://aw-dashboard-backend
```

### Problem: ACR name is taken ("awregistry already exists")

**Fix:** Choose a different name:
```bash
export AZURE_ACR=awregistry42  # or any unique name
bash scripts/azure-setup.sh
```
Then update all GitHub secrets that reference ACR_NAME, ACR_LOGIN_SERVER, ACR_USERNAME, ACR_PASSWORD.

### Problem: Storage account name is taken

**Fix:** Same as ACR — choose a globally unique name:
```bash
export AZURE_STORAGE_ACCOUNT=awstorage42
bash scripts/azure-setup.sh
```
Update `STORAGE_ACCOUNT` and `STORAGE_KEY` GitHub secrets.

### Problem: Front Door WAF blocks legitimate traffic

**Cause 1:** Geo-filtering is blocking a country you want to allow.
**Fix:** Redeploy with updated allowed countries:
```bash
# Use the AFD-only workflow input:
# allowed_countries: "US,GB,CA,AU,DE,FR,NL,SE,NO,DK,FI,IE,JP,SG,BR,IN"
```
Or via CLI:
```bash
az deployment group create -g AdaptiveWardens --template-file infra/afd-waf.bicep \
  --parameters wafPolicyName=aw-waf-policy frontDoorName=aw-afd \
    honeyEndpointName=honeypot dashEndpointName=dashboard \
    httpFrontendFqdn="$HTTP_FQDN" dashboardFrontendFqdn="$DASH_FQDN" \
    dashboardBackendFqdn="$DASH_BACKEND_FQDN" \
    allowedCountries='["US","GB","CA"]' rateLimitThreshold=200
```

**Cause 2:** Rate limit is too aggressive.
**Fix:** Increase `rateLimitThreshold` in the Bicep parameters (default: 200/min).

**Cause 3:** OWASP rules are false-positives for the dashboard.
**Fix:** Add exclusions to the WAF managed rules in `infra/afd-waf.bicep`.

### Problem: Front Door shows "Origin not reachable"

**Cause:** The ACA origin FQDNs have changed (e.g., after re-deploying the ACA environment).
**Fix:** Run the "Azure Container Apps Deploy" workflow with `afd_only=true` to update Front Door origins with the current ACA FQDNs.

### Problem: X-Forwarded-For shows Front Door IP instead of real client IP

**Cause:** The network flow is direct to ACA instead of through Front Door.
**Fix:** Ensure clients access the Front Door endpoint (`*.azurefd.net`) instead of the ACA origin URL (`*.azurecontainerapps.io`). The http-frontend code extracts the first IP from X-Forwarded-For when present.

### Problem: Need to reset the service principal password

```bash
az ad sp credential reset \
  --id $(az ad sp list --display-name AdaptiveWardensGH --query "[0].appId -o tsv)" \
  --create-cert
```
Update `AZURE_CREDENTIALS` GitHub secret with the new JSON output.

---

> **End of deployment guide.** Save this file as `AZURE-DEPLOYMENT-GUIDE.md` in the repo root. Feed the entire file to any AI assistant to replicate the deployment.
