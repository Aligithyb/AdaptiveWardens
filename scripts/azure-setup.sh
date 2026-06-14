#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# AdaptiveWardens — Azure Container Apps Infrastructure Setup
# =============================================================================
# Run this ONCE from your local machine to create all Azure resources.
# Safe to re-run: each step checks for existing resources before creating.
#
# Usage:
#   az login
#   bash scripts/azure-setup.sh
#
# Optional overrides (set as env vars before running):
#   export AZURE_LOCATION=eastus
#   export AZURE_RG=AdaptiveWardens
#   export AZURE_ACR=awregistry
#   export AZURE_STORAGE_ACCOUNT=awstorage42   # must be globally unique!
# =============================================================================

# ── User-configurable variables ──────────────────────────────────────────────
# Only edit these if you want different names. Storage account must be globally
# unique across all of Azure (3-24 chars, lowercase letters and numbers only).

LOCATION="${AZURE_LOCATION:-westeurope}"
RG="${AZURE_RG:-AdaptiveWardens}"
ACR_NAME="${AZURE_ACR:-awregistry}"
ACA_ENV="${AZURE_ACA_ENV:-aw-ca-env}"
LOG_ANALYTICS="${AZURE_LOG_ANALYTICS:-aw-logs}"
STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-awstorage}"
FILE_SHARE="${AZURE_FILE_SHARE:-awdata}"
KEY_VAULT="${AZURE_KEY_VAULT:-aw-kv}"
SP_NAME="${AZURE_SP_NAME:-AdaptiveWardensGH}"

echo ""
echo "============================================================================="
echo "  AdaptiveWardens — Azure Infrastructure Setup"
echo "============================================================================="
echo "  Resource Group  : $RG"
echo "  Location        : $LOCATION"
echo "  ACR             : $ACR_NAME"
echo "  ACA Environment : $ACA_ENV"
echo "  Storage Account : $STORAGE_ACCOUNT"
echo "  File Share      : $FILE_SHARE"
echo "  Key Vault       : $KEY_VAULT"
echo "  Service Principal: $SP_NAME"
echo "============================================================================="
echo ""

# ── 1. Resource Group ────────────────────────────────────────────────────────
echo "[1/8] Resource Group: $RG"
az group create \
  --name "$RG" \
  --location "$LOCATION" \
  --tags Project=AdaptiveWardens \
  --output none
echo "  Done."

# ── 2. Azure Container Registry ──────────────────────────────────────────────
echo "[2/8] Azure Container Registry: $ACR_NAME"
if ! az acr show --name "$ACR_NAME" --resource-group "$RG" &>/dev/null; then
  az acr create \
    --resource-group "$RG" \
    --name "$ACR_NAME" \
    --sku Basic \
    --admin-enabled true \
    --tags Project=AdaptiveWardens \
    --output none
  echo "  Created."
else
  echo "  Already exists — skipping."
fi
ACR_LOGIN_SERVER=$(az acr show \
  --name "$ACR_NAME" \
  --resource-group "$RG" \
  --query loginServer -o tsv)
ACR_PASSWORD=$(az acr credential show \
  --name "$ACR_NAME" \
  --resource-group "$RG" \
  --query "passwords[0].value" -o tsv)
echo "  Login server: $ACR_LOGIN_SERVER"

# ── 3. Log Analytics Workspace ───────────────────────────────────────────────
echo "[3/8] Log Analytics Workspace: $LOG_ANALYTICS"
if ! az monitor log-analytics workspace show \
  --workspace-name "$LOG_ANALYTICS" \
  --resource-group "$RG" &>/dev/null; then
  az monitor log-analytics workspace create \
    --resource-group "$RG" \
    --workspace-name "$LOG_ANALYTICS" \
    --location "$LOCATION" \
    --output none
  echo "  Created."
else
  echo "  Already exists — skipping."
fi
LA_ID=$(az monitor log-analytics workspace show \
  --workspace-name "$LOG_ANALYTICS" \
  --resource-group "$RG" \
  --query id -o tsv)

# ── 4. Container Apps Environment ────────────────────────────────────────────
echo "[4/8] ACA Environment: $ACA_ENV"
if ! az containerapp env show \
  --name "$ACA_ENV" \
  --resource-group "$RG" &>/dev/null; then
  az containerapp env create \
    --resource-group "$RG" \
    --name "$ACA_ENV" \
    --location "$LOCATION" \
    --logs-workspace-id "$LA_ID" \
    --tags Project=AdaptiveWardens \
    --output none
  echo "  Created."
else
  echo "  Already exists — skipping."
fi

# ── 5. Storage Account ───────────────────────────────────────────────────────
echo "[5/8] Storage Account: $STORAGE_ACCOUNT"
if ! az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RG" &>/dev/null; then
  az storage account create \
    --resource-group "$RG" \
    --name "$STORAGE_ACCOUNT" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --enable-large-file-share \
    --tags Project=AdaptiveWardens \
    --output none
  echo "  Created. Waiting 15s for propagation..."
  sleep 15
else
  echo "  Already exists — skipping."
fi
STORAGE_KEY=$(az storage account keys list \
  --resource-group "$RG" \
  --account-name "$STORAGE_ACCOUNT" \
  --query "[0].value" -o tsv)

# ── 6. Azure File Share ──────────────────────────────────────────────────────
echo "[6/8] File Share: $FILE_SHARE"
SHARE_EXISTS=$(az storage share exists \
  --name "$FILE_SHARE" \
  --account-name "$STORAGE_ACCOUNT" \
  --account-key "$STORAGE_KEY" \
  --query exists -o tsv 2>/dev/null || echo "false")
if [ "$SHARE_EXISTS" != "true" ]; then
  az storage share create \
    --name "$FILE_SHARE" \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --quota 10 \
    --output none
  echo "  Created (10 GB quota)."
else
  echo "  Already exists — skipping."
fi

# ── 7. Key Vault ─────────────────────────────────────────────────────────────
echo "[7/8] Key Vault: $KEY_VAULT"
if ! az keyvault show \
  --name "$KEY_VAULT" \
  --resource-group "$RG" &>/dev/null; then
  az keyvault create \
    --resource-group "$RG" \
    --name "$KEY_VAULT" \
    --location "$LOCATION" \
    --enable-rbac-authorization true \
    --tags Project=AdaptiveWardens \
    --output none
  echo "  Created."
  # Grant current user access
  USER_OID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
  if [ -n "$USER_OID" ]; then
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    az role assignment create \
      --role "Key Vault Secrets Officer" \
      --assignee "$USER_OID" \
      --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$KEY_VAULT" \
      --output none
    echo "  Granted Key Vault Secrets Officer to current user."
  fi
else
  echo "  Already exists — skipping."
fi

# ── 8. Service Principal for GitHub Actions ──────────────────────────────────
echo "[8/8] Service Principal: $SP_NAME"
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SP_EXISTS=$(az ad sp list \
  --display-name "$SP_NAME" \
  --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [ -z "$SP_EXISTS" ]; then
  SP_JSON=$(az ad sp create-for-rbac \
    --name "$SP_NAME" \
    --role "Contributor" \
    --scopes "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG" \
    --sdk-auth)
  echo "  Created."
else
  echo "  Already exists — resetting credentials..."
  SP_JSON=$(az ad sp credential reset \
    --id "$SP_EXISTS" \
    --credential-description "gh-actions-$(date +%s)" \
    --append \
    --output json)
fi

SP_FILE="./.azure-sp-credentials.json"
echo "$SP_JSON" > "$SP_FILE"

# ── Final Output ─────────────────────────────────────────────────────────────
echo ""
echo "============================================================================="
echo "  SETUP COMPLETE"
echo "============================================================================="
echo ""
echo "  All Azure resources are ready. Now add these GitHub Secrets:"
echo ""
echo "  ┌─────────────────────────────┬───────────────────────────────────────────┐"
echo "  │ Secret Name                 │ Value                                     │"
echo "  ├─────────────────────────────┼───────────────────────────────────────────┤"
echo "  │ AZURE_CREDENTIALS           │ (see .azure-sp-credentials.json below)    │"
echo "  │ ACR_NAME                    │ $ACR_NAME"
echo "  │ ACR_LOGIN_SERVER            │ $ACR_LOGIN_SERVER"
echo "  │ ACR_USERNAME                │ $ACR_NAME"
echo "  │ ACR_PASSWORD                │ $ACR_PASSWORD"
echo "  │ AZURE_RG                    │ $RG"
echo "  │ AZURE_ACA_ENV               │ $ACA_ENV"
echo "  │ STORAGE_ACCOUNT             │ $STORAGE_ACCOUNT"
echo "  │ STORAGE_KEY                 │ $STORAGE_KEY"
echo "  │ FILE_SHARE                  │ $FILE_SHARE"
echo "  └─────────────────────────────┴───────────────────────────────────────────┘"
echo ""
echo "  AZURE_CREDENTIALS (paste this entire JSON into the GitHub Secret):"
echo ""
cat "$SP_FILE"
echo ""
echo "============================================================================="
echo "  MANUAL SECRETS (you must provide these values):"
echo "============================================================================="
echo "  DEEPSEEK_API_KEY          → platform.deepseek.com/api_keys"
echo "  DEEPSEEK_MODEL            → deepseek-v4-flash"
echo "  DEEPSEEK_BASE_URL         → https://api.deepseek.com"
echo "  LLM_DAILY_INPUT_TOKEN_BUDGET  → 50000"
echo "  LLM_DAILY_OUTPUT_TOKEN_BUDGET → 20000"
echo "  LLM_PER_IP_RATE_LIMIT_CALLS  → 30"
echo "  LLM_PER_IP_RATE_LIMIT_WINDOW → 60"
echo "  SLACK_WEBHOOK_URL         → https://hooks.slack.com/services/..."
echo "  SLACK_BOT_TOKEN           → xoxb-... (optional)"
echo "  SLACK_CHANNEL             → #alerts (optional)"
echo "  CANARY_AWS_ACCESS_KEY     → canarytokens.org (optional)"
echo "  CANARY_AWS_SECRET_KEY     → canarytokens.org (optional)"
echo "  CANARY_STRIPE_KEY         → canarytokens.org (optional)"
echo "  CANARY_DNS_HOSTNAME       → canarytokens.org (optional)"
echo "  DASHBOARD_API_KEY         → run: openssl rand -hex 32"
echo ""
echo "  After adding all secrets, push to main to trigger deployment."
echo "  Delete .azure-sp-credentials.json once you've saved the secret."
echo "============================================================================="
