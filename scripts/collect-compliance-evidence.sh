#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# AdaptiveWardens — Compliance Evidence Collector
# =============================================================================
# Collects compliance evidence for SOC 2, ISO 27001, and NIST SP 800-53.
# Called from GitHub Actions after each deployment.
#
# Usage:
#   bash scripts/collect-compliance-evidence.sh
#
# Environment variables (set by GitHub Actions):
#   AZURE_RG, STORAGE_ACCOUNT, STORAGE_KEY, IMAGE_TAG
# =============================================================================

RG="${AZURE_RG:-AdaptiveWardens}"
STORAGE="${STORAGE_ACCOUNT:-}"
STORAGE_KEY="${STORAGE_KEY:-}"
TAG="${IMAGE_TAG:-unknown}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_DIR="./compliance-evidence"

mkdir -p "$OUTPUT_DIR"

echo ""
echo "============================================================================="
echo "  Compliance Evidence Collection"
echo "  Resource Group : $RG"
echo "  Timestamp      : $TIMESTAMP"
echo "  Image Tag      : $TAG"
echo "============================================================================="
echo ""

# ── 1. Azure Policy Compliance ─────────────────────────────────────────────────
echo "[1/8] Policy compliance state..."
POLICY_FILE="$OUTPUT_DIR/policy-compliance-$TAG.json"
az policy state list --resource-group "$RG" \
  --query "[].{resourceId:resourceId, policyDefinitionName:policyDefinitionName, policySetDefinitionName:policySetDefinitionName, effect:effect, complianceState:complianceState, timestamp:timestamp}" \
  -o json > "$POLICY_FILE" 2>/dev/null || echo '[]' > "$POLICY_FILE"

TOTAL_POLICIES=$(jq '. | length' "$POLICY_FILE" 2>/dev/null || echo 0)
NON_COMPLIANT=$(jq '[.[] | select(.complianceState=="NonCompliant")] | length' "$POLICY_FILE" 2>/dev/null || echo 0)
COMPLIANT=$(jq '[.[] | select(.complianceState=="Compliant")] | length' "$POLICY_FILE" 2>/dev/null || echo 0)
echo "  Total evaluations: $TOTAL_POLICIES"
echo "  Compliant: $COMPLIANT  Non-compliant: $NON_COMPLIANT"

# ── 2. Defender for Cloud Secure Score ─────────────────────────────────────────
echo "[2/8] Defender for Cloud secure score..."
SCORE_FILE="$OUTPUT_DIR/secure-score-$TAG.json"
az security secure-score-controls list \
  --query "[].{name:name, displayName:displayName, currentScore:currentScore, maxScore:maxScore, percentage:percentage, healthyResourceCount:healthyResourceCount, unhealthyResourceCount:unhealthyResourceCount}" \
  -o json > "$SCORE_FILE" 2>/dev/null || echo '[]' > "$SCORE_FILE"

TOTAL_SCORE=$(jq '[.[].currentScore | select(. != null)] | add // 0' "$SCORE_FILE" 2>/dev/null || echo 0)
TOTAL_MAX=$(jq '[.[].maxScore | select(. != null)] | add // 0' "$SCORE_FILE" 2>/dev/null || echo 0)
echo "  Secure score: $TOTAL_SCORE / $TOTAL_MAX"

# ── 3. Activity Log (last 24h) ────────────────────────────────────────────────
echo "[3/8] Activity logs (last 24h)..."
ACTIVITY_FILE="$OUTPUT_DIR/activity-log-$TAG.json"
SINCE=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
if [ -n "$SINCE" ]; then
  az monitor activity-log list \
    --resource-group "$RG" \
    --start-time "$SINCE" \
    --query "[].{time:eventTimestamp, caller:caller, action:operationName.value, status:status.value, resourceType:resourceType}" \
    -o json > "$ACTIVITY_FILE" 2>/dev/null || echo '[]' > "$ACTIVITY_FILE"
else
  echo '[]' > "$ACTIVITY_FILE"
fi
ACTIVITY_COUNT=$(jq '. | length' "$ACTIVITY_FILE" 2>/dev/null || echo 0)
echo "  Operations in last 24h: $ACTIVITY_COUNT"

# ── 4. Container App Configurations ───────────────────────────────────────────
echo "[4/8] Container app configurations..."
CA_FILE="$OUTPUT_DIR/container-apps-$TAG.json"
echo '[]' > "$CA_FILE"
for APP in aw-sandbox-store aw-ai-engine aw-ssh-frontend aw-http-frontend aw-dashboard-backend aw-dashboard-frontend; do
  CONFIG=$(az containerapp show --name "$APP" --resource-group "$RG" \
    --query "{name:name, image:properties.template.containers[0].image, cpu:properties.template.containers[0].resources.cpu, memory:properties.template.containers[0].resources.memory, minReplicas:properties.template.scale.minReplicas, maxReplicas:properties.template.scale.maxReplicas, ingress:properties.configuration.ingress.external, targetPort:properties.configuration.ingress.targetPort}" \
    -o json 2>/dev/null || echo "null")
  if [ "$CONFIG" != "null" ] && [ -n "$CONFIG" ]; then
    TMP=$(mktemp)
    jq ". + [${CONFIG}]" "$CA_FILE" > "$TMP" && mv "$TMP" "$CA_FILE"
  fi
done

# ── 5. WAF Configuration ──────────────────────────────────────────────────────
echo "[5/8] WAF configuration..."
WAF_FILE="$OUTPUT_DIR/waf-config-$TAG.json"
az network application-gateway waf-policy show \
  --name aw-waf-policy --resource-group "$RG" \
  --query "{mode:properties.policySettings.mode, state:properties.policySettings.state, rulesets:properties.managedRules.managedRuleSets[].{type:ruleSetType,version:ruleSetVersion}, customRules:properties.customRules[].{name:name, action:action, priority:priority}}" \
  -o json > "$WAF_FILE" 2>/dev/null || echo '{"mode":"unknown","state":"unknown"}' > "$WAF_FILE"

WAF_MODE=$(jq -r '.mode // "unknown"' "$WAF_FILE")
echo "  WAF mode: $WAF_MODE"

# ── 6. Container App Revisions ────────────────────────────────────────────────
echo "[6/8] Container app revision status..."
REV_FILE="$OUTPUT_DIR/revisions-$TAG.json"
echo '[]' > "$REV_FILE"
for APP in aw-sandbox-store aw-ai-engine aw-ssh-frontend aw-http-frontend aw-dashboard-backend aw-dashboard-frontend; do
  REV=$(az containerapp revision list \
    --name "$APP" --resource-group "$RG" \
    --query "[].{name:name, active:active, trafficWeight:trafficWeight, replicas:replicas, createdTime:createdTime}" \
    -o json 2>/dev/null || echo "[]")
  if [ "$REV" != "[]" ] && [ -n "$REV" ]; then
    TMP=$(mktemp)
    jq ". + [{\"app\":\"$APP\", \"revisions\": $REV}]" "$REV_FILE" > "$TMP" && mv "$TMP" "$REV_FILE"
  fi
done

# ── 7. Network Security Assessment ────────────────────────────────────────────
echo "[7/8] Network security assessment..."
NET_FILE="$OUTPUT_DIR/network-security-$TAG.json"
az network application-gateway show \
  --name aw-appgw --resource-group "$RG" \
  --query "{name:name, sku:sku.name, tier:sku.tier, enableHttp2:enableHttp2, backendPools:properties.backendAddressPools[].{name:name, fqdns:properties.backendAddresses[].fqdn}, listeners:properties.httpListeners[].{name:name, protocol:protocol}}" \
  -o json > "$NET_FILE" 2>/dev/null || echo '{"status":"unavailable"}' > "$NET_FILE"

# ── 8. Generate Compliance Summary ───────────────────────────────────────────
echo "[8/8] Generating compliance summary..."

# Calculate overall compliance percentage
if [ "$TOTAL_POLICIES" -gt 0 ]; then
  COMPLIANCE_PCT=$(echo "scale=2; $COMPLIANT * 100 / $TOTAL_POLICIES" | bc 2>/dev/null || echo "0")
else
  COMPLIANCE_PCT="N/A"
fi

SUMMARY_FILE="$OUTPUT_DIR/summary-$TAG.json"
jq -n \
  --arg ts "$TIMESTAMP" \
  --arg rg "$RG" \
  --arg tag "$TAG" \
  --argjson totalPolicies "$TOTAL_POLICIES" \
  --argjson compliant "$COMPLIANT" \
  --argjson nonCompliant "$NON_COMPLIANT" \
  --arg compliancePct "$COMPLIANCE_PCT" \
  --argjson totalScore "${TOTAL_SCORE:-0}" \
  --argjson maxScore "${TOTAL_MAX:-0}" \
  --argjson activityCount "${ACTIVITY_COUNT:-0}" \
  --arg wafMode "$WAF_MODE" \
  '{
    timestamp: $ts,
    resourceGroup: $rg,
    imageTag: $tag,
    policy: {
      totalEvaluations: $totalPolicies,
      compliant: $compliant,
      nonCompliant: $nonCompliant,
      compliancePercent: $compliancePct
    },
    secureScore: {
      currentScore: $totalScore,
      maxScore: $maxScore
    },
    activityLog: {
      operationsLast24h: $activityCount
    },
    waf: {
      mode: $wafMode
    },
    status: "evidence_collected"
  }' > "$SUMMARY_FILE"

echo ""
echo "============================================================================="
echo "  Summary"
echo "============================================================================="
echo "  Policy compliance  : $COMPLIANT/$TOTAL_POLICIES compliant ($COMPLIANCE_PCT%)"
echo "  Secure score       : $TOTAL_SCORE / $TOTAL_MAX"
echo "  Activity (24h)     : $ACTIVITY_COUNT operations"
echo "  WAF mode           : $WAF_MODE"
echo "============================================================================="
echo ""
echo "Evidence saved to: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
echo ""
echo "Collection complete."
