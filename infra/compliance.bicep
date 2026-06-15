@description('Azure region (use same as ACA — swedencentral)')
param location string

@description('Log Analytics workspace name')
param logAnalyticsName string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

@description('Key Vault name')
param keyVaultName string

@description('Storage account name')
param storageAccountName string

@description('Resource group name')
param rgName string

@description('Subscription ID')
param subscriptionId string

// ── Log Analytics: set 365-day retention for compliance ──
// Note: Defender for Cloud pricing is enabled via Azure CLI in the workflow
// (requires subscription-level permissions — cannot be done at RG scope)
resource laWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsName
}

resource laRetention 'Microsoft.OperationalInsights/workspaces/tables@2023-01-01-preview' = if (!empty(logAnalyticsName)) {
  name: '${logAnalyticsName}/AzureActivity'
  properties: {
    retentionInDays: 365
    totalRetentionInDays: 365
    plan: 'Analytics'
  }
  dependsOn: [
    laWorkspace
  ]
}

// ── Storage Account Diagnostic Settings ──
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource storageDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'aw-compliance-diag'
  scope: storageAccount
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'StorageRead', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
      { category: 'StorageWrite', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
      { category: 'StorageDelete', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
    ]
    metrics: [
      { category: 'Transaction', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
    ]
  }
}

// ── Key Vault Diagnostic Settings ──
resource keyVault 'Microsoft.KeyVault/vaults@2022-11-01' existing = {
  name: keyVaultName
}

resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'aw-compliance-diag'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'AuditEvent', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true, retentionPolicy: { enabled: true, days: 365 } }
    ]
  }
}

// ── Azure Policy: ISO 27001:2013 built-in initiative assignment ──
resource iso27001Assignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'iso27001-aw-${uniqueString(resourceGroup().id)}'
  properties: {
    displayName: 'ISO 27001:2013 - AdaptiveWardens Compliance'
    description: 'Built-in ISO 27001:2013 policy initiative assigned at deployment'
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
    scope: resourceGroup().id
    enforcementMode: 'DoNotEnforce'
    parameters: {}
    nonComplianceMessages: [
      { message: 'Resource is not ISO 27001:2013 compliant' }
    ]
  }
}

// ── Azure Policy: SOC 2 Type II built-in initiative assignment ──
resource soc2Assignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'soc2-aw-${uniqueString(resourceGroup().id)}'
  properties: {
    displayName: 'SOC 2 Type II - AdaptiveWardens Compliance'
    description: 'Built-in SOC 2 Type II policy initiative assigned at deployment'
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/e64b2e1b-9a07-4bb6-9e0f-982a36b8cb91'
    scope: resourceGroup().id
    enforcementMode: 'DoNotEnforce'
    parameters: {}
    nonComplianceMessages: [
      { message: 'Resource is not SOC 2 Type II compliant' }
    ]
  }
}

// ── Azure Policy: NIST SP 800-53 Rev. 5 built-in initiative assignment ──
resource nistAssignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'nist80053-aw-${uniqueString(resourceGroup().id)}'
  properties: {
    displayName: 'NIST SP 800-53 Rev. 5 - AdaptiveWardens Compliance'
    description: 'Built-in NIST SP 800-53 Rev. 5 policy initiative assigned at deployment'
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f'
    scope: resourceGroup().id
    enforcementMode: 'DoNotEnforce'
    parameters: {}
    nonComplianceMessages: [
      { message: 'Resource is not NIST SP 800-53 Rev. 5 compliant' }
    ]
  }
}

// ── Outputs ──
output defenderPricingTier string = 'Standard'
output iso27001AssignmentId string = iso27001Assignment.id
output soc2AssignmentId string = soc2Assignment.id
output nistAssignmentId string = nistAssignment.id
