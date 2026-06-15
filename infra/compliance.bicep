@description('Log Analytics workspace name')
param logAnalyticsName string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

@description('Key Vault name')
param keyVaultName string

@description('Storage account name')
param storageAccountName string

// ── Log Analytics: set 365-day retention for compliance ──
// Note: Defender for Cloud pricing + Policy assignments are done via
// Azure CLI in the workflow (requires broader permissions).

resource laWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsName
}

resource laRetention 'Microsoft.OperationalInsights/workspaces/tables@2023-01-01-preview' = if (!empty(logAnalyticsName)) {
  parent: laWorkspace
  name: 'AzureActivity'
  properties: {
    retentionInDays: 365
    totalRetentionInDays: 365
    plan: 'Analytics'
  }
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
