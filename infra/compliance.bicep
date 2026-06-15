@description('Log Analytics workspace name')
param logAnalyticsName string

// ── Log Analytics: set 365-day retention for compliance audit trail ──
// Diagnostic settings and Defender for Cloud are configured via Azure CLI
// in the workflow (more reliable across resource types).

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

resource laContainerAppsConsole 'Microsoft.OperationalInsights/workspaces/tables@2023-01-01-preview' = if (!empty(logAnalyticsName)) {
  parent: laWorkspace
  name: 'ContainerAppConsoleLogs'
  properties: {
    retentionInDays: 90
    totalRetentionInDays: 90
    plan: 'Analytics'
  }
}
