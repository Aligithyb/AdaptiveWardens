@description('Name of the Front Door Web Application Firewall policy')
param wafPolicyName string

@description('Name of the Front Door Standard profile')
param frontDoorName string

@description('Endpoint name for HTTP honeypot (e.g. honeypot)')
param honeyEndpointName string

@description('Endpoint name for SOC dashboard (e.g. dashboard)')
param dashEndpointName string

@description('FQDN of the HTTP honeypot ACA app')
param httpFrontendFqdn string

@description('FQDN of the dashboard frontend ACA app')
param dashboardFrontendFqdn string

@description('FQDN of the dashboard backend ACA app (for API calls)')
param dashboardBackendFqdn string

@description('ISO country codes to allow (empty = all allowed)')
param allowedCountries array = []

@description('Max requests per IP per minute (0 = disabled)')
param rateLimitThreshold int = 200

// ── WAF Policy ──────────────────────────────────────────────────────────
resource wafPolicy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: wafPolicyName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: 'Enabled'
      customBlockResponseStatusCode: 403
      customBlockResponseBody: base64('{"error":"blocked","message":"Request blocked by AdaptiveWardens WAF policy","policy":"${wafPolicyName}"}')
    }
    customRules: {
      rules: [
        {
          name: 'GeoFilter'
          priority: 10
          ruleType: 'MatchRule'
          action: 'Block'
          enabledState: 'Enabled'
          matchConditions: [
            {
              matchVariable: 'RemoteAddr'
              operator: 'GeoMatch'
              negateCondition: true
              matchValue: allowedCountries
              selector: null
              transforms: []
            }
          ]
        }
        {
          name: 'RateLimitPerIP'
          priority: 20
          ruleType: 'RateLimitRule'
          action: 'Block'
          enabledState: 'Enabled'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: rateLimitThreshold
          groupBy: [
            {
              variableName: 'SocketAddr'
            }
          ]
          matchConditions: [
            {
              matchVariable: 'RemoteAddr'
              operator: 'IPMatch'
              negateCondition: false
              matchValue: ['*']
              transforms: []
            }
          ]
        }
        {
          name: 'BlockDirectOriginAccess'
          priority: 30
          ruleType: 'MatchRule'
          action: 'Block'
          enabledState: 'Enabled'
          matchConditions: [
            {
              matchVariable: 'RequestHeader'
              selector: 'X-Forwarded-Host'
              operator: 'Equal'
              negateCondition: false
              matchValue: ['localhost']
              transforms: ['Lowercase']
            }
          ]
        }
        {
          name: 'BlockSuspiciousUA'
          priority: 40
          ruleType: 'MatchRule'
          action: 'Block'
          enabledState: 'Enabled'
          matchConditions: [
            {
              matchVariable: 'RequestHeader'
              selector: 'User-Agent'
              operator: 'Contains'
              negateCondition: false
              matchValue: ['Nmap', 'masscan', 'Zgrab', 'sqlmap', 'nuclei']
              transforms: ['Lowercase']
            }
          ]
        }
      ]
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
          ruleSetAction: 'Block'
          exclusions: [
            {
              matchVariable: 'RequestHeaderNames'
              selector: 'User-Agent'
              selectorMatchOperator: 'Equals'
            }
          ]
        }
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
        }
      ]
    }
  }
}

// ── Front Door Standard Profile ─────────────────────────────────────────
resource afd 'Microsoft.Cdn/profiles@2024-06-01-preview' = {
  name: frontDoorName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
  properties: {
    originResponseTimeoutSeconds: 60
  }
}

// ── Origin Groups ───────────────────────────────────────────────────────
resource honeyOriginGroup 'Microsoft.Cdn/profiles/originGroups@2024-06-01-preview' = {
  parent: afd
  name: 'honeypot-origin-group'
  properties: {
    healthProbeSettings: {
      probePath: '/health'
      probeRequestType: 'GET'
      probeProtocol: 'Http'
      probeIntervalInSeconds: 60
    }
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    sessionAffinityState: 'Disabled'
  }
}

resource honeyOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-06-01-preview' = {
  parent: honeyOriginGroup
  name: 'http-frontend-origin'
  properties: {
    hostName: httpFrontendFqdn
    httpPort: 80
    httpsPort: 443
    enabledState: 'Enabled'
    priority: 1
    weight: 100
    originHostHeader: httpFrontendFqdn
    enforceCertificateNameCheck: true
  }
}

resource dashOriginGroup 'Microsoft.Cdn/profiles/originGroups@2024-06-01-preview' = {
  parent: afd
  name: 'dashboard-origin-group'
  properties: {
    healthProbeSettings: {
      probePath: '/health'
      probeRequestType: 'GET'
      probeProtocol: 'Http'
      probeIntervalInSeconds: 60
    }
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    sessionAffinityState: 'Disabled'
  }
}

resource dashFrontendOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-06-01-preview' = {
  parent: dashOriginGroup
  name: 'dashboard-frontend-origin'
  properties: {
    hostName: dashboardFrontendFqdn
    httpPort: 80
    httpsPort: 443
    enabledState: 'Enabled'
    priority: 1
    weight: 100
    originHostHeader: dashboardFrontendFqdn
    enforceCertificateNameCheck: true
  }
}

resource dashBackendOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-06-01-preview' = {
  parent: dashOriginGroup
  name: 'dashboard-backend-origin'
  properties: {
    hostName: dashboardBackendFqdn
    httpPort: 80
    httpsPort: 443
    enabledState: 'Enabled'
    priority: 2
    weight: 50
    originHostHeader: dashboardBackendFqdn
    enforceCertificateNameCheck: true
  }
}

// ── Front Door Endpoints ────────────────────────────────────────────────
resource honeyEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-06-01-preview' = {
  parent: afd
  name: honeyEndpointName
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

resource dashEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-06-01-preview' = {
  parent: afd
  name: dashEndpointName
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

// ── Routes ──────────────────────────────────────────────────────────────
resource honeyRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-06-01-preview' = {
  parent: honeyEndpoint
  name: 'honeypot-default-route'
  properties: {
    originGroup: honeyOriginGroup
    supportedProtocols: ['Http', 'Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        contentTypesToCompress: ['text/html', 'text/plain', 'text/css', 'application/javascript', 'application/json', 'text/javascript']
        isCompressionEnabled: true
      }
    }
  }
}

resource dashRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-06-01-preview' = {
  parent: dashEndpoint
  name: 'dashboard-default-route'
  properties: {
    originGroup: dashOriginGroup
    supportedProtocols: ['Http', 'Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    cacheConfiguration: {
      queryStringCachingBehavior: 'IgnoreQueryString'
      compressionSettings: {
        contentTypesToCompress: ['text/html', 'text/plain', 'text/css', 'application/javascript', 'application/json', 'text/javascript']
        isCompressionEnabled: true
      }
    }
  }
}

// ── Security Policy: Links WAF to Front Door domains ───────────────────
resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2024-06-01-preview' = {
  parent: afd
  name: '${frontDoorName}-waf-policy'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: {
        id: wafPolicy.id
      }
      associations: [
        {
          domains: [
            { id: honeyEndpoint.id }
            { id: dashEndpoint.id }
          ]
          patternsToMatch: ['/*']
        }
      ]
    }
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────
output honeyEndpointHostname string = honeyEndpoint.properties.hostName
output dashEndpointHostname string = dashEndpoint.properties.hostName
output frontDoorId string = afd.id
output wafPolicyId string = wafPolicy.id
