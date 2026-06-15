@description('Name of the WAF policy (Application Gateway)')
param wafPolicyName string

@description('Name of the Application Gateway')
param appGwName string

@description('Azure region (use same as ACA — swedencentral)')
param location string

@description('FQDN of the HTTP honeypot ACA app')
param httpFrontendFqdn string

@description('FQDN of the dashboard frontend ACA app')
param dashboardFrontendFqdn string

@description('ISO country codes to allow (empty = all allowed)')
param allowedCountries array = []

var subnetName = 'appgw-subnet'
var publicIpName = '${appGwName}-pip'
var vnetName = '${appGwName}-vnet'

var geoRules = empty(allowedCountries) ? [] : [
  {
    name: 'GeoFilter'
    priority: 10
    ruleType: 'MatchRule'
    action: 'Block'
    matchConditions: [
      {
        matchVariables: [
          { variableName: 'RemoteAddr', selector: null }
        ]
        operator: 'GeoMatch'
        negationConditon: true
        transforms: []
        matchValues: allowedCountries
      }
    ]
  }
]
var otherRules = [
  {
    name: 'BlockSuspiciousUA'
    priority: 20
    ruleType: 'MatchRule'
    action: 'Block'
    matchConditions: [
      {
        matchVariables: [
          { variableName: 'RequestHeaders', selector: 'User-Agent' }
        ]
        operator: 'Contains'
        negationConditon: false
        transforms: ['Lowercase']
        matchValues: ['nmap', 'masscan', 'zgrab', 'sqlmap', 'nuclei', 'nikto', 'dirbuster']
      }
    ]
  }
  {
    name: 'BlockSensitivePaths'
    priority: 30
    ruleType: 'MatchRule'
    action: 'Block'
    matchConditions: [
      {
        matchVariables: [
          { variableName: 'RequestUri', selector: null }
        ]
        operator: 'Contains'
        negationConditon: false
        transforms: ['Lowercase']
        matchValues: ['.env', '.git/config', 'wp-admin', 'phpmyadmin', 'actuator/', '/admin/', 'aws_access_key']
      }
    ]
  }
]
var customRules = concat(geoRules, otherRules)

resource wafPolicy 'Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies@2022-09-01' = {
  name: wafPolicyName
  location: location
  properties: {
    policySettings: {
      state: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: true
      fileUploadLimitInMb: 100
      maxRequestBodySizeInKb: 128
    }
    customRules: customRules
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
        }
      ]
      exclusions: [
        {
          matchVariable: 'RequestHeaderNames'
          selector: 'User-Agent'
          selectorMatchOperator: 'Equals'
        }
      ]
    }
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2022-09-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2022-09-01' = {
  name: publicIpName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource appGw 'Microsoft.Network/applicationGateways@2022-09-01' = {
  name: appGwName
  location: location
  dependsOn: [
    vnet
  ]
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
      capacity: 2
    }
    gatewayIPConfigurations: [
      {
        name: 'appGwIpConfig'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName)
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'appGwFrontend'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port-80'
        properties: { port: 80 }
      }
    ]
    backendAddressPools: [
      {
        name: 'http-honeypool'
        properties: {
          backendAddresses: [
            { fqdn: httpFrontendFqdn }
          ]
        }
      }
      {
        name: 'dashboard-pool'
        properties: {
          backendAddresses: [
            { fqdn: dashboardFrontendFqdn }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'https-honeypot-setting'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          requestTimeout: 30
          pickHostNameFromBackendAddress: true
        }
      }
      {
        name: 'https-dashboard-setting'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          requestTimeout: 30
          pickHostNameFromBackendAddress: true
        }
      }
    ]
    httpListeners: [
      {
        name: 'public-listener'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', appGwName, 'appGwFrontend')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', appGwName, 'port-80')
          }
          protocol: 'Http'
          requireServerNameIndication: false
        }
      }
    ]
    urlPathMaps: [
      {
        name: 'aw-url-path-map'
        properties: {
          defaultBackendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appGwName, 'http-honeypool')
          }
          defaultBackendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', appGwName, 'https-honeypot-setting')
          }
          pathRules: [
            {
              name: 'dashboard-path'
              properties: {
                paths: [
                  '/dashboard/*'
                ]
                backendAddressPool: {
                  id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appGwName, 'dashboard-pool')
                }
                backendHttpSettings: {
                  id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', appGwName, 'https-dashboard-setting')
                }
              }
            }
          ]
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'main-rule'
        properties: {
          priority: 10
          ruleType: 'PathBasedRouting'
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', appGwName, 'public-listener')
          }
          urlPathMap: {
            id: resourceId('Microsoft.Network/applicationGateways/urlPathMaps', appGwName, 'aw-url-path-map')
          }
        }
      }
    ]
    firewallPolicy: {
      id: wafPolicy.id
    }
    enableHttp2: false
  }
}

output appGwPublicIp string = publicIp.properties.ipAddress
output appGwId string = appGw.id
output wafPolicyId string = wafPolicy.id
