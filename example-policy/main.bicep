// Example Azure Firewall Policy with inline IP addresses
// Simplified for demo - 3 Rule Collection Groups, ~12 rules, targeting ~10 IP Groups after migration

@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the Firewall Policy')
param policyName string = 'fw-policy-inline-ips'

@description('Tier of the Firewall Policy')
@allowed([
  'Standard'
  'Premium'
])
param policyTier string = 'Premium'

// Azure Firewall Policy
resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-11-01' = {
  name: policyName
  location: location
  properties: {
    sku: {
      tier: policyTier
    }
    threatIntelMode: 'Alert'
    dnsSettings: {
      enableProxy: true
    }
    intrusionDetection: policyTier == 'Premium' ? {
      mode: 'Alert'
    } : null
  }
}

// Rule Collection Group 1 - Infrastructure (AD, DNS, Management)
resource infraRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-11-01' = {
  parent: firewallPolicy
  name: 'InfrastructureRules'
  properties: {
    priority: 100
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'ActiveDirectory-DNS'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'Allow-DNS-To-DomainControllers'
            description: 'Allow DNS traffic to domain controllers'
            ipProtocols: ['UDP', 'TCP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
              '10.5.0.0/24'
            ]
            destinationAddresses: [
              '192.168.1.10'
              '192.168.1.11'
              '192.168.1.12'
            ]
            destinationPorts: ['53']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-LDAP-To-DomainControllers'
            description: 'Allow LDAP/LDAPS traffic to domain controllers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
              '10.5.0.0/24'
            ]
            destinationAddresses: [
              '192.168.1.10'
              '192.168.1.11'
              '192.168.1.12'
            ]
            destinationPorts: ['389', '636']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-Kerberos-To-DomainControllers'
            description: 'Allow Kerberos authentication'
            ipProtocols: ['TCP', 'UDP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
              '10.5.0.0/24'
            ]
            destinationAddresses: [
              '192.168.1.10'
              '192.168.1.11'
              '192.168.1.12'
            ]
            destinationPorts: ['88']
          }
        ]
      }
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'Management-Access'
        priority: 200
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'Allow-SSH-From-JumpBoxes'
            description: 'Allow SSH from jump boxes to Linux servers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.0.0.10'
              '10.0.0.11'
              '10.0.0.12'
            ]
            destinationAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
            ]
            destinationPorts: ['22']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-RDP-From-JumpBoxes'
            description: 'Allow RDP from jump boxes to Windows servers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.0.0.10'
              '10.0.0.11'
              '10.0.0.12'
            ]
            destinationAddresses: [
              '10.1.2.0/24'
              '10.2.2.0/24'
            ]
            destinationPorts: ['3389']
          }
        ]
      }
    ]
  }
}

// Rule Collection Group 2 - Application Rules (Azure, GitHub, Updates)
resource appRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-11-01' = {
  parent: firewallPolicy
  name: 'ApplicationRules'
  dependsOn: [infraRuleCollectionGroup]
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'Azure-Services'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'Allow-Azure-Management'
            description: 'Allow Azure portal and management'
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
              '10.5.0.0/24'
            ]
            protocols: [{protocolType: 'Https', port: 443}]
            targetFqdns: [
              'portal.azure.com'
              '*.portal.azure.com'
              'management.azure.com'
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'Allow-GitHub'
            description: 'Allow GitHub for source control'
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.5.0.0/24'
            ]
            protocols: [{protocolType: 'Https', port: 443}]
            targetFqdns: [
              'github.com'
              '*.github.com'
              'api.github.com'
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'Allow-Windows-Update'
            description: 'Allow Windows Update'
            sourceAddresses: [
              '10.1.2.0/24'
              '10.2.2.0/24'
            ]
            protocols: [
              {protocolType: 'Https', port: 443}
              {protocolType: 'Http', port: 80}
            ]
            targetFqdns: [
              'windowsupdate.microsoft.com'
              '*.windowsupdate.microsoft.com'
              'update.microsoft.com'
            ]
          }
        ]
      }
    ]
  }
}

// Rule Collection Group 3 - Database Access
resource dbRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-11-01' = {
  parent: firewallPolicy
  name: 'DatabaseRules'
  dependsOn: [appRuleCollectionGroup]
  properties: {
    priority: 300
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'Database-Access'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'Allow-SQL-From-AppServers'
            description: 'Allow SQL Server from app servers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
            ]
            destinationAddresses: [
              '10.3.1.10'
              '10.3.1.11'
            ]
            destinationPorts: ['1433']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-PostgreSQL-From-AppServers'
            description: 'Allow PostgreSQL from app servers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.5.0.0/24'
            ]
            destinationAddresses: [
              '10.3.2.10'
              '10.3.2.11'
            ]
            destinationPorts: ['5432']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-Redis-From-AppServers'
            description: 'Allow Redis cache from app servers'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
            ]
            destinationAddresses: [
              '10.3.3.10'
              '10.3.3.11'
            ]
            destinationPorts: ['6379']
          }
          {
            ruleType: 'NetworkRule'
            name: 'Allow-Monitoring-To-All'
            description: 'Allow monitoring server to scrape metrics'
            ipProtocols: ['TCP']
            sourceAddresses: [
              '192.168.100.10'
            ]
            destinationAddresses: [
              '10.1.0.0/24'
              '10.1.1.0/24'
              '10.2.0.0/24'
              '10.3.1.10'
              '10.3.1.11'
              '10.3.2.10'
              '10.3.2.11'
              '10.3.3.10'
              '10.3.3.11'
            ]
            destinationPorts: ['9090', '9100']
          }
        ]
      }
    ]
  }
}

output policyId string = firewallPolicy.id
output policyName string = firewallPolicy.name
