# Azure Firewall Policy Migration - Inline IPs to IP Groups

This project provides tools to migrate an Azure Firewall Policy from using inline IP addresses to using IP Groups, which improves manageability, reusability, and helps stay within Azure Firewall limits.

## Why Migrate to IP Groups?

- **Reusability**: IP Groups can be shared across multiple rules and policies
- **Manageability**: Update IP addresses in one place instead of multiple rules
- **Scalability**: IP Groups support up to 5,000 IP addresses per group
- **Limits**: Azure Firewall has limits on unique source/destination combinations; IP Groups help optimize this
- **Auditing**: Easier to track and audit IP address changes

## Project Structure

```
azure-firewall-policy/
├── example-policy/
│   ├── main.bicep              # Example policy with inline IPs (for testing)
│   └── deploy.ps1              # Deploy the example policy
├── scripts/
│   ├── Export-FirewallPolicy.ps1    # Export policy and extract IPs
│   └── Migrate-ToIPGroups.ps1       # Create IP Groups and new policy
└── README.md
```

## Prerequisites

- Azure PowerShell modules:
  - `Az.Network`
  - `Az.Resources`
- Azure subscription with contributor access
- Existing Azure Firewall Policy (or use the example)

## Getting Started

```bash
# Clone the repository
git clone https://github.com/colinweiner111/azure-firewall-policy-migration.git
cd azure-firewall-policy-migration

# Install required PowerShell modules (if not already installed)
Install-Module -Name Az.Network -Scope CurrentUser
Install-Module -Name Az.Resources -Scope CurrentUser

# Connect to Azure
Connect-AzAccount
```

## Quick Start

### Option A: Use Your Own Policy (Recommended)

Migrate any existing Azure Firewall Policy - no example deployment needed:

```powershell
cd scripts

# Step 1: Export and analyze your policy
.\Export-FirewallPolicy.ps1 `
    -ResourceGroupName "your-resource-group" `
    -PolicyName "your-firewall-policy"
```

This creates an export directory (e.g., `firewall-policy-export-20260127-120000`) with all the extracted IP information.

> 💡 **Before continuing:** Review the export directory to understand what IP Groups will be created. See [Understanding the Export](#understanding-the-export) for details on each file.

```powershell
# Step 2: Create IP Groups and new policy
.\Migrate-ToIPGroups.ps1 `
    -ResourceGroupName "your-resource-group" `
    -PolicyName "your-firewall-policy" `
    -ExportPath ".\firewall-policy-export-YYYYMMDD-HHMMSS" `
    -NewPolicyName "your-policy-ipgroups"
```

Or create the new policy and IP Groups in a different resource group:

```powershell
.\Migrate-ToIPGroups.ps1 `
    -ResourceGroupName "rg-source-firewall" `
    -PolicyName "fw-policy-prod" `
    -ExportPath ".\firewall-policy-export-YYYYMMDD-HHMMSS" `
    -NewPolicyName "fw-policy-prod-ipgroups" `
    -NewPolicyResourceGroup "rg-firewall-new"
```

### Option B: Test with Example Policy

If you want to test the migration workflow without risking production:

**Step 1: Deploy the example policy**
```powershell
cd example-policy
.\deploy.ps1 -ResourceGroupName "rg-firewall-demo" -Location "eastus"
```

**Step 2: Run the migration**
```powershell
cd ..\scripts
.\Migrate-ToIPGroups.ps1 -ResourceGroupName "rg-firewall-demo" -PolicyName "fw-policy-inline-ips" -ConsolidateIPGroups
```

The example creates a sample policy with 3 Rule Collection Groups, 12 rules, and various inline IPs.

---

## Understanding the Export

After running `Export-FirewallPolicy.ps1`, review the export directory before migrating. This helps you understand what IP Groups will be created and validate the extraction.

### Export Directory Structure

```
firewall-policy-export-YYYYMMDD-HHMMSS/
├── policy-full.json          # Complete policy export (for reference)
├── rule-ip-mapping.csv       # Maps each rule to its source/destination IPs
├── ip-group-suggestions.json # Proposed IP Groups with their addresses
├── ip-group-mapping.csv      # Template for custom IP Group names (edit this!)
├── source-ips.json           # All unique source IPs extracted
├── destination-ips.json      # All unique destination IPs extracted
└── summary.txt               # Human-readable summary
```

### Key Files to Review

#### 1. summary.txt
Quick overview of what was found:
```
Export Summary
==============
Policy: fw-original-policy
Rule Collection Groups: 3
Total Rules: 12
Unique Source IPs/CIDRs: 8
Unique Destination IPs/CIDRs: 13
Suggested IP Groups: 21 (or fewer with consolidation)
```

#### 2. ip-group-suggestions.json
Shows exactly what IP Groups will be created:
```json
[
  {
    "Name": "ipg-AllowADDNS-Source",
    "Addresses": ["10.1.0.0/24", "10.2.0.0/24"],
    "UsedInRules": ["AllowADDNS"],
    "Type": "Source"
  },
  {
    "Name": "ipg-AllowADDNS-Destination", 
    "Addresses": ["192.168.1.10", "192.168.1.11"],
    "UsedInRules": ["AllowADDNS"],
    "Type": "Destination"
  }
]
```

#### 3. rule-ip-mapping.csv
Detailed breakdown by rule - useful for auditing:
```csv
RuleCollectionGroup,RuleCollection,RuleName,RuleType,SourceAddresses,DestinationAddresses,Ports,Protocols
InfrastructureRules,NetworkRules,AllowADDNS,Network,"10.1.0.0/24,10.2.0.0/24","192.168.1.10,192.168.1.11",53,UDP
```

### What to Look For

| Check | Why It Matters |
|-------|----------------|
| **Number of IP Groups** | Azure allows max 200 IP Groups per firewall. Use `-ConsolidateIPGroups` to reduce. |
| **IP Group sizes** | Max 5,000 IPs per group. Large groups may need splitting. |
| **Duplicate addresses** | Same IPs in multiple rules = good consolidation opportunity. |
| **Missing IPs** | Verify critical IPs were extracted correctly. |

### Consolidation Example

Without consolidation, you might get:
- `ipg-Rule1-Source` with `10.1.0.0/24, 10.2.0.0/24`
- `ipg-Rule2-Source` with `10.1.0.0/24, 10.2.0.0/24`
- `ipg-Rule3-Source` with `10.1.0.0/24, 10.2.0.0/24`

With `-ConsolidateIPGroups`, these become a single:
- `ipg-Consolidated-1` with `10.1.0.0/24, 10.2.0.0/24`

This dramatically reduces IP Group count and improves manageability.

### Custom IP Group Names

By default, IP Groups are named based on rule names (e.g., `ipg-AllowDNS-src`). For more meaningful names, edit the `ip-group-mapping.csv` file:

**1. Open the mapping template:**
```csv
IPAddresses,SuggestedName,CustomName,AddressType,UsedInRules
"192.168.1.10;192.168.1.11;192.168.1.12",ipg-AllowDNS-dst,,Destination,"AllowDNS;AllowLDAP"
"10.1.0.0/24;10.2.0.0/24",ipg-AllowDNS-src,,Source,"AllowDNS;AllowLDAP"
```

**2. Fill in the `CustomName` column:**
```csv
IPAddresses,SuggestedName,CustomName,AddressType,UsedInRules
"192.168.1.10;192.168.1.11;192.168.1.12",ipg-AllowDNS-dst,On-Prem-DomainControllers,Destination,"AllowDNS;AllowLDAP"
"10.1.0.0/24;10.2.0.0/24",ipg-AllowDNS-src,Azure-AppServers,Source,"AllowDNS;AllowLDAP"
```

**3. Run migration with the mapping file:**
```powershell
.\Migrate-ToIPGroups.ps1 `
    -ResourceGroupName "rg-firewall" `
    -PolicyName "fw-policy" `
    -ExportPath ".\firewall-policy-export-YYYYMMDD-HHMMSS" `
    -IPGroupMappingFile ".\firewall-policy-export-YYYYMMDD-HHMMSS\ip-group-mapping.csv" `
    -ConsolidateIPGroups
```

**Result:** IP Groups with friendly names like `ipg-On-Prem-DomainControllers` and `ipg-Azure-AppServers`.

---

## Scripts Reference

### Export-FirewallPolicy.ps1

Exports an existing Azure Firewall Policy and extracts all IP addresses.

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| ResourceGroupName | Yes | Resource group containing the policy |
| PolicyName | Yes | Name of the policy to export |
| OutputPath | No | Where to save export files (default: current directory) |

**Output Files:**
- `policy-full.json` - Complete policy export
- `rule-ip-mapping.csv` - Mapping of rules to IP addresses
- `ip-group-suggestions.json` - Suggested IP Groups with addresses
- `ip-group-mapping.csv` - Template for custom IP Group names
- `source-ips.json` - All unique source IPs with usage info
- `destination-ips.json` - All unique destination IPs with usage info
- `summary.txt` - Human-readable summary

### Migrate-ToIPGroups.ps1

Creates IP Groups and a new policy using them.

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| ResourceGroupName | Yes | Resource group containing the source policy |
| PolicyName | Yes | Name of the source policy |
| NewPolicyName | No | Name for new policy (default: `<PolicyName>-ipgroups`) |
| NewPolicyResourceGroup | No | RG for new policy and IP Groups (default: same as source) |
| ExportPath | No | Path to export directory (runs export if not provided) |
| IPGroupResourceGroup | No | RG for IP Groups (default: same as NewPolicyResourceGroup) |
| IPGroupMappingFile | No | CSV file with custom IP Group names (generated by export) |
| ConsolidateIPGroups | No | Combine IP Groups with identical addresses |
| SmartConsolidate | No | Consolidate by logical function (creates fewer, more manageable groups) |
| WhatIf | No | Preview changes without applying |

## Example Policy Details

The example policy (`example-policy/main.bicep`) includes:

### Rule Collection Groups

1. **InfrastructureRules** (Priority: 100)
   - Active Directory rules (DNS, LDAP, Kerberos)
   - Management rules (SSH, RDP)

2. **ApplicationRules** (Priority: 200)
   - Azure services (portal, management APIs)
   - GitHub access
   - Windows Update

3. **DatabaseRules** (Priority: 300)
   - SQL Server, PostgreSQL, Redis access
   - Monitoring server scraping

### IP Ranges Used

**Source Networks (Azure VNets):**
- `10.0.0.10-12` - Jump boxes
- `10.1.0.0/24`, `10.1.1.0/24`, `10.1.2.0/24` - App servers, Windows servers
- `10.2.0.0/24`, `10.2.2.0/24` - Secondary app servers
- `10.5.0.0/24` - Additional workloads
- `192.168.100.10` - Monitoring server (source for scraping)

**Destination Networks (On-Prem/DBs):**
- `192.168.1.10-12` - Domain Controllers
- `10.3.1.10-11` - SQL Servers
- `10.3.2.10-11` - PostgreSQL Servers
- `10.3.3.10-11` - Redis Servers

## Considerations

### IP Group Limits

- Maximum 5,000 individual IP addresses per IP Group
- Maximum 200 IP Groups per firewall
- IP Groups count against the 10,000 unique source/destination limit

### Best Practices

1. **Group by function**: Create IP Groups based on logical groupings (e.g., "Domain Controllers", "App Servers")
2. **Use consolidation**: Enable `-ConsolidateIPGroups` to reduce duplicate groups
3. **Test thoroughly**: Validate all traffic flows after migration
4. **Keep documentation**: The export files serve as documentation of the original configuration

### Rollback

If issues occur:
1. The original policy is not modified
2. Associate the original policy back to the firewall
3. Delete the new policy and IP Groups if needed

## Troubleshooting

### Common Issues

**"IP Group already exists"**
- The script skips existing IP Groups and uses them as-is
- Delete existing IP Groups first if you need fresh ones

**"Policy already exists"**
- The script will remove and recreate the policy
- Use a different `NewPolicyName` to preserve both

**"Rate limiting"**
- Azure may throttle requests when creating many IP Groups
- The script handles retries automatically
