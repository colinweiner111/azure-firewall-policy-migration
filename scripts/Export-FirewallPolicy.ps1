#Requires -Modules Az.Network

<#
.SYNOPSIS
    Exports an Azure Firewall Policy and extracts all IP addresses from rules.

.DESCRIPTION
    This script exports an Azure Firewall Policy to JSON and extracts all unique
    IP addresses and CIDR ranges from network and application rules. It generates
    reports showing which IPs are used in which rules and suggests IP Group groupings.

.PARAMETER ResourceGroupName
    The name of the resource group containing the firewall policy.

.PARAMETER PolicyName
    The name of the firewall policy to export.

.PARAMETER OutputPath
    The path where export files will be saved. Defaults to current directory.

.EXAMPLE
    .\Export-FirewallPolicy.ps1 -ResourceGroupName "rg-firewall" -PolicyName "fw-policy-inline-ips"

.EXAMPLE
    .\Export-FirewallPolicy.ps1 -ResourceGroupName "rg-firewall" -PolicyName "fw-policy" -OutputPath "C:\exports"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$PolicyName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info"    { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Header"  { "Cyan" }
        default   { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Get-IPCategory {
    param([string]$IPAddress)
    
    # Remove CIDR notation for analysis
    $ip = $IPAddress -replace '/.*$', ''
    
    # Check if it's a valid IP
    if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $ip.Split('.')
        $firstOctet = [int]$octets[0]
        $secondOctet = [int]$octets[1]
        
        # RFC 1918 Private Ranges
        if ($firstOctet -eq 10) {
            # 10.x.x.x - Further categorize by second octet
            return "Private-10.$secondOctet.x.x"
        }
        if ($firstOctet -eq 172 -and $secondOctet -ge 16 -and $secondOctet -le 31) {
            return "Private-172.x.x.x"
        }
        if ($firstOctet -eq 192 -and $secondOctet -eq 168) {
            $thirdOctet = [int]$octets[2]
            return "Private-192.168.$thirdOctet.x"
        }
        
        # Other ranges
        if ($firstOctet -eq 169 -and $secondOctet -eq 254) {
            return "LinkLocal"
        }
        
        return "Public"
    }
    
    return "Unknown"
}

function Get-SuggestedIPGroupName {
    param(
        [string]$RuleCollectionName,
        [string]$RuleName,
        [string]$AddressType  # "Source" or "Destination"
    )
    
    # Clean up names for IP Group naming
    $baseName = "$RuleCollectionName-$RuleName" -replace '[^a-zA-Z0-9-]', '-'
    $baseName = $baseName -replace '-+', '-'
    $baseName = $baseName.TrimStart('-').TrimEnd('-')
    
    # Truncate if too long (IP Group names max 80 chars)
    if ($baseName.Length -gt 60) {
        $baseName = $baseName.Substring(0, 60)
    }
    
    return "ipg-$baseName-$AddressType".ToLower()
}

#endregion

#region Main Script

Write-Log "========================================" "Header"
Write-Log "Azure Firewall Policy Export Tool" "Header"
Write-Log "========================================" "Header"
Write-Log ""

# Check Azure login
Write-Log "Checking Azure connection..." "Info"
$context = Get-AzContext
if (-not $context) {
    Write-Log "Not logged in to Azure. Please run 'Connect-AzAccount' first." "Error"
    exit 1
}
Write-Log "Connected as: $($context.Account.Id)" "Success"
Write-Log "Subscription: $($context.Subscription.Name)" "Info"
Write-Log ""

# Create output directory
$exportDir = Join-Path $OutputPath "firewall-policy-export-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
Write-Log "Export directory: $exportDir" "Info"
Write-Log ""

# Get the firewall policy
Write-Log "Fetching firewall policy '$PolicyName'..." "Info"
try {
    $policy = Get-AzFirewallPolicy -ResourceGroupName $ResourceGroupName -Name $PolicyName
    Write-Log "Policy found: $($policy.Name) (SKU: $($policy.Sku.Tier))" "Success"
} catch {
    Write-Log "Failed to get firewall policy: $_" "Error"
    exit 1
}

# Export full policy to JSON
$policyJsonPath = Join-Path $exportDir "policy-full.json"
$policy | ConvertTo-Json -Depth 100 | Out-File $policyJsonPath -Encoding UTF8
Write-Log "Full policy exported to: $policyJsonPath" "Success"
Write-Log ""

# Get all rule collection groups
Write-Log "Fetching rule collection groups..." "Info"

# Get the list of rule collection group names from the policy
$rcgNames = $policy.RuleCollectionGroups | ForEach-Object { ($_.Id -split '/')[-1] }

$ruleCollectionGroups = @()
foreach ($rcgName in $rcgNames) {
    $rcg = Get-AzFirewallPolicyRuleCollectionGroup -ResourceGroupName $ResourceGroupName -AzureFirewallPolicyName $PolicyName -Name $rcgName
    $ruleCollectionGroups += $rcg
}

Write-Log "Found $($ruleCollectionGroups.Count) rule collection group(s)" "Info"
Write-Log ""

# Initialize tracking objects
$allSourceIPs = @{}
$allDestinationIPs = @{}
$ruleIPMapping = @()
$ipGroupSuggestions = @()

# Process each rule collection group
foreach ($rcg in $ruleCollectionGroups) {
    Write-Log "Processing Rule Collection Group: $($rcg.Name)" "Header"
    
    foreach ($rc in $rcg.Properties.RuleCollection) {
        $rcName = $rc.Name
        $rcType = $rc.RuleCollectionType
        $rcPriority = $rc.Priority
        $rcAction = $rc.Action.Type
        
        Write-Log "  Rule Collection: $rcName (Type: $rcType, Priority: $rcPriority, Action: $rcAction)" "Info"
        
        foreach ($rule in $rc.Rules) {
            $ruleName = $rule.Name
            $ruleType = $rule.RuleType
            
            $sourceAddresses = @()
            $destinationAddresses = @()
            
            # Extract addresses based on rule type
            if ($ruleType -eq "NetworkRule") {
                $sourceAddresses = $rule.SourceAddresses | Where-Object { $_ }
                $destinationAddresses = $rule.DestinationAddresses | Where-Object { $_ }
            }
            elseif ($ruleType -eq "ApplicationRule") {
                $sourceAddresses = $rule.SourceAddresses | Where-Object { $_ }
                # Application rules use FQDNs for destinations, not IPs
            }
            
            # Track source IPs
            foreach ($ip in $sourceAddresses) {
                $category = Get-IPCategory $ip
                if (-not $allSourceIPs.ContainsKey($ip)) {
                    $allSourceIPs[$ip] = @{
                        Address  = $ip
                        Category = $category
                        UsedIn   = @()
                    }
                }
                $allSourceIPs[$ip].UsedIn += @{
                    RuleCollectionGroup = $rcg.Name
                    RuleCollection      = $rcName
                    Rule                = $ruleName
                    Type                = "Source"
                }
            }
            
            # Track destination IPs
            foreach ($ip in $destinationAddresses) {
                $category = Get-IPCategory $ip
                if (-not $allDestinationIPs.ContainsKey($ip)) {
                    $allDestinationIPs[$ip] = @{
                        Address  = $ip
                        Category = $category
                        UsedIn   = @()
                    }
                }
                $allDestinationIPs[$ip].UsedIn += @{
                    RuleCollectionGroup = $rcg.Name
                    RuleCollection      = $rcName
                    Rule                = $ruleName
                    Type                = "Destination"
                }
            }
            
            # Create rule-to-IP mapping
            if ($sourceAddresses.Count -gt 0 -or $destinationAddresses.Count -gt 0) {
                $ruleIPMapping += [PSCustomObject]@{
                    RuleCollectionGroup  = $rcg.Name
                    RuleCollection       = $rcName
                    RuleName             = $ruleName
                    RuleType             = $ruleType
                    Priority             = $rcPriority
                    Action               = $rcAction
                    SourceAddresses      = ($sourceAddresses -join "; ")
                    SourceCount          = $sourceAddresses.Count
                    DestinationAddresses = ($destinationAddresses -join "; ")
                    DestinationCount     = $destinationAddresses.Count
                }
                
                # Generate IP Group suggestions
                if ($sourceAddresses.Count -gt 0) {
                    $suggestedName = Get-SuggestedIPGroupName -RuleCollectionName $rcName -RuleName $ruleName -AddressType "src"
                    $ipGroupSuggestions += [PSCustomObject]@{
                        SuggestedIPGroupName = $suggestedName
                        RuleCollectionGroup  = $rcg.Name
                        RuleCollection       = $rcName
                        RuleName             = $ruleName
                        AddressType          = "Source"
                        IPAddresses          = $sourceAddresses
                        Count                = $sourceAddresses.Count
                    }
                }
                
                if ($destinationAddresses.Count -gt 0) {
                    $suggestedName = Get-SuggestedIPGroupName -RuleCollectionName $rcName -RuleName $ruleName -AddressType "dst"
                    $ipGroupSuggestions += [PSCustomObject]@{
                        SuggestedIPGroupName = $suggestedName
                        RuleCollectionGroup  = $rcg.Name
                        RuleCollection       = $rcName
                        RuleName             = $ruleName
                        AddressType          = "Destination"
                        IPAddresses          = $destinationAddresses
                        Count                = $destinationAddresses.Count
                    }
                }
            }
            
            Write-Log "    Rule: $ruleName - Sources: $($sourceAddresses.Count), Destinations: $($destinationAddresses.Count)" "Info"
        }
    }
    Write-Log ""
}

# Export rule-to-IP mapping
$mappingPath = Join-Path $exportDir "rule-ip-mapping.csv"
$ruleIPMapping | Export-Csv -Path $mappingPath -NoTypeInformation
Write-Log "Rule-to-IP mapping exported to: $mappingPath" "Success"

# Export IP Group suggestions
$suggestionsPath = Join-Path $exportDir "ip-group-suggestions.json"
$ipGroupSuggestions | ConvertTo-Json -Depth 10 | Out-File $suggestionsPath -Encoding UTF8
Write-Log "IP Group suggestions exported to: $suggestionsPath" "Success"

# Export IP Group mapping template for custom naming
$mappingTemplatePath = Join-Path $exportDir "ip-group-mapping.csv"
$mappingTemplate = @()

# Get unique IP sets for consolidation-aware naming
$uniqueIPSets = @{}
foreach ($suggestion in $ipGroupSuggestions) {
    $ipKey = ($suggestion.IPAddresses | Sort-Object) -join ","
    if (-not $uniqueIPSets.ContainsKey($ipKey)) {
        $uniqueIPSets[$ipKey] = @{
            IPAddresses = $suggestion.IPAddresses
            SuggestedName = $suggestion.SuggestedIPGroupName
            UsedInRules = @($suggestion.RuleName)
            AddressType = $suggestion.AddressType
        }
    } else {
        $uniqueIPSets[$ipKey].UsedInRules += $suggestion.RuleName
    }
}

foreach ($entry in $uniqueIPSets.GetEnumerator()) {
    $mappingTemplate += [PSCustomObject]@{
        IPAddresses = $entry.Value.IPAddresses -join ";"
        SuggestedName = $entry.Value.SuggestedName
        CustomName = ""  # User fills this in
        AddressType = $entry.Value.AddressType
        UsedInRules = $entry.Value.UsedInRules -join ";"
    }
}

$mappingTemplate | Export-Csv -Path $mappingTemplatePath -NoTypeInformation
Write-Log "IP Group mapping template exported to: $mappingTemplatePath" "Success"
Write-Log "  Edit the 'CustomName' column to specify friendly names for IP Groups" "Info"

# Export unique source IPs
$sourceIPsPath = Join-Path $exportDir "source-ips.json"
$allSourceIPs | ConvertTo-Json -Depth 10 | Out-File $sourceIPsPath -Encoding UTF8
Write-Log "Source IPs exported to: $sourceIPsPath" "Success"

# Export unique destination IPs
$destIPsPath = Join-Path $exportDir "destination-ips.json"
$allDestinationIPs | ConvertTo-Json -Depth 10 | Out-File $destIPsPath -Encoding UTF8
Write-Log "Destination IPs exported to: $destIPsPath" "Success"

# Create a summary report
$summaryPath = Join-Path $exportDir "summary.txt"
$summary = @"
Azure Firewall Policy Export Summary
=====================================
Policy Name: $PolicyName
Resource Group: $ResourceGroupName
SKU Tier: $($policy.Sku.Tier)
Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Statistics
----------
Rule Collection Groups: $($ruleCollectionGroups.Count)
Rules with IP Addresses: $($ruleIPMapping.Count)
Unique Source IPs/CIDRs: $($allSourceIPs.Count)
Unique Destination IPs/CIDRs: $($allDestinationIPs.Count)
Suggested IP Groups: $($ipGroupSuggestions.Count)

IP Groups to Create
-------------------
$($ipGroupSuggestions | ForEach-Object { "- $($_.SuggestedIPGroupName) ($($_.Count) addresses)" } | Out-String)

Files Generated
---------------
- policy-full.json: Complete policy export
- rule-ip-mapping.csv: Mapping of rules to IP addresses
- ip-group-suggestions.json: Suggested IP Groups with addresses
- source-ips.json: All unique source IPs with usage info
- destination-ips.json: All unique destination IPs with usage info

Next Steps
----------
1. Review ip-group-suggestions.json for proposed IP Groups
2. Modify as needed (combine groups, rename, etc.)
3. Run Migrate-ToIPGroups.ps1 to create IP Groups and new policy
"@

$summary | Out-File $summaryPath -Encoding UTF8
Write-Log "Summary exported to: $summaryPath" "Success"

# Display summary
Write-Log ""
Write-Log "========================================" "Header"
Write-Log "Export Complete!" "Header"
Write-Log "========================================" "Header"
Write-Log ""
Write-Log "Statistics:" "Info"
Write-Log "  Rule Collection Groups: $($ruleCollectionGroups.Count)" "Info"
Write-Log "  Rules with IP Addresses: $($ruleIPMapping.Count)" "Info"
Write-Log "  Unique Source IPs/CIDRs: $($allSourceIPs.Count)" "Info"
Write-Log "  Unique Destination IPs/CIDRs: $($allDestinationIPs.Count)" "Info"
Write-Log "  Suggested IP Groups: $($ipGroupSuggestions.Count)" "Info"
Write-Log ""
Write-Log "Export Location: $exportDir" "Success"
Write-Log ""

# Return the export path for use by other scripts
return $exportDir

#endregion

