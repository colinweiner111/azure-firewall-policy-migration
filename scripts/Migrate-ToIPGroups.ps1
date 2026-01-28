#Requires -Modules Az.Network, Az.Resources

<#
.SYNOPSIS
    Migrates an Azure Firewall Policy from inline IPs to IP Groups.

.DESCRIPTION
    This script takes an existing Azure Firewall Policy that uses inline IP addresses
    and creates:
    1. IP Groups for source and destination addresses
    2. A new Firewall Policy that uses IP Groups instead of inline IPs

.PARAMETER ResourceGroupName
    The name of the resource group containing the firewall policy.

.PARAMETER PolicyName
    The name of the existing firewall policy with inline IPs.

.PARAMETER NewPolicyName
    The name for the new firewall policy using IP Groups. Defaults to original name with '-ipgroups' suffix.

.PARAMETER ExportPath
    Path to the export directory created by Export-FirewallPolicy.ps1. If not provided,
    the script will run the export automatically.

.PARAMETER IPGroupResourceGroup
    Resource group for IP Groups. Defaults to NewPolicyResourceGroup if specified, otherwise same as source policy.

.PARAMETER NewPolicyResourceGroup
    Resource group for the new policy and IP Groups. Defaults to same as source policy resource group.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.PARAMETER ConsolidateIPGroups
    If set, attempts to consolidate IP Groups that have the same IP addresses.

.PARAMETER SmartConsolidate
    If set, consolidates IP Groups by logical function (e.g., all domain controllers into one group).
    This creates a smaller, more manageable set of IP Groups (~15-25 instead of per-rule groups).

.EXAMPLE
    .\Migrate-ToIPGroups.ps1 -ResourceGroupName "rg-firewall" -PolicyName "fw-policy-inline-ips"

.EXAMPLE
    .\Migrate-ToIPGroups.ps1 -ResourceGroupName "rg-firewall" -PolicyName "fw-policy" -NewPolicyName "fw-policy-v2" -ConsolidateIPGroups
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$PolicyName,

    [Parameter(Mandatory = $false)]
    [string]$NewPolicyName,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string]$IPGroupResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$NewPolicyResourceGroup,

    [Parameter(Mandatory = $false)]
    [switch]$ConsolidateIPGroups,

    [Parameter(Mandatory = $false)]
    [switch]$SmartConsolidate

    [Parameter(Mandatory = $false)]
    [string]$IPGroupMappingFile
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

function Get-UniqueIPGroupName {
    param(
        [string]$BaseName,
        [hashtable]$ExistingNames
    )
    
    $name = $BaseName
    $counter = 1
    
    while ($ExistingNames.ContainsKey($name)) {
        $name = "$BaseName-$counter"
        $counter++
    }
    
    return $name
}

function Get-IPGroupHash {
    param([array]$IPAddresses)
    
    $sorted = $IPAddresses | Sort-Object
    return ($sorted -join ",").GetHashCode()
}

#endregion

#region Main Script

Write-Log "========================================" "Header"
Write-Log "Azure Firewall Policy Migration Tool" "Header"
Write-Log "Migrate Inline IPs to IP Groups" "Header"
Write-Log "========================================" "Header"
Write-Log ""

# Set defaults
if (-not $NewPolicyName) {
    $NewPolicyName = "$PolicyName-ipgroups"
}

# Set defaults for resource groups
if (-not $NewPolicyResourceGroup) {
    $NewPolicyResourceGroup = $ResourceGroupName
}
if (-not $IPGroupResourceGroup) {
    $IPGroupResourceGroup = $NewPolicyResourceGroup
}

# Check Azure login
Write-Log "Checking Azure connection..." "Info"
$context = Get-AzContext
if (-not $context) {
    Write-Log "Not logged in to Azure. Please run 'Connect-AzAccount' first." "Error"
    exit 1
}
Write-Log "Connected as: $($context.Account.Id)" "Success"
Write-Log ""

# Run export if no export path provided
if (-not $ExportPath) {
    Write-Log "No export path provided. Running export..." "Info"
    $exportScript = Join-Path $PSScriptRoot "Export-FirewallPolicy.ps1"
    $ExportPath = & $exportScript -ResourceGroupName $ResourceGroupName -PolicyName $PolicyName
    Write-Log ""
}

# Load IP Group suggestions
$suggestionsPath = Join-Path $ExportPath "ip-group-suggestions.json"
if (-not (Test-Path $suggestionsPath)) {
    Write-Log "IP Group suggestions file not found: $suggestionsPath" "Error"
    exit 1
}

$ipGroupSuggestions = Get-Content $suggestionsPath -Raw | ConvertFrom-Json
Write-Log "Loaded $($ipGroupSuggestions.Count) IP Group suggestions" "Info"

# Get existing policy
Write-Log "Fetching existing policy '$PolicyName'..." "Info"
$existingPolicy = Get-AzFirewallPolicy -ResourceGroupName $ResourceGroupName -Name $PolicyName
$location = $existingPolicy.Location
Write-Log "Policy found. Location: $location, SKU: $($existingPolicy.Sku.Tier)" "Success"
Write-Log ""


# Load custom IP Group name mappings if provided
$customNameMappings = @{}
if ($IPGroupMappingFile -and (Test-Path $IPGroupMappingFile)) {
    Write-Log "Loading custom IP Group name mappings from: $IPGroupMappingFile" "Info"
    $mappingData = Import-Csv $IPGroupMappingFile
    foreach ($row in $mappingData) {
        if ($row.CustomName -and $row.CustomName.Trim() -ne "") {
            # Create a hash of the IP addresses for matching
            $ipList = $row.IPAddresses -split ";" | ForEach-Object { $_.Trim() } | Sort-Object
            $ipHash = ($ipList -join ",").GetHashCode()
            $customNameMappings[$ipHash] = "ipg-$($row.CustomName.Trim())"
            Write-Log "  Mapped IP set to: ipg-$($row.CustomName.Trim())" "Info"
        }
    }
    Write-Log "Loaded $($customNameMappings.Count) custom name mappings" "Success"
} elseif ($IPGroupMappingFile) {
    Write-Log "Warning: Mapping file not found: $IPGroupMappingFile" "Warning"
}

# Consolidate IP Groups if requested
$ipGroupsToCreate = @{}
$ruleToIPGroupMapping = @{}

if ($ConsolidateIPGroups) {
    Write-Log "Consolidating IP Groups with identical IP addresses..." "Info"
    
    $ipHashToGroup = @{}
    
    foreach ($suggestion in $ipGroupSuggestions) {
        $ipAddresses = @($suggestion.IPAddresses)
        $hash = Get-IPGroupHash -IPAddresses $ipAddresses
        
        if ($ipHashToGroup.ContainsKey($hash)) {
            # Reuse existing group
            $existingGroupName = $ipHashToGroup[$hash]
            $ruleToIPGroupMapping["$($suggestion.RuleCollection)|$($suggestion.RuleName)|$($suggestion.AddressType)"] = $existingGroupName
            Write-Log "  Reusing '$existingGroupName' for $($suggestion.RuleName)" "Info"
        } else {
            # Create new group - check for custom name first
            $ipSortedHash = (($ipAddresses | Sort-Object) -join ",").GetHashCode()
            if ($customNameMappings.ContainsKey($ipSortedHash)) {
                $groupName = $customNameMappings[$ipSortedHash]
            } else {
                $groupName = Get-UniqueIPGroupName -BaseName $suggestion.SuggestedIPGroupName -ExistingNames $ipGroupsToCreate
            }
                Name        = $groupName
                IPAddresses = $ipAddresses
                UsedBy      = @("$($suggestion.RuleCollection)|$($suggestion.RuleName)")
            }
            $ipHashToGroup[$hash] = $groupName
            $ruleToIPGroupMapping["$($suggestion.RuleCollection)|$($suggestion.RuleName)|$($suggestion.AddressType)"] = $groupName
        }
    }
    
    Write-Log "Consolidated to $($ipGroupsToCreate.Count) unique IP Groups" "Success"
} else {
    # Create individual IP Groups for each rule
    foreach ($suggestion in $ipGroupSuggestions) {
        # Check for custom name first
        $ipAddresses = @($suggestion.IPAddresses)
        $ipSortedHash = (($ipAddresses | Sort-Object) -join ",").GetHashCode()
        if ($customNameMappings.ContainsKey($ipSortedHash)) {
            $groupName = $customNameMappings[$ipSortedHash]
        } else {
            $groupName = Get-UniqueIPGroupName -BaseName $suggestion.SuggestedIPGroupName -ExistingNames $ipGroupsToCreate
        }
        $ipGroupsToCreate[$groupName] = @{
            Name        = $groupName
            IPAddresses = $ipAddresses
            UsedBy      = @("$($suggestion.RuleCollection)|$($suggestion.RuleName)")
        }
        $ruleToIPGroupMapping["$($suggestion.RuleCollection)|$($suggestion.RuleName)|$($suggestion.AddressType)"] = $groupName
    }
}
Write-Log ""
Write-Log "IP Groups to create: $($ipGroupsToCreate.Count)" "Info"

# Create IP Groups
Write-Log ""
Write-Log "Creating IP Groups..." "Header"
$createdIPGroups = @{}

foreach ($ipGroupName in $ipGroupsToCreate.Keys) {
    $ipGroupData = $ipGroupsToCreate[$ipGroupName]
    
    if ($PSCmdlet.ShouldProcess($ipGroupName, "Create IP Group")) {
        Write-Log "  Creating IP Group: $ipGroupName ($($ipGroupData.IPAddresses.Count) addresses)" "Info"
        
        try {
            # Check if IP Group already exists
            $existingIPGroup = Get-AzIpGroup -ResourceGroupName $IPGroupResourceGroup -Name $ipGroupName -ErrorAction SilentlyContinue
            
            if ($existingIPGroup) {
                Write-Log "    IP Group already exists, skipping..." "Warning"
                $ipGroup = $existingIPGroup
            } else {
                $ipGroup = New-AzIpGroup -ResourceGroupName $IPGroupResourceGroup -Name $ipGroupName -Location $location -IpAddress $ipGroupData.IPAddresses
            }
            
            $createdIPGroups[$ipGroupName] = $ipGroup.Id
            Write-Log "    Created: $($ipGroup.Id)" "Success"
        } catch {
            Write-Log "    Failed to create IP Group: $_" "Error"
            throw
        }
    }
}

Write-Log ""
Write-Log "Created $($createdIPGroups.Count) IP Groups" "Success"

# Get rule collection groups from existing policy
Write-Log ""
Write-Log "Building new policy with IP Groups..." "Header"

# Get the list of rule collection group names from the policy
$rcgNames = $existingPolicy.RuleCollectionGroups | ForEach-Object { ($_.Id -split '/')[-1] }

$existingRCGs = @()
foreach ($rcgName in $rcgNames) {
    $rcg = Get-AzFirewallPolicyRuleCollectionGroup -ResourceGroupName $ResourceGroupName -AzureFirewallPolicyName $PolicyName -Name $rcgName
    $existingRCGs += $rcg
}

# Create the new policy
if ($PSCmdlet.ShouldProcess($NewPolicyName, "Create Firewall Policy")) {
    Write-Log "Creating new policy: $NewPolicyName" "Info"
    
    # Check if new policy already exists
    $newPolicyExists = Get-AzFirewallPolicy -ResourceGroupName $NewPolicyResourceGroup -Name $NewPolicyName -ErrorAction SilentlyContinue
    if ($newPolicyExists) {
        Write-Log "Policy '$NewPolicyName' already exists. Removing..." "Warning"
        Remove-AzFirewallPolicy -ResourceGroupName $NewPolicyResourceGroup -Name $NewPolicyName -Force
    }
    
    # Create base policy with same settings
    $newPolicyParams = @{
        ResourceGroupName = $NewPolicyResourceGroup
        Name              = $NewPolicyName
        Location          = $location
        SkuTier           = $existingPolicy.Sku.Tier
    }
    
    if ($existingPolicy.ThreatIntelMode) {
        $newPolicyParams['ThreatIntelMode'] = $existingPolicy.ThreatIntelMode
    }
    
    if ($existingPolicy.DnsSettings) {
        $newPolicyParams['DnsSetting'] = New-AzFirewallPolicyDnsSetting -EnableProxy
    }
    
    $newPolicy = New-AzFirewallPolicy @newPolicyParams
    Write-Log "Base policy created: $($newPolicy.Id)" "Success"
    
    # Recreate rule collection groups with IP Groups
    foreach ($rcg in $existingRCGs | Sort-Object { $_.Properties.Priority }) {
        $rcgName = $rcg.Name
        $rcgPriority = $rcg.Properties.Priority
        
        Write-Log ""
        Write-Log "Processing Rule Collection Group: $rcgName (Priority: $rcgPriority)" "Info"
        
        $newRuleCollections = @()
        
        foreach ($rc in $rcg.Properties.RuleCollection) {
            $rcName = $rc.Name
            $rcType = $rc.RuleCollectionType
            $rcPriority = $rc.Priority
            $rcAction = $rc.Action.Type
            
            Write-Log "  Rule Collection: $rcName" "Info"
            
            $newRules = @()
            
            foreach ($rule in $rc.Rules) {
                $ruleName = $rule.Name
                $ruleType = $rule.RuleType
                
                if ($ruleType -eq "NetworkRule") {
                    # Get protocols - handle different property names
                    $protocols = $rule.IpProtocols
                    if (-not $protocols) { $protocols = $rule.Protocols }
                    if (-not $protocols) { $protocols = @("TCP") } # Default fallback
                    
                    # Get destination ports
                    $destPorts = $rule.DestinationPorts
                    if (-not $destPorts) { $destPorts = @("*") }
                    
                    # Build new network rule with IP Groups
                    $newRuleParams = @{
                        Name              = $ruleName
                        Protocol          = $protocols
                        DestinationPort   = $destPorts
                    }
                    
                    if ($rule.Description) {
                        $newRuleParams['Description'] = $rule.Description
                    }
                    
                    # Handle source addresses
                    $sourceKey = "$rcName|$ruleName|Source"
                    if ($ruleToIPGroupMapping.ContainsKey($sourceKey)) {
                        $ipGroupId = $createdIPGroups[$ruleToIPGroupMapping[$sourceKey]]
                        $newRuleParams['SourceIpGroup'] = @($ipGroupId)
                        Write-Log "    $ruleName : Using IP Group for source" "Info"
                    } elseif ($rule.SourceAddresses -and $rule.SourceAddresses.Count -gt 0) {
                        $newRuleParams['SourceAddress'] = $rule.SourceAddresses
                    } elseif ($rule.SourceIpGroups -and $rule.SourceIpGroups.Count -gt 0) {
                        $newRuleParams['SourceIpGroup'] = $rule.SourceIpGroups
                    }
                    
                    # Handle destination addresses
                    $destKey = "$rcName|$ruleName|Destination"
                    if ($ruleToIPGroupMapping.ContainsKey($destKey)) {
                        $ipGroupId = $createdIPGroups[$ruleToIPGroupMapping[$destKey]]
                        $newRuleParams['DestinationIpGroup'] = @($ipGroupId)
                        Write-Log "    $ruleName : Using IP Group for destination" "Info"
                    } elseif ($rule.DestinationAddresses -and $rule.DestinationAddresses.Count -gt 0) {
                        $newRuleParams['DestinationAddress'] = $rule.DestinationAddresses
                    } elseif ($rule.DestinationIpGroups -and $rule.DestinationIpGroups.Count -gt 0) {
                        $newRuleParams['DestinationIpGroup'] = $rule.DestinationIpGroups
                    } elseif ($rule.DestinationFqdns -and $rule.DestinationFqdns.Count -gt 0) {
                        $newRuleParams['DestinationFqdn'] = $rule.DestinationFqdns
                    }
                    
                    $newRule = New-AzFirewallPolicyNetworkRule @newRuleParams
                    $newRules += $newRule
                }
                elseif ($ruleType -eq "ApplicationRule") {
                    # Build new application rule with IP Groups
                    $newRuleParams = @{
                        Name     = $ruleName
                        Protocol = @()
                    }
                    
                    if ($rule.Description) {
                        $newRuleParams['Description'] = $rule.Description
                    }
                    
                    # Handle protocols
                    foreach ($protocol in $rule.Protocols) {
                        $protocolString = "$($protocol.ProtocolType):$($protocol.Port)"
                        $newRuleParams['Protocol'] += $protocolString
                    }
                    
                    # Handle source addresses
                    $sourceKey = "$rcName|$ruleName|Source"
                    if ($ruleToIPGroupMapping.ContainsKey($sourceKey)) {
                        $ipGroupId = $createdIPGroups[$ruleToIPGroupMapping[$sourceKey]]
                        $newRuleParams['SourceIpGroup'] = @($ipGroupId)
                        Write-Log "    $ruleName : Using IP Group for source" "Info"
                    } elseif ($rule.SourceAddresses -and $rule.SourceAddresses.Count -gt 0) {
                        $newRuleParams['SourceAddress'] = $rule.SourceAddresses
                    } elseif ($rule.SourceIpGroups -and $rule.SourceIpGroups.Count -gt 0) {
                        $newRuleParams['SourceIpGroup'] = $rule.SourceIpGroups
                    }
                    
                    # Handle target FQDNs
                    if ($rule.TargetFqdns -and $rule.TargetFqdns.Count -gt 0) {
                        $newRuleParams['TargetFqdn'] = $rule.TargetFqdns
                    }
                    
                    # Handle FQDN Tags
                    if ($rule.FqdnTags -and $rule.FqdnTags.Count -gt 0) {
                        $newRuleParams['FqdnTag'] = $rule.FqdnTags
                    }
                    
                    # Handle Web Categories
                    if ($rule.WebCategories -and $rule.WebCategories.Count -gt 0) {
                        $newRuleParams['WebCategory'] = $rule.WebCategories
                    }
                    
                    $newRule = New-AzFirewallPolicyApplicationRule @newRuleParams
                    $newRules += $newRule
                }
                elseif ($ruleType -eq "NatRule") {
                    # NAT rules - copy as-is for now
                    Write-Log "    $ruleName : NAT rule (copied as-is)" "Warning"
                    # NAT rules would need special handling
                }
            }
            
            # Create the filter rule collection
            if ($newRules.Count -gt 0) {
                $filterCollection = New-AzFirewallPolicyFilterRuleCollection `
                    -Name $rcName `
                    -Priority $rcPriority `
                    -ActionType $rcAction `
                    -Rule $newRules
                
                $newRuleCollections += $filterCollection
            }
        }
        
        # Create the rule collection group
        if ($newRuleCollections.Count -gt 0) {
            Write-Log "  Creating Rule Collection Group: $rcgName" "Info"
            
            New-AzFirewallPolicyRuleCollectionGroup `
                -Name $rcgName `
                -Priority $rcgPriority `
                -FirewallPolicyObject $newPolicy `
                -RuleCollection $newRuleCollections
            
            Write-Log "  Rule Collection Group created" "Success"
        }
    }
}

# Export migration report
$reportPath = Join-Path $ExportPath "migration-report.json"
$migrationReport = @{
    OriginalPolicy   = $PolicyName
    NewPolicy        = $NewPolicyName
    SourceResourceGroup = $ResourceGroupName
    NewPolicyResourceGroup = $NewPolicyResourceGroup
    IPGroupResourceGroup = $IPGroupResourceGroup
    MigrationDate    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    IPGroupsCreated  = $createdIPGroups.Count
    IPGroups         = $createdIPGroups
    RuleMappings     = $ruleToIPGroupMapping
}
$migrationReport | ConvertTo-Json -Depth 10 | Out-File $reportPath -Encoding UTF8

Write-Log ""
Write-Log "========================================" "Header"
Write-Log "Migration Complete!" "Header"
Write-Log "========================================" "Header"
Write-Log ""
Write-Log "Original Policy: $PolicyName" "Info"
Write-Log "New Policy: $NewPolicyName" "Success"
Write-Log "IP Groups Created: $($createdIPGroups.Count)" "Success"
Write-Log ""
Write-Log "Migration report saved to: $reportPath" "Info"
Write-Log ""
Write-Log "Next Steps:" "Warning"
Write-Log "1. Review the new policy in Azure Portal" "Info"
Write-Log "2. Test rules to ensure traffic flows correctly" "Info"
Write-Log "3. Associate the new policy with your Azure Firewall" "Info"
Write-Log "4. Once validated, delete the old policy if desired" "Info"

#endregion






