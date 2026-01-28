#Requires -Modules Az.Resources

<#
.SYNOPSIS
    Deploys the example Azure Firewall Policy with inline IP addresses.

.DESCRIPTION
    This script deploys an example Azure Firewall Policy that uses inline IP addresses
    in its rules. This policy can then be migrated to use IP Groups using the migration scripts.

.PARAMETER ResourceGroupName
    The name of the resource group to deploy to.

.PARAMETER Location
    The Azure region to deploy to.

.PARAMETER PolicyName
    The name of the firewall policy.

.PARAMETER PolicyTier
    The tier of the firewall policy (Standard or Premium).

.EXAMPLE
    .\deploy.ps1 -ResourceGroupName "rg-firewall-demo" -Location "eastus"

.EXAMPLE
    .\deploy.ps1 -ResourceGroupName "rg-firewall-demo" -Location "eastus" -PolicyName "my-fw-policy" -PolicyTier "Premium"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "fw-policy-inline-ips",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Standard", "Premium")]
    [string]$PolicyTier = "Premium"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Azure Firewall Policy Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if logged in to Azure
Write-Host "Checking Azure login status..." -ForegroundColor Yellow
$context = Get-AzContext
if (-not $context) {
    Write-Host "Not logged in to Azure. Please run 'Connect-AzAccount' first." -ForegroundColor Red
    exit 1
}
Write-Host "Logged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "Subscription: $($context.Subscription.Name)" -ForegroundColor Green
Write-Host ""

# Create resource group if it doesn't exist
Write-Host "Checking resource group '$ResourceGroupName'..." -ForegroundColor Yellow
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Host "Creating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Yellow
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Host "Resource group created." -ForegroundColor Green
} else {
    Write-Host "Resource group already exists." -ForegroundColor Green
}
Write-Host ""

# Deploy the Bicep template
Write-Host "Deploying Azure Firewall Policy..." -ForegroundColor Yellow
Write-Host "  Policy Name: $PolicyName" -ForegroundColor Gray
Write-Host "  Policy Tier: $PolicyTier" -ForegroundColor Gray
Write-Host ""

$templateFile = Join-Path $PSScriptRoot "main.bicep"

$deploymentParams = @{
    policyName = $PolicyName
    policyTier = $PolicyTier
    location   = $Location
}

$deployment = New-AzResourceGroupDeployment `
    -Name "fw-policy-deployment-$(Get-Date -Format 'yyyyMMddHHmmss')" `
    -ResourceGroupName $ResourceGroupName `
    -TemplateFile $templateFile `
    -TemplateParameterObject $deploymentParams `
    -Verbose

if ($deployment.ProvisioningState -eq "Succeeded") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Deployment Successful!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Policy ID: $($deployment.Outputs.policyId.Value)" -ForegroundColor Cyan
    Write-Host "Policy Name: $($deployment.Outputs.policyName.Value)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Run the export script to extract the policy:" -ForegroundColor Gray
    Write-Host "   .\Export-FirewallPolicy.ps1 -ResourceGroupName '$ResourceGroupName' -PolicyName '$PolicyName'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Run the migration script to create IP Groups and new policy:" -ForegroundColor Gray
    Write-Host "   .\Migrate-ToIPGroups.ps1 -ResourceGroupName '$ResourceGroupName' -PolicyName '$PolicyName'" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "Deployment failed with state: $($deployment.ProvisioningState)" -ForegroundColor Red
    exit 1
}
