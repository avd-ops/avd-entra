# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
  Tears down an opt-in operator Enterprise App using object IDs from its run manifest only.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$RunManifestPath,
    [Parameter()][ValidateSet('commercial', 'usgov')][string]$Cloud = 'commercial',
    [Parameter()][switch]$DiscardLastCopy,
    [Parameter()][switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name 'AvdEntra')) {
    Import-Module (Join-Path $PSScriptRoot 'AvdEntra.psm1')
}

if (-not (Test-Path -LiteralPath $RunManifestPath)) {
    throw "Operator run manifest not found at '$RunManifestPath'."
}

$manifest = Get-Content -LiteralPath $RunManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$targetCloud = if ($manifest.PSObject.Properties['cloud'] -and -not [string]::IsNullOrWhiteSpace([string]$manifest.cloud)) {
    [string]$manifest.cloud
} else { $Cloud }

$isDryRun = [bool]$DryRun -or ($env:AVD_OPS_DRY_RUN -eq '1') -or [bool]$WhatIfPreference
$cloudEnv = Set-AvdEntraCloudContext -Cloud $targetCloud
$null = Assert-AvdCloudMatch -Cloud $targetCloud -DryRun:$isDryRun
$graphEndpoint = ([string]$cloudEnv.graphEndpoint).TrimEnd('/')

if (-not $PSCmdlet.ShouldProcess([string]$manifest.displayName, 'Remove operator Enterprise App by object ID')) {
    return
}

# Verify appId matches current application object before deleting
if (-not [string]::IsNullOrWhiteSpace([string]$manifest.appObjectId) -and -not [string]::IsNullOrWhiteSpace([string]$manifest.appId)) {
    $current = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications?`$filter=appId eq '$($manifest.appId)'&`$select=id,appId" -Cloud $targetCloud -DryRun:$isDryRun)
    if ($current.Count -gt 0 -and [string]$current[0].id -ne [string]$manifest.appObjectId) {
        throw "Manifest appObjectId '$($manifest.appObjectId)' does not match current appId '$($manifest.appId)' ($($current[0].id)). Refusing to delete."
    }
}

# 1. Delete appRoleAssignments created by this run
foreach ($grant in @($manifest.appRoleAssignments | Where-Object { $_ -and $_.created -eq $true })) {
    if (-not [string]::IsNullOrWhiteSpace([string]$grant.id) -and -not [string]::IsNullOrWhiteSpace([string]$manifest.spObjectId)) {
        $null = Invoke-EntraGraph -Method DELETE -Uri "$graphEndpoint/v1.0/servicePrincipals/$($manifest.spObjectId)/appRoleAssignments/$($grant.id)" -Cloud $targetCloud -DryRun:$isDryRun
    }
}

# 2. Delete federatedIdentityCredential created by this run
if ($manifest.ficCreated -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$manifest.ficId) -and -not [string]::IsNullOrWhiteSpace([string]$manifest.appObjectId)) {
    $null = Invoke-EntraGraph -Method DELETE -Uri "$graphEndpoint/v1.0/applications/$($manifest.appObjectId)/federatedIdentityCredentials/$($manifest.ficId)" -Cloud $targetCloud -DryRun:$isDryRun
}

# 3. Delete Service Principal created by this run
if ($manifest.spCreated -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$manifest.spObjectId)) {
    $null = Invoke-EntraGraph -Method DELETE -Uri "$graphEndpoint/v1.0/servicePrincipals/$($manifest.spObjectId)" -Cloud $targetCloud -DryRun:$isDryRun
}

# 4. Delete Application created by this run
if ($manifest.appCreated -eq $true -and -not [string]::IsNullOrWhiteSpace([string]$manifest.appObjectId)) {
    $null = Invoke-EntraGraph -Method DELETE -Uri "$graphEndpoint/v1.0/applications/$($manifest.appObjectId)" -Cloud $targetCloud -DryRun:$isDryRun
    if ($DiscardLastCopy.IsPresent) {
        $null = Invoke-EntraGraph -Method DELETE -Uri "$graphEndpoint/v1.0/directory/deletedItems/$($manifest.appObjectId)" -Cloud $targetCloud -DryRun:$isDryRun
    }
}

Write-Information "Operator app teardown complete. Remember to remove AZURE_CLIENT_ID and AZURE_TENANT_ID from the GitHub environment if no longer used." -InformationAction Continue
