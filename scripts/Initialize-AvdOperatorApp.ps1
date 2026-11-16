# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
  Opt-in bootstrap for an unattended CI/lab avd-ops operator Enterprise App with immutable GitHub OIDC federation.

.DESCRIPTION
  Explicitly opt-in helper for lab and CI automation. Requires a signed-in human user holding
  Privileged Role Administrator or Global Administrator. Enterprise environments with split-plane
  governance should continue using interactive/PIM-activated admins.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()][ValidateSet('commercial', 'usgov')][string]$Cloud = 'commercial',
    [Parameter()][switch]$AllowUntestedUsGov,
    [Parameter()][ValidatePattern('^[a-z0-9]{2,16}$')][string]$Prefix = 'avd',
    [Parameter()][ValidateSet('dev', 'test', 'prod')][string]$Environment = 'dev',
    [Parameter()][switch]$ConfirmProd,
    [Parameter(Mandatory)][ValidateSet('entra', 'intune')][string[]]$Planes,
    [Parameter()][switch]$AllowUnionOfRights,
    [Parameter()][switch]$IncludeWin365,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')][string]$GitHubRepo,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$GitHubEnvironment,
    [Parameter()][string]$GitHubOwnerId = '',
    [Parameter()][string]$GitHubRepoId = '',
    [Parameter()][string]$RunManifestPath = './operator-run-manifest.json',
    [Parameter()][switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name 'AvdEntra')) {
    Import-Module (Join-Path $PSScriptRoot 'AvdEntra.psm1')
}
if (-not (Get-Module -Name 'AvdOperatorApp')) {
    Import-Module (Join-Path $PSScriptRoot 'AvdOperatorApp.psm1')
}

$uniquePlanes = @($Planes | Sort-Object -Unique)
if ($uniquePlanes.Count -gt 1 -and -not $AllowUnionOfRights.IsPresent) {
    throw "Multiple planes requested ($($uniquePlanes -join ', ')). Pass -AllowUnionOfRights to combine them on one operator app, or create one operator per plane."
}

if ($Environment -eq 'prod' -and -not $ConfirmProd.IsPresent) {
    throw "Refusing -Environment prod without -ConfirmProd. This operator bootstrap is intended for lab and CI environments."
}

if ($Cloud -eq 'usgov' -and -not $AllowUntestedUsGov.IsPresent) {
    throw "Refusing -Cloud usgov without -AllowUntestedUsGov (usgov OIDC audience and consent path are not yet verified in a live tenant)."
}

$isDryRun = [bool]$DryRun -or ($env:AVD_OPS_DRY_RUN -eq '1') -or [bool]$WhatIfPreference
$cloudEnv = Set-AvdEntraCloudContext -Cloud $Cloud
$null = Assert-AvdCloudMatch -Cloud $Cloud -DryRun:$isDryRun
$graphEndpoint = ([string]$cloudEnv.graphEndpoint).TrimEnd('/')
$oidcAudience = Get-AvdOperatorOidcAudience -Cloud $Cloud
if ([string]::IsNullOrWhiteSpace($oidcAudience)) {
    throw "Missing oidcAudience in cloud-environments.json for cloud '$Cloud'."
}

$planesCfg = Get-AvdOperatorPlanesConfig
$requestedRoles = @(Get-AvdOperatorRequestedRoles -Config $planesCfg -Planes $uniquePlanes -IncludeWin365:$IncludeWin365)
$stampName = Get-AvdOperatorStampName -Prefix $Prefix -Environment $Environment -Planes $uniquePlanes

# Resolve GitHub numeric owner/repo IDs
$repoParts = $GitHubRepo -split '/', 2
$ghOwner = $repoParts[0]
$ghRepoName = $repoParts[1]
if ([string]::IsNullOrWhiteSpace($GitHubOwnerId) -or [string]::IsNullOrWhiteSpace($GitHubRepoId)) {
    if ($isDryRun) {
        $GitHubOwnerId = '1000001'
        $GitHubRepoId = '2000001'
    } else {
        $ghCmd = Get-Command gh -ErrorAction SilentlyContinue
        if (-not $ghCmd) {
            throw "GitHub CLI (gh) not found. Pass -GitHubOwnerId and -GitHubRepoId explicitly."
        }
        $ghJson = & $ghCmd.Source api "repos/$GitHubRepo" --jq '{repoId: .id, ownerId: .owner.id, private: .private}'
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to resolve GitHub repo '$GitHubRepo' via gh api."
        }
        $ghMeta = $ghJson | ConvertFrom-Json
        $GitHubOwnerId = [string]$ghMeta.ownerId
        $GitHubRepoId = [string]$ghMeta.repoId
    }
}

$ficSubject = Get-AvdOperatorSubject -Owner $ghOwner -OwnerId $GitHubOwnerId -Repo $ghRepoName -RepoId $GitHubRepoId -Environment $GitHubEnvironment
$ficName = Get-AvdOperatorCredentialName -RepoId $GitHubRepoId -Environment $GitHubEnvironment

# Caller privilege check
if ($isDryRun -and -not (Get-Variable -Name 'EntraGraphMock' -Scope Script -ErrorAction SilentlyContinue)) {
    $callerUserId = Get-EntraDeterministicGuid -Seed 'dryrun-caller'
} else {
    $callerMe = Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/me?`$select=id,userPrincipalName" -Cloud $Cloud -DryRun:$isDryRun
    $callerMemberOf = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/me/memberOf?`$select=id,roleTemplateId,displayName" -Cloud $Cloud -DryRun:$isDryRun)
    $callerUserId = Assert-AvdOperatorCaller -CallerMe $callerMe -CallerMemberOf $callerMemberOf
}

# Resolve Graph SP appRoles
$graphSpAppId = [string]$planesCfg.graphServicePrincipalAppId
$graphSpList = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/servicePrincipals?`$filter=appId eq '$graphSpAppId'&`$select=id,appId,appRoles" -Cloud $Cloud -DryRun:$isDryRun)
if ($isDryRun -and $graphSpList.Count -eq 0) {
    $graphSp = [pscustomobject]@{ id = (Get-EntraDeterministicGuid -Seed 'graph-sp'); appId = $graphSpAppId; appRoles = $requestedRoles }
} elseif ($graphSpList.Count -eq 0) {
    throw "Microsoft Graph service principal ($graphSpAppId) not found."
} else {
    $graphSp = $graphSpList[0]
}
$resolvedRoles = @(Resolve-AvdOperatorGraphRoles -RequestedRoles $requestedRoles -GraphServicePrincipal $graphSp -DenyList $planesCfg.denyList)

# Check existing manifest for reuse by appId
$existingManifest = $null
if (Test-Path -LiteralPath $RunManifestPath) {
    $existingManifest = Get-Content -LiteralPath $RunManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

$existingAppId = if ($null -ne $existingManifest -and $null -ne $existingManifest.PSObject.Properties['appId']) {
    [string]$existingManifest.appId
} else { '' }

$targetApp = $null
$appCreated = $false
if (-not [string]::IsNullOrWhiteSpace($existingAppId)) {
    $found = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications?`$filter=appId eq '$existingAppId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials" -Cloud $Cloud -DryRun:$isDryRun)
    if ($found.Count -eq 1) {
        $targetApp = $found[0]
    }
}

if ($null -eq $targetApp) {
    $escapedStamp = $stampName.Replace("'", "''")
    $collisions = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications?`$filter=displayName eq '$escapedStamp'&`$select=id,appId,displayName" -Cloud $Cloud -DryRun:$isDryRun)
    if ($collisions.Count -gt 0) {
        $ids = ($collisions | ForEach-Object { "$($_.id) (appId=$($_.appId))" }) -join ', '
        throw "Refusing to adopt existing application(s) with displayName '$stampName': [$ids]. Reuse is by RunManifestPath appId only."
    }
}

Write-Host "Operator App Plan:" -ForegroundColor Cyan
Write-Host "  DisplayName : $stampName"
Write-Host "  Cloud       : $Cloud ($graphEndpoint)"
Write-Host "  Planes      : $($uniquePlanes -join ', ')"
Write-Host "  FIC Subject : $ficSubject"
Write-Host "  Audience    : $oidcAudience"
Write-Host "  AppRoles    : $(($resolvedRoles | ForEach-Object { "$($_.value) ($($_.id))" }) -join '; ')"

# Write initial run manifest before first write
$manifest = [ordered]@{
    schema            = 'avd-ops-operator-run-manifest/v1'
    cloud             = $Cloud
    environment       = $Environment
    prefix            = $Prefix
    planes            = @($uniquePlanes)
    displayName       = $stampName
    appId             = $existingAppId
    appObjectId       = ''
    appCreated        = $false
    spObjectId        = ''
    spCreated         = $false
    policyId          = ''
    policyCreated     = $false
    ficName           = $ficName
    ficId             = ''
    ficCreated        = $false
    ficSubject        = $ficSubject
    oidcAudience      = $oidcAudience
    appRoleAssignments = @()
}

$manifestDir = Split-Path -Parent $RunManifestPath
if (-not [string]::IsNullOrWhiteSpace($manifestDir) -and -not (Test-Path -LiteralPath $manifestDir)) {
    New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $RunManifestPath -Encoding UTF8

if (-not $PSCmdlet.ShouldProcess($stampName, 'Initialize operator Enterprise App')) {
    return [pscustomobject]$manifest
}

# 1. Create or validate Application
if ($null -eq $targetApp) {
    $appBody = @{
        displayName    = $stampName
        signInAudience = 'AzureADMyOrg'
        notes          = 'avd-ops opt-in operator identity (federated credentials only)'
    }
    $targetApp = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/v1.0/applications" -Body $appBody -Cloud $Cloud -DryRun:$isDryRun
    $appCreated = $true
} else {
    $owners = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications/$($targetApp.id)/owners?`$select=id" -Cloud $Cloud -DryRun:$isDryRun)
    $fics = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications/$($targetApp.id)/federatedIdentityCredentials" -Cloud $Cloud -DryRun:$isDryRun)
    Assert-AvdOperatorAppClean -App $targetApp -Owners $owners -CallerUserId $callerUserId -FederatedCredentials $fics
}
$manifest.appObjectId = [string]$targetApp.id
$manifest.appId = if ($targetApp.PSObject.Properties['appId']) { [string]$targetApp.appId } else { Get-EntraDeterministicGuid -Seed $stampName }
$manifest.appCreated = $appCreated

# 2. Create or reuse Service Principal
$spList = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/servicePrincipals?`$filter=appId eq '$($manifest.appId)'&`$select=id,appId" -Cloud $Cloud -DryRun:$isDryRun)
$spCreated = $false
if ($spList.Count -eq 0) {
    $spBody = @{
        appId                     = $manifest.appId
        appRoleAssignmentRequired = $true
        tags                      = @('WindowsAzureActiveDirectoryIntegratedApp')
    }
    $spObj = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/v1.0/servicePrincipals" -Body $spBody -Cloud $Cloud -DryRun:$isDryRun
    $spCreated = $true
} else {
    $spObj = $spList[0]
}
$manifest.spObjectId = [string]$spObj.id
$manifest.spCreated = $spCreated

# 3. Apply App Management Policy blocking secrets BEFORE granting any appRoleAssignments
$policyBody = Get-AvdOperatorPolicyBody -AppDisplayName $stampName
$policyObj = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/beta/policies/appManagementPolicies" -Body $policyBody -Cloud $Cloud -DryRun:$isDryRun
$manifest.policyId = [string]$policyObj.id
$manifest.policyCreated = $true
$refBody = @{ '@odata.id' = "$graphEndpoint/beta/policies/appManagementPolicies/$($manifest.policyId)" }
$null = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/beta/applications/$($manifest.appObjectId)/appManagementPolicies/`$ref" -Body $refBody -Cloud $Cloud -DryRun:$isDryRun

# 4. Bind immutable GitHub OIDC Federated Identity Credential
$existingFics = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/applications/$($manifest.appObjectId)/federatedIdentityCredentials" -Cloud $Cloud -DryRun:$isDryRun)
$matchingFic = @($existingFics | Where-Object { $_.name -eq $ficName } | Select-Object -First 1)
if ($matchingFic.Count -eq 0) {
    $ficBody = @{
        name        = $ficName
        issuer      = 'https://token.actions.githubusercontent.com'
        subject     = $ficSubject
        description = "Immutable GitHub OIDC for $GitHubRepo environment $GitHubEnvironment"
        audiences   = @($oidcAudience)
    }
    $ficObj = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/v1.0/applications/$($manifest.appObjectId)/federatedIdentityCredentials" -Body $ficBody -Cloud $Cloud -DryRun:$isDryRun
    $manifest.ficId = [string]$ficObj.id
    $manifest.ficCreated = $true
} else {
    $manifest.ficId = [string]$matchingFic[0].id
    $manifest.ficCreated = $false
}

# 5. Consent Graph Application appRoleAssignments
$existingGrants = @(Invoke-EntraGraph -Method GET -Uri "$graphEndpoint/v1.0/servicePrincipals/$($manifest.spObjectId)/appRoleAssignments" -Cloud $Cloud -DryRun:$isDryRun)
$grantRecords = @()
foreach ($role in $resolvedRoles) {
    $already = @($existingGrants | Where-Object { ([string]$_.appRoleId).ToLowerInvariant() -eq $role.id } | Select-Object -First 1)
    if ($already.Count -eq 0) {
        $grantBody = @{
            principalId = $manifest.spObjectId
            resourceId  = [string]$graphSp.id
            appRoleId   = $role.id
        }
        $grantObj = Invoke-EntraGraph -Method POST -Uri "$graphEndpoint/v1.0/servicePrincipals/$($manifest.spObjectId)/appRoleAssignments" -Body $grantBody -Cloud $Cloud -DryRun:$isDryRun
        $grantRecords += [ordered]@{
            id        = [string]$grantObj.id
            appRoleId = $role.id
            value     = $role.value
            created   = $true
        }
    } else {
        $grantRecords += [ordered]@{
            id        = [string]$already[0].id
            appRoleId = $role.id
            value     = $role.value
            created   = $false
        }
    }
}
$manifest.appRoleAssignments = $grantRecords

$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $RunManifestPath -Encoding UTF8
Write-Host "Operator app initialized. Ensure GitHub environment '$GitHubEnvironment' on '$GitHubRepo' requires reviewer approval and restricts deployment branches to the default branch." -ForegroundColor Yellow
return [pscustomobject]$manifest
