# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:DryRunStore = $null
$script:EntraGraphMock = $null
$script:ActiveCloud = 'commercial'
$script:CloudEnvironmentCache = @{}
$script:PhishingResistantMfaCombinations = @(
    'windowsHelloForBusiness',
    'fido2',
    'x509CertificateMultiFactor'
)
$script:OperatorScopes = @(
    'Application.ReadWrite.All',
    'DelegatedPermissionGrant.ReadWrite.All',
    'Policy.Read.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Group.ReadWrite.All',
    'Directory.Read.All',
    'Device.ReadWrite.All',
    'DeviceManagementManagedDevices.ReadWrite.All'
)

function Resolve-AvdCloudEnvironment {
    <#
    .SYNOPSIS
      Loads contract C26 (contracts/cloud-environments.json) and returns the cloud descriptor
      for 'commercial' or 'usgov'.
    #>
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = 'commercial',
        [string]$ContractPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'contracts/cloud-environments.json')
    )
    if (-not (Test-Path -LiteralPath $ContractPath)) {
        throw "Cloud environments contract (C26) not found at '$ContractPath'."
    }
    $raw = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
    if ($raw.schema -ne 'avd-cloud-environments/v1') {
        throw "Unsupported cloud environments contract schema '$($raw.schema)' in '$ContractPath'."
    }

    $cloudProp = $null
    if ($raw.PSObject.Properties['clouds'] -and $raw.clouds -and $raw.clouds.PSObject.Properties[$Cloud]) {
        $cloudProp = $raw.clouds.PSObject.Properties[$Cloud].Value
    }
    if (-not $cloudProp -and $raw.PSObject.Properties['environments'] -and $raw.environments) {
        $cloudProp = @($raw.environments | Where-Object { $_.id -eq $Cloud }) | Select-Object -First 1
    }
    if (-not $cloudProp) {
        throw "Cloud profile '$Cloud' was not found in '$ContractPath'."
    }

    $defaultProfile = if ($Cloud -eq 'usgov') { 'itar-cui' } else { 'standard' }
    $resolved = [pscustomobject]@{
        id                           = $Cloud
        displayName                  = [string]$cloudProp.displayName
        azCloudName                  = [string]$cloudProp.azCloudName
        psEnvironmentName            = [string]$cloudProp.psEnvironmentName
        entraEnvironment             = [string]$cloudProp.entraEnvironment
        mgGraphEnvironment           = [string]$cloudProp.entraEnvironment
        armEndpoint                  = [string]$cloudProp.armEndpoint
        loginEndpoint                = [string]$cloudProp.loginEndpoint
        graphEndpoint                = [string]$cloudProp.graphEndpoint
        storageEndpointSuffix        = [string]$cloudProp.storageEndpointSuffix
        keyVaultDnsSuffix            = [string]$cloudProp.keyVaultDnsSuffix
        logAnalyticsWorkspaceSuffix  = [string]$cloudProp.logAnalyticsWorkspaceSuffix
        logAnalyticsOdsSuffix        = [string]$cloudProp.logAnalyticsOdsSuffix
        avd                          = $cloudProp.avd
        m365                         = $cloudProp.m365
        powerPlatform                = $cloudProp.powerPlatform
        privateDnsZones              = $cloudProp.privateDnsZones
        defaultRegions               = @($cloudProp.defaultRegions)
        allowedRegions               = @($cloudProp.allowedRegions)
        capabilities                 = $cloudProp.capabilities
        defaultComplianceProfile     = $defaultProfile
        azure                        = [pscustomobject]@{
            environmentName       = [string]$cloudProp.azCloudName
            psEnvironmentName     = [string]$cloudProp.psEnvironmentName
            armEndpoint           = [string]$cloudProp.armEndpoint
            storageEndpointSuffix = [string]$cloudProp.storageEndpointSuffix
            keyVaultDnsSuffix     = [string]$cloudProp.keyVaultDnsSuffix
        }
        entra                        = [pscustomobject]@{
            environmentName    = [string]$cloudProp.entraEnvironment
            mgGraphEnvironment = [string]$cloudProp.entraEnvironment
            loginEndpoint      = [string]$cloudProp.loginEndpoint
            graphEndpoint      = [string]$cloudProp.graphEndpoint
        }
    }
    return $resolved
}

function Set-AvdEntraCloudContext {
    <#
    .SYNOPSIS
      Sets the active cloud profile ('commercial' or 'usgov') for AvdEntra Graph URI resolution.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = 'commercial'
    )
    $script:ActiveCloud = $Cloud
    return (Resolve-AvdCloudEnvironment -Cloud $Cloud)
}

function Get-EntraGraphEndpoint {
    <#
    .SYNOPSIS
      Returns the Microsoft Graph base endpoint for the specified or active cloud profile from C26.
    #>
    [OutputType([string])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = $script:ActiveCloud
    )
    $envConfig = Resolve-AvdCloudEnvironment -Cloud $Cloud
    return ([string]$envConfig.graphEndpoint).TrimEnd('/')
}

function Test-AvdEntraCloudContext {
    <#
    .SYNOPSIS
      Fail-closed cross-cloud guard verifying that active Az PowerShell (Get-AzContext),
      Azure CLI (az account show), Microsoft Graph PowerShell (Get-MgContext), and any
      handoff/run manifest cloud match the target cloud ('commercial' vs 'usgov').
    #>
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = $script:ActiveCloud,
        [object]$AzContext = $null,
        [object]$MgContext = $null,
        [string]$AzCliCloudName = '',
        [string]$ManifestCloud = '',
        [switch]$DryRun
    )
    $envConfig = Resolve-AvdCloudEnvironment -Cloud $Cloud
    $expectedAz = [string]$envConfig.azCloudName
    $expectedMg = [string]$envConfig.entraEnvironment

    if (-not [string]::IsNullOrWhiteSpace($ManifestCloud) -and $ManifestCloud.Trim() -ne $Cloud) {
        throw "Cloud boundary mismatch (fail-closed): target cloud '$Cloud' does not match manifest cloud '$($ManifestCloud.Trim())'."
    }

    if ($null -eq $AzContext) {
        $azCmd = Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue
        if ($azCmd) {
            $AzContext = & $azCmd -ErrorAction SilentlyContinue
        }
    }

    if ($null -ne $AzContext) {
        $actualAz = ''
        if ($AzContext.PSObject.Properties['Environment'] -and $null -ne $AzContext.Environment) {
            if ($AzContext.Environment -is [string]) {
                $actualAz = [string]$AzContext.Environment
            }
            elseif ($AzContext.Environment.PSObject.Properties['Name']) {
                $actualAz = [string]$AzContext.Environment.Name
            }
        }
        elseif ($AzContext.PSObject.Properties['EnvironmentName']) {
            $actualAz = [string]$AzContext.EnvironmentName
        }

        if (-not [string]::IsNullOrWhiteSpace($actualAz) -and $actualAz -ne $expectedAz) {
            throw "Cloud boundary mismatch (fail-closed): target cloud '$Cloud' expects Az environment '$expectedAz', but active Get-AzContext environment is '$actualAz'."
        }
    }

    if ($null -eq $MgContext) {
        $mgCmd = Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue
        if ($mgCmd) {
            $MgContext = & $mgCmd -ErrorAction SilentlyContinue
        }
    }

    if ($null -ne $MgContext) {
        $actualMg = ''
        if ($MgContext.PSObject.Properties['Environment'] -and $null -ne $MgContext.Environment) {
            $actualMg = [string]$MgContext.Environment
        }
        if (-not [string]::IsNullOrWhiteSpace($actualMg) -and $actualMg -ne $expectedMg) {
            throw "Cloud boundary mismatch (fail-closed): target cloud '$Cloud' expects MgGraph environment '$expectedMg', but active Get-MgContext environment is '$actualMg'."
        }
    }

    if ([string]::IsNullOrWhiteSpace($AzCliCloudName)) {
        $azCliCmd = Get-Command -Name 'az' -ErrorAction SilentlyContinue
        $shouldQueryAzCli = ($null -ne $azCliCmd) -and (-not $DryRun -or $azCliCmd.CommandType -in @('Function', 'Alias', 'Filter'))
        if ($shouldQueryAzCli) {
            $cliOut = & az account show --query environmentName -o tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace("$cliOut")) {
                $AzCliCloudName = ("$cliOut").Trim()
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($AzCliCloudName) -and $AzCliCloudName.Trim() -ne $expectedAz) {
        throw "Cloud boundary mismatch (fail-closed): target cloud '$Cloud' expects az cloud '$expectedAz', but active az account environment is '$($AzCliCloudName.Trim())'."
    }

    return [pscustomobject]@{
        Cloud          = $Cloud
        AzEnvironment  = $expectedAz
        MgEnvironment  = $expectedMg
        GraphEndpoint  = [string]$envConfig.graphEndpoint
        LoginEndpoint  = [string]$envConfig.loginEndpoint
        Verified       = $true
    }
}

function Assert-AvdCloudMatch {
    <#
    .SYNOPSIS
      Enforces fail-closed cloud-boundary matching across Az, az CLI, MgGraph, and manifest state.
    #>
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = $script:ActiveCloud,
        [object]$AzContext = $null,
        [object]$MgContext = $null,
        [string]$AzCliCloudName = '',
        [string]$ManifestCloud = '',
        [switch]$DryRun
    )
    return (Test-AvdEntraCloudContext @PSBoundParameters)
}

function Connect-AvdEntraGraph {
    <#
    .SYNOPSIS
      Connects to Microsoft Graph using the cloud-matched environment (Connect-MgGraph -Environment USGov
      for usgov, Connect-MgGraph -Environment Global for commercial) after fail-closed context verification.
    #>
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('commercial', 'usgov')]
        [string]$Cloud = $script:ActiveCloud,
        [string[]]$Scopes = $script:OperatorScopes,
        [switch]$DryRun
    )
    $null = Set-AvdEntraCloudContext -Cloud $Cloud
    $verified = Assert-AvdCloudMatch -Cloud $Cloud -DryRun:$DryRun
    $envConfig = Resolve-AvdCloudEnvironment -Cloud $Cloud

    $mgConnectCmd = Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue
    if ($mgConnectCmd -and (-not $DryRun -or $mgConnectCmd.CommandType -in @('Function', 'Alias', 'Filter'))) {
        if ($Cloud -eq 'usgov') {
            $null = Connect-MgGraph -Environment USGov -Scopes $Scopes -NoWelcome
        }
        else {
            $null = Connect-MgGraph -Environment Global -Scopes $Scopes -NoWelcome
        }
    }

    return [pscustomobject]@{
        Cloud              = $Cloud
        MgGraphEnvironment = [string]$envConfig.entraEnvironment
        GraphEndpoint      = [string]$envConfig.graphEndpoint
        LoginEndpoint      = [string]$envConfig.loginEndpoint
        Verified           = $verified.Verified
    }
}

function New-AvdEntraConditionalAccessPayload {
    <#
    .SYNOPSIS
      Builds a Conditional Access policy payload from a template object, enriching grantControls
      with phishing-resistant MFA authenticationStrength (windowsHelloForBusiness, fido2,
      x509CertificateMultiFactor) and strict session controls when ComplianceProfile is 'itar-cui'.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$PolicyDefinition,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string[]]$IncludeGroupIds,
        [Parameter(Mandatory)][string[]]$ExcludeGroupIds,
        [string]$ExcludeStorageAppId = '',
        [ValidateSet('standard', 'itar-cui')]
        [string]$ComplianceProfile = 'standard'
    )
    $policyState = if ($PolicyDefinition.PSObject.Properties['state'] -and $PolicyDefinition.state) {
        [string]$PolicyDefinition.state
    }
    else {
        'enabledForReportingButNotEnforced'
    }

    $conditionsBody = @{
        applications = @{
            includeApplications = @($PolicyDefinition.conditions.applications.includeApplications)
        }
        users        = @{
            includeGroups = @($IncludeGroupIds)
            excludeGroups = @($ExcludeGroupIds)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExcludeStorageAppId)) {
        $existingExcludes = if ($PolicyDefinition.conditions.applications.PSObject.Properties['excludeApplications'] -and $PolicyDefinition.conditions.applications.excludeApplications) {
            @($PolicyDefinition.conditions.applications.excludeApplications)
        }
        else {
            @()
        }
        if ($existingExcludes -notcontains $ExcludeStorageAppId) {
            $existingExcludes += $ExcludeStorageAppId
        }
        $conditionsBody.applications['excludeApplications'] = @($existingExcludes)
    }

    $grantControls = @{
        operator        = if ($PolicyDefinition.grantControls.PSObject.Properties['operator']) { [string]$PolicyDefinition.grantControls.operator } else { 'OR' }
        builtInControls = @($PolicyDefinition.grantControls.builtInControls)
    }

    $sessionControls = @{
        signInFrequency = @{
            value     = [int]$PolicyDefinition.sessionControls.signInFrequency.value
            type      = [string]$PolicyDefinition.sessionControls.signInFrequency.type
            isEnabled = [bool]$PolicyDefinition.sessionControls.signInFrequency.isEnabled
        }
    }

    if ($ComplianceProfile -eq 'itar-cui') {
        $grantControls['authenticationStrength'] = @{
            id                    = '00000000-0000-0000-0000-000000000004'
            displayName           = 'Phishing-resistant MFA'
            requirementsSatisfied = 'mfa'
            allowedCombinations   = @($script:PhishingResistantMfaCombinations)
        }
        $sessionControls['signInFrequency'] = @{
            value              = 4
            type               = 'hours'
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval  = 'timeBased'
            isEnabled          = $true
        }
        $sessionControls['persistentBrowser'] = @{
            mode      = 'never'
            isEnabled = $true
        }
    }

    return @{
        displayName     = $DisplayName
        state           = $policyState
        conditions      = $conditionsBody
        grantControls   = $grantControls
        sessionControls = $sessionControls
    }
}

function Get-EntraDeterministicGuid {
    <#
    .SYNOPSIS
      Computes a deterministic UUID v4-formatted GUID from a seed string.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Seed
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("avd-ops-entra:$Seed")
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $guidBytes = [byte[]]::new(16)
    [Array]::Copy($hash, 0, $guidBytes, 0, 16)
    # Set version 4 and variant bits for valid UUID format
    $guidBytes[7] = ($guidBytes[7] -band 0x0F) -bor 0x40
    $guidBytes[8] = ($guidBytes[8] -band 0x3F) -bor 0x80
    return ([guid]::new($guidBytes)).ToString()
}

function Get-EntraRandomPassword {
    <#
    .SYNOPSIS
      Generates a cryptographically random password meeting Windows and Entra complexity rules.
    #>
    [OutputType([string])]
    param([int]$Length = 24)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%*-_=+?')
    $all = -join $sets
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($s in $sets) {
        $chars.Add($s[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($s.Length)])
    }
    while ($chars.Count -lt $Length) {
        $chars.Add($all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)])
    }
    $shuffled = $chars | Sort-Object { [System.Security.Cryptography.RandomNumberGenerator]::GetInt32([int]::MaxValue) }
    return (-join $shuffled)
}

function Resolve-EntraPythonCommand {
    <#
    .SYNOPSIS
      Resolves a working Python 3 executable across Linux, macOS, and Windows.
    #>
    foreach ($candidate in @('python3', 'python', 'py')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        if ($cmd.Source -like '*\WindowsApps\*') { continue }
        return $cmd.Source
    }
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($localPy) { return $localPy.FullName }
    return 'python3'
}

function Get-EntraGraphFilterUri {
    <#
    .SYNOPSIS
      Builds an OData-filtered Microsoft Graph v1.0 collection URI for the active cloud environment.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Collection,
        [Parameter(Mandatory)][string]$Filter,
        [string]$Select = '',
        [ValidateSet('commercial', 'usgov')][string]$Cloud = $script:ActiveCloud
    )
    $baseUri = Get-EntraGraphEndpoint -Cloud $Cloud
    $escaped = [uri]::EscapeDataString($Filter)
    $uri = "$baseUri/v1.0/$Collection`?`$filter=$escaped"
    if ($Select) {
        $uri += "&`$select=$Select"
    }
    return $uri
}

function Invoke-EntraGraphDryRun {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Method,
        [object]$Body
    )
    if (-not $script:DryRunStore) {
        $script:DryRunStore = @{
            groups               = [ordered]@{}
            policies             = [ordered]@{}
            applications         = [ordered]@{}
            servicePrincipals    = [ordered]@{}
            grants               = [ordered]@{}
            users                = [ordered]@{}
            groupMembers         = @{}
            requests             = [System.Collections.Generic.List[object]]::new()
        }
    }

    $script:DryRunStore.requests.Add([pscustomobject]@{
        Method = $Method
        Uri    = $Uri
        Body   = $Body
    })

    if ($Method -eq 'GET') {
        if ($Uri -match '/subscribedSkus') {
            return @(
                [pscustomobject]@{
                    skuId            = (Get-EntraDeterministicGuid -Seed 'sku:m365-e3')
                    skuPartNumber    = 'SPE_E3'
                    capabilityStatus = 'Enabled'
                    consumedUnits    = 1
                    prepaidUnits     = [pscustomobject]@{ enabled = 25 }
                    servicePlans     = @(
                        [pscustomobject]@{ servicePlanName = 'INTUNE_A'; provisioningStatus = 'Success' }
                        [pscustomobject]@{ servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }
                    )
                }
            )
        }
        if ($Uri -match '/organization') {
            return @(
                [pscustomobject]@{
                    id              = (Get-EntraDeterministicGuid -Seed 'org:contoso')
                    verifiedDomains = @(
                        [pscustomobject]@{ name = 'contoso.com'; isDefault = $true }
                    )
                }
            )
        }
        if ($Uri -match "servicePrincipals.*00000003-0000-0000-c000-000000000000") {
            $scopes = foreach ($s in (@('openid', 'profile', 'offline_access', 'User.Read') + $script:OperatorScopes)) {
                [pscustomobject]@{
                    id    = (Get-EntraDeterministicGuid -Seed "scope:$s")
                    value = $s
                }
            }
            return @(
                [pscustomobject]@{
                    id                     = (Get-EntraDeterministicGuid -Seed 'sp:msgraph')
                    appId                  = $script:GraphAppId
                    displayName            = 'Microsoft Graph'
                    oauth2PermissionScopes = @($scopes)
                }
            )
        }
        if ($Uri -match 'applications\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "displayName eq '(.+?)'") {
                $targetName = $Matches[1] -replace "''", "'"
                if ($targetName.StartsWith('[Storage Account] ') -and -not $script:DryRunStore.applications.Contains($targetName)) {
                    $appId = Get-EntraDeterministicGuid -Seed "storage-appId:$targetName"
                    $objId = Get-EntraDeterministicGuid -Seed "storage-appObj:$targetName"
                    $spId = Get-EntraDeterministicGuid -Seed "storage-sp:$targetName"
                    $appObj = [pscustomobject]@{
                        id                     = $objId
                        appId                  = $appId
                        displayName            = $targetName
                        tags                   = @()
                        requiredResourceAccess = @()
                    }
                    $script:DryRunStore.applications[$targetName] = $appObj
                    $script:DryRunStore.servicePrincipals[$appId] = [pscustomobject]@{
                        id                        = $spId
                        appId                     = $appId
                        displayName               = $targetName
                        appRoleAssignmentRequired = $false
                    }
                }
                if ($script:DryRunStore.applications.Contains($targetName)) {
                    return @($script:DryRunStore.applications[$targetName])
                }
            }
            return @()
        }
        if ($Uri -match '/applications/([^/?]+)/owners') {
            return @()
        }
        if ($Uri -match 'servicePrincipals\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "appId eq '([^']+)'") {
                $appId = $Matches[1]
                if ($script:DryRunStore.servicePrincipals.Contains($appId)) {
                    return @($script:DryRunStore.servicePrincipals[$appId])
                }
            }
            return @()
        }
        if ($Uri -match 'oauth2PermissionGrants\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "clientId eq '([^']+)'") {
                $clientId = $Matches[1]
                if ($script:DryRunStore.grants.Contains($clientId)) {
                    return @($script:DryRunStore.grants[$clientId])
                }
            }
            return @()
        }
        if ($Uri -match 'groups\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "displayName eq '(.+?)'") {
                $name = $Matches[1] -replace "''", "'"
                if ($script:DryRunStore.groups.Contains($name)) {
                    return @($script:DryRunStore.groups[$name])
                }
            }
            return @()
        }
        if ($Uri -match '/groups/([^/?]+)/members') {
            $gid = $Matches[1]
            if ($script:DryRunStore.groupMembers.ContainsKey($gid)) {
                return @($script:DryRunStore.groupMembers[$gid])
            }
            return @()
        }
        if ($Uri -match 'identity/conditionalAccess/policies\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "displayName eq '(.+?)'") {
                $name = $Matches[1] -replace "''", "'"
                if ($script:DryRunStore.policies.Contains($name)) {
                    return @($script:DryRunStore.policies[$name])
                }
            }
            return @()
        }
        if ($Uri -match 'identity/conditionalAccess/policies$') {
            return @($script:DryRunStore.policies.Values)
        }
        if ($Uri -match 'users\?\$filter=') {
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match "userPrincipalName eq '([^']+)'") {
                $upn = $Matches[1]
                if ($script:DryRunStore.users.Contains($upn)) {
                    return @($script:DryRunStore.users[$upn])
                }
            }
            return @()
        }
        return @()
    }

    if ($Method -eq 'POST') {
        if ($Uri -match '/groups/([^/?]+)/members/\$ref') {
            $gid = $Matches[1]
            if (-not $script:DryRunStore.groupMembers.ContainsKey($gid)) {
                $script:DryRunStore.groupMembers[$gid] = [System.Collections.Generic.List[object]]::new()
            }
            $script:DryRunStore.groupMembers[$gid].Add([pscustomobject]@{ id = (Get-EntraDeterministicGuid -Seed "member:$gid") })
            return $null
        }
        if ($Uri -match '/groups$') {
            $id = Get-EntraDeterministicGuid -Seed "group:$($Body.displayName)"
            $obj = [pscustomobject]@{
                id                            = $id
                displayName                   = $Body.displayName
                description                   = $Body.description
                securityEnabled               = [bool]$Body.securityEnabled
                mailEnabled                   = [bool]$Body.mailEnabled
                groupTypes                    = if ($Body.ContainsKey('groupTypes')) { @($Body.groupTypes) } else { @() }
                membershipRule                = if ($Body.ContainsKey('membershipRule')) { $Body.membershipRule } else { $null }
                membershipRuleProcessingState = if ($Body.ContainsKey('membershipRuleProcessingState')) { $Body.membershipRuleProcessingState } else { $null }
            }
            $script:DryRunStore.groups[$Body.displayName] = $obj
            return $obj
        }
        if ($Uri -match '/identity/conditionalAccess/policies$') {
            $id = Get-EntraDeterministicGuid -Seed "ca:$($Body.displayName)"
            $obj = [pscustomobject]@{
                id              = $id
                displayName     = $Body.displayName
                state           = $Body.state
                conditions      = $Body.conditions
                grantControls   = $Body.grantControls
                sessionControls = $Body.sessionControls
            }
            $script:DryRunStore.policies[$Body.displayName] = $obj
            return $obj
        }
        if ($Uri -match '/applications$') {
            $id = Get-EntraDeterministicGuid -Seed "appObj:$($Body.displayName)"
            $appId = Get-EntraDeterministicGuid -Seed "appId:$($Body.displayName)"
            $obj = [pscustomobject]@{
                id                     = $id
                appId                  = $appId
                displayName            = $Body.displayName
                isFallbackPublicClient = $Body.isFallbackPublicClient
                publicClient           = $Body.publicClient
                requiredResourceAccess = $Body.requiredResourceAccess
                tags                   = @()
            }
            $script:DryRunStore.applications[$Body.displayName] = $obj
            return $obj
        }
        if ($Uri -match '/servicePrincipals$') {
            $id = Get-EntraDeterministicGuid -Seed "sp:$($Body.appId)"
            $obj = [pscustomobject]@{
                id                        = $id
                appId                     = $Body.appId
                displayName               = if ($Body.ContainsKey('displayName')) { $Body.displayName } else { $Body.appId }
                appRoleAssignmentRequired = [bool]$Body.appRoleAssignmentRequired
            }
            $script:DryRunStore.servicePrincipals[$Body.appId] = $obj
            return $obj
        }
        if ($Uri -match '/oauth2PermissionGrants$') {
            $id = Get-EntraDeterministicGuid -Seed "grant:$($Body.clientId)"
            $obj = [pscustomobject]@{
                id          = $id
                clientId    = $Body.clientId
                consentType = $Body.consentType
                resourceId  = $Body.resourceId
                scope       = $Body.scope
            }
            $script:DryRunStore.grants[$Body.clientId] = $obj
            return $obj
        }
        if ($Uri -match '/users/([^/?]+)/assignLicense$') {
            return [pscustomobject]@{ id = $Matches[1] }
        }
        if ($Uri -match '/users$') {
            $id = Get-EntraDeterministicGuid -Seed "user:$($Body.userPrincipalName)"
            $obj = [pscustomobject]@{
                id                = $id
                userPrincipalName = $Body.userPrincipalName
                displayName       = $Body.displayName
            }
            $script:DryRunStore.users[$Body.userPrincipalName] = $obj
            return $obj
        }
    }

    if ($Method -eq 'PATCH') {
        if ($Uri -match '/applications/([^/?]+)$') {
            $appObjId = $Matches[1]
            foreach ($k in @($script:DryRunStore.applications.Keys)) {
                if ($script:DryRunStore.applications[$k].id -eq $appObjId) {
                    if ($Body.ContainsKey('tags')) {
                        $script:DryRunStore.applications[$k].tags = @($Body.tags)
                    }
                }
            }
        }
        if ($Uri -match '/identity/conditionalAccess/policies/([^/?]+)$') {
            $polId = $Matches[1]
            foreach ($k in @($script:DryRunStore.policies.Keys)) {
                if ($script:DryRunStore.policies[$k].id -eq $polId) {
                    $script:DryRunStore.policies[$k].grantControls = $Body.grantControls
                    $script:DryRunStore.policies[$k].sessionControls = $Body.sessionControls
                    $script:DryRunStore.policies[$k].conditions = $Body.conditions
                }
            }
        }
        return $null
    }

    if ($Method -eq 'DELETE') {
        return $null
    }

    return $null
}

function Clear-EntraDryRunStore {
    <#
    .SYNOPSIS
      Clears the in-memory dry-run store and test mock used for offline Graph testing.
    #>
    $script:DryRunStore = $null
    $script:EntraGraphMock = $null
    $script:ActiveCloud = 'commercial'
}

function Invoke-EntraGraph {
    <#
    .SYNOPSIS
      Invokes Microsoft Graph v1.0 REST endpoints via az rest (or dry-run/test mock),
      routing to the cloud-resolved Graph endpoint from contract C26.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET',
        [object]$Body = $null,
        [ValidateSet('commercial', 'usgov')][string]$Cloud = $script:ActiveCloud,
        [switch]$DryRun
    )
    $baseUri = Get-EntraGraphEndpoint -Cloud $Cloud
    $fullUri = if ($Uri -match '^https://') {
        $Uri
    }
    elseif ($Uri -match '^/?v1\.0/') {
        "$baseUri/$($Uri.TrimStart('/'))"
    }
    else {
        "$baseUri/v1.0/$($Uri.TrimStart('/'))"
    }

    if ($script:EntraGraphMock -is [scriptblock]) {
        return (& $script:EntraGraphMock $Method $fullUri $Body)
    }

    if ($DryRun -or $env:AVD_OPS_DRY_RUN -eq '1') {
        return Invoke-EntraGraphDryRun -Uri $fullUri -Method $Method -Body $Body
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $fullUri

    while ($nextUri) {
        $tempFile = $null
        try {
            $azArgs = @('rest', '--method', $Method, '--url', $nextUri, '--output', 'json')
            if ($null -ne $Body) {
                $tempFile = [System.IO.Path]::GetTempFileName()
                $jsonBody = $Body | ConvertTo-Json -Depth 20 -Compress
                [System.IO.File]::WriteAllText($tempFile, $jsonBody, [System.Text.UTF8Encoding]::new($false))
                $azArgs += @('--headers', 'Content-Type=application/json', '--body', "@$tempFile")
            }
            $rawOutput = & az @azArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "az rest $Method $nextUri failed: $($rawOutput -join "`n")"
            }
        }
        finally {
            if ($tempFile -and (Test-Path -LiteralPath $tempFile)) {
                Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
            }
        }

        if ($Method -ne 'GET') {
            $joined = ($rawOutput | Out-String).Trim()
            if (-not $joined) { return $null }
            return ($joined | ConvertFrom-Json -Depth 20)
        }

        $joined = ($rawOutput | Out-String).Trim()
        if (-not $joined) { return @() }
        $parsed = $joined | ConvertFrom-Json -Depth 20
        if ($null -ne $parsed -and $parsed.PSObject.Properties['value']) {
            foreach ($v in @($parsed.value)) {
                $items.Add($v)
            }
            $nextLinkProp = $parsed.PSObject.Properties['@odata.nextLink']
            $nextUri = if ($nextLinkProp -and $nextLinkProp.Value) { [string]$nextLinkProp.Value } else { $null }
        }
        else {
            return $parsed
        }
    }

    return $items.ToArray()
}

Export-ModuleMember -Function @(
    'Resolve-AvdCloudEnvironment',
    'Set-AvdEntraCloudContext',
    'Get-EntraGraphEndpoint',
    'Test-AvdEntraCloudContext',
    'Assert-AvdCloudMatch',
    'Connect-AvdEntraGraph',
    'New-AvdEntraConditionalAccessPayload',
    'Get-EntraDeterministicGuid',
    'Get-EntraRandomPassword',
    'Resolve-EntraPythonCommand',
    'Get-EntraGraphFilterUri',
    'Invoke-EntraGraph',
    'Clear-EntraDryRunStore'
)
