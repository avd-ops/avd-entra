# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
  Idempotently deploys the avd-entra identity control plane (security groups, dynamic device group,
  report-only Conditional Access policies, optional Graph operator app, Entra Kerberos readiness,
  and optional greenfield lab users) via Microsoft Graph v1.0 REST and emits entra-manifest.json.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()][ValidateLength(2, 16)][string]$Prefix = 'avd',
    [Parameter()][ValidateSet('dev', 'test', 'prod')][string]$Environment = 'dev',
    [Parameter()][string[]]$PoolNames = @('pool1'),
    [Parameter()][string]$StorageAccountFqdn = '',
    [Parameter()][switch]$InitializeGraphApp,
    [Parameter()][switch]$SeedLabUsers,
    [Parameter()][string]$OutputPath = './entra-manifest.json',
    [Parameter()][string]$RunManifestPath = './entra-run-manifest.json',
    [Parameter()][switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name 'AvdEntra')) {
    Import-Module (Join-Path $PSScriptRoot 'AvdEntra.psm1')
}

$isDryRun = [bool]$DryRun -or ($env:AVD_OPS_DRY_RUN -eq '1')
$stamp = "[avd-ops-$Prefix-$Environment]"
$runObjects = [System.Collections.Generic.List[object]]::new()
$graphAppId = '00000003-0000-0000-c000-000000000000'
$operatorScopes = @(
    'Application.ReadWrite.All',
    'DelegatedPermissionGrant.ReadWrite.All',
    'Policy.Read.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Group.ReadWrite.All',
    'Directory.Read.All',
    'Device.ReadWrite.All',
    'DeviceManagementManagedDevices.ReadWrite.All'
)

function Set-EntraGroupObject {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$RoleKey,
        [switch]$DynamicDeviceGroup,
        [string]$MembershipRule = ''
    )
    $escaped = $DisplayName.Replace("'", "''")
    $filterUri = Get-EntraGraphFilterUri -Collection 'groups' -Filter "displayName eq '$escaped'" -Select 'id,displayName,description,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState'
    $existingList = @(Invoke-EntraGraph -Method GET -Uri $filterUri -DryRun:$isDryRun)
    if ($existingList.Count -gt 1) {
        throw "Multiple Entra groups match displayName '$DisplayName'. Resolve duplicates before running."
    }

    $nick = (($DisplayName.ToLowerInvariant() -replace '[^a-z0-9]', '-') -replace '-+', '-').Trim('-')
    if ($nick.Length -gt 64) { $nick = $nick.Substring(0, 64).Trim('-') }

    if ($existingList.Count -eq 1) {
        $existing = $existingList[0]
        $patchBody = @{}
        if ($existing.PSObject.Properties['description'] -and $existing.description -ne $Description) {
            $patchBody['description'] = $Description
        }
        if ($DynamicDeviceGroup -and $existing.PSObject.Properties['membershipRule'] -and $existing.membershipRule -ne $MembershipRule) {
            $patchBody['membershipRule'] = $MembershipRule
            $patchBody['membershipRuleProcessingState'] = 'On'
        }
        if ($patchBody.Count -gt 0 -and $PSCmdlet.ShouldProcess($DisplayName, 'Update Entra group properties')) {
            $null = Invoke-EntraGraph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$($existing.id)" -Body $patchBody -DryRun:$isDryRun
        }
        $members = @(Invoke-EntraGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($existing.id)/members?`$select=id&`$top=1" -DryRun:$isDryRun)
        $runObjects.Add([ordered]@{
            type        = 'group'
            role        = $RoleKey
            id          = [string]$existing.id
            displayName = $DisplayName
            created     = $false
            stateful    = ($members.Count -gt 0)
        })
        return $existing
    }

    $createBody = @{
        displayName     = $DisplayName
        description     = $Description
        mailEnabled     = $false
        mailNickname    = $nick
        securityEnabled = $true
    }
    if ($DynamicDeviceGroup) {
        $createBody['groupTypes'] = @('DynamicMembership')
        $createBody['membershipRule'] = $MembershipRule
        $createBody['membershipRuleProcessingState'] = 'On'
    }

    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create Entra group')) {
        $created = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body $createBody -DryRun:$isDryRun
        $runObjects.Add([ordered]@{
            type        = 'group'
            role        = $RoleKey
            id          = [string]$created.id
            displayName = $DisplayName
            created     = $true
            stateful    = $false
        })
        return $created
    }

    $fallbackId = Get-EntraDeterministicGuid -Seed "whatif-group:$DisplayName"
    return [pscustomobject]@{ id = $fallbackId; displayName = $DisplayName }
}

# ---- 1. Preflight SKU check (subscribedSkus) ----
$subscribedSkus = @(Invoke-EntraGraph -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -DryRun:$isDryRun)
$allPlans = @(foreach ($sku in $subscribedSkus) {
    if ($null -ne $sku -and $sku.PSObject.Properties['servicePlans'] -and $sku.servicePlans) {
        foreach ($sp in @($sku.servicePlans)) { $sp }
    }
})
$hasIntune = @($allPlans | Where-Object { $_.servicePlanName -like 'INTUNE_A*' -and $_.provisioningStatus -eq 'Success' }).Count -gt 0
$hasEntraP1 = @($allPlans | Where-Object { $_.servicePlanName -like 'AAD_PREMIUM*' -and $_.provisioningStatus -eq 'Success' }).Count -gt 0

if (-not $hasIntune) {
    Write-Warning "Tenant subscribedSkus does not report an active INTUNE_A service plan. Session host Intune enrollment requires Intune licensing."
}
if (-not $hasEntraP1) {
    Write-Warning "Tenant subscribedSkus does not report an active AAD_PREMIUM service plan. Dynamic device groups and Conditional Access require Entra ID P1."
}

$availableSku = $subscribedSkus | Where-Object {
    $null -ne $_ -and
    $_.PSObject.Properties['prepaidUnits'] -and
    $_.prepaidUnits -and
    [int]$_.prepaidUnits.enabled -gt [int]$_.consumedUnits
} | Select-Object -First 1

# ---- 2. Optional Graph operator app registration (avd-opsbot) ----
if ($InitializeGraphApp) {
    $appDisplayName = "$stamp avd-opsbot"
    $graphSpUri = Get-EntraGraphFilterUri -Collection 'servicePrincipals' -Filter "appId eq '$graphAppId'" -Select 'id,appId,oauth2PermissionScopes'
    $graphSp = @(Invoke-EntraGraph -Method GET -Uri $graphSpUri -DryRun:$isDryRun) | Select-Object -First 1
    $grantScopes = @('openid', 'profile', 'offline_access') + $operatorScopes
    $scopeIds = [ordered]@{}
    if ($graphSp -and $graphSp.PSObject.Properties['oauth2PermissionScopes']) {
        foreach ($s in $grantScopes) {
            $matchScope = @($graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $s }) | Select-Object -First 1
            if ($matchScope) { $scopeIds[$s] = $matchScope.id }
        }
    }
    $wantAccess = @($scopeIds.Values | ForEach-Object { @{ id = $_; type = 'Scope' } })

    $escapedApp = $appDisplayName.Replace("'", "''")
    $appFilterUri = Get-EntraGraphFilterUri -Collection 'applications' -Filter "displayName eq '$escapedApp'" -Select 'id,appId,displayName,isFallbackPublicClient,publicClient,requiredResourceAccess'
    $existingApps = @(Invoke-EntraGraph -Method GET -Uri $appFilterUri -DryRun:$isDryRun)
    $appObj = $existingApps | Select-Object -First 1

    if (-not $appObj) {
        if ($PSCmdlet.ShouldProcess($appDisplayName, 'Create public client Graph operator application')) {
            $appObj = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
                displayName            = $appDisplayName
                description            = 'Delegated Microsoft Graph sign-in for avd-ops control-plane automation. Public client: no secret, no certificate.'
                signInAudience         = 'AzureADMyOrg'
                isFallbackPublicClient = $true
                publicClient           = @{ redirectUris = @('http://localhost') }
                requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = $wantAccess })
            } -DryRun:$isDryRun
            $runObjects.Add([ordered]@{
                type        = 'application'
                role        = 'graphOperatorApp'
                id          = [string]$appObj.id
                displayName = $appDisplayName
                created     = $true
                stateful    = $false
            })
        }
    }
    else {
        $runObjects.Add([ordered]@{
            type        = 'application'
            role        = 'graphOperatorApp'
            id          = [string]$appObj.id
            displayName = $appDisplayName
            created     = $false
            stateful    = $false
        })
    }

    if ($appObj) {
        $spFilterUri = Get-EntraGraphFilterUri -Collection 'servicePrincipals' -Filter "appId eq '$($appObj.appId)'" -Select 'id,appId,displayName,appRoleAssignmentRequired'
        $spObj = @(Invoke-EntraGraph -Method GET -Uri $spFilterUri -DryRun:$isDryRun) | Select-Object -First 1
        if (-not $spObj) {
            if ($PSCmdlet.ShouldProcess($appDisplayName, 'Create service principal with assignment required')) {
                $spObj = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{
                    appId                     = $appObj.appId
                    displayName               = $appDisplayName
                    appRoleAssignmentRequired = $true
                    tags                      = @('WindowsAzureActiveDirectoryIntegratedApp')
                } -DryRun:$isDryRun
            }
        }
        elseif (-not $spObj.appRoleAssignmentRequired) {
            if ($PSCmdlet.ShouldProcess($appDisplayName, 'Enable appRoleAssignmentRequired on service principal')) {
                $null = Invoke-EntraGraph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($spObj.id)" -Body @{
                    appRoleAssignmentRequired = $true
                } -DryRun:$isDryRun
            }
        }

        if ($spObj -and $graphSp) {
            $grantFilterUri = Get-EntraGraphFilterUri -Collection 'oauth2PermissionGrants' -Filter "clientId eq '$($spObj.id)'"
            $grants = @(Invoke-EntraGraph -Method GET -Uri $grantFilterUri -DryRun:$isDryRun)
            $existingGrant = @($grants | Where-Object { $_.consentType -eq 'AllPrincipals' -and $_.resourceId -eq $graphSp.id }) | Select-Object -First 1
            if (-not $existingGrant -and $PSCmdlet.ShouldProcess($appDisplayName, 'Grant admin consent for delegated Microsoft Graph scopes')) {
                $null = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
                    clientId    = $spObj.id
                    consentType = 'AllPrincipals'
                    resourceId  = $graphSp.id
                    scope       = ($grantScopes -join ' ')
                } -DryRun:$isDryRun
            }
        }
    }
}

# ---- 3. Idempotent Entra Security & Dynamic Groups ----
$usersGroup = Set-EntraGroupObject `
    -DisplayName "$stamp AVD Users" `
    -Description "AVD standard desktop users for $Prefix ($Environment)" `
    -RoleKey 'avdUsersGroupId'

$poolGroupMap = [ordered]@{}
foreach ($pool in $PoolNames) {
    if ([string]::IsNullOrWhiteSpace($pool)) { continue }
    $cleanPool = $pool.Trim()
    $poolGroup = Set-EntraGroupObject `
        -DisplayName "$stamp AVD Users ($cleanPool)" `
        -Description "AVD pool '$cleanPool' users for $Prefix ($Environment)" `
        -RoleKey "pool:$cleanPool"
    $poolGroupMap[$cleanPool] = [string]$poolGroup.id
}

$adminsGroup = Set-EntraGroupObject `
    -DisplayName "$stamp AVD Admins" `
    -Description "AVD session host administrators for $Prefix ($Environment)" `
    -RoleKey 'avdAdminsGroupId'

$breakGlassGroup = Set-EntraGroupObject `
    -DisplayName "$stamp AVD Break-Glass Exclude" `
    -Description "Emergency access accounts excluded from AVD Conditional Access policies for $Prefix ($Environment)" `
    -RoleKey 'breakGlassExcludeGroupId'

$dynamicRule = "(device.displayName -startsWith `"$Prefix`")"
$dynamicHostsGroup = Set-EntraGroupObject `
    -DisplayName "$stamp AVD Session Hosts" `
    -Description "Dynamic device group for AVD session hosts matching prefix '$Prefix' ($Environment)" `
    -RoleKey 'sessionHostsDynamicGroupId' `
    -DynamicDeviceGroup `
    -MembershipRule $dynamicRule

# ---- 4. Optional Entra Kerberos Storage App Readiness ----
$entraKerberosReady = $false
$storageKerberosAppId = $null
if (-not [string]::IsNullOrWhiteSpace($StorageAccountFqdn)) {
    $storageAppName = "[Storage Account] $($StorageAccountFqdn.Trim())"
    $escapedStorageName = $storageAppName.Replace("'", "''")
    $storageAppUri = Get-EntraGraphFilterUri -Collection 'applications' -Filter "displayName eq '$escapedStorageName'" -Select 'id,appId,displayName,tags,requiredResourceAccess'
    $storageApps = @(Invoke-EntraGraph -Method GET -Uri $storageAppUri -DryRun:$isDryRun)

    $unownedApps = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in $storageApps) {
        $owners = @(Invoke-EntraGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($candidate.id)/owners?`$select=id" -DryRun:$isDryRun)
        if ($owners.Count -eq 0) {
            $unownedApps.Add($candidate)
        }
    }

    if ($unownedApps.Count -eq 1) {
        $storageApp = $unownedApps[0]
        $storageKerberosAppId = [string]$storageApp.appId
        $storageSpUri = Get-EntraGraphFilterUri -Collection 'servicePrincipals' -Filter "appId eq '$storageKerberosAppId'" -Select 'id,appId,displayName'
        $storageSp = @(Invoke-EntraGraph -Method GET -Uri $storageSpUri -DryRun:$isDryRun) | Select-Object -First 1

        $graphSpUri = Get-EntraGraphFilterUri -Collection 'servicePrincipals' -Filter "appId eq '$graphAppId'" -Select 'id,appId,oauth2PermissionScopes'
        $graphSp = @(Invoke-EntraGraph -Method GET -Uri $graphSpUri -DryRun:$isDryRun) | Select-Object -First 1

        if ($storageSp -and $graphSp) {
            $requiredScopes = @('openid', 'profile', 'User.Read')
            $grantsUri = Get-EntraGraphFilterUri -Collection 'oauth2PermissionGrants' -Filter "clientId eq '$($storageSp.id)'"
            $grants = @(Invoke-EntraGraph -Method GET -Uri $grantsUri -DryRun:$isDryRun)
            $grant = @($grants | Where-Object { $_.consentType -eq 'AllPrincipals' -and $_.resourceId -eq $graphSp.id }) | Select-Object -First 1
            $haveScopes = if ($grant -and $grant.PSObject.Properties['scope'] -and $grant.scope) {
                @($grant.scope -split ' ' | Where-Object { $_ })
            }
            else {
                @()
            }
            $missingScopes = @($requiredScopes | Where-Object { $haveScopes -notcontains $_ })
            if ($missingScopes.Count -gt 0 -and $PSCmdlet.ShouldProcess($storageAppName, "Grant admin consent for $($requiredScopes -join ' ')")) {
                if ($grant) {
                    $null = Invoke-EntraGraph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grant.id)" -Body @{
                        scope = ((@($haveScopes) + $missingScopes) -join ' ')
                    } -DryRun:$isDryRun
                }
                else {
                    $null = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
                        clientId    = $storageSp.id
                        consentType = 'AllPrincipals'
                        resourceId  = $graphSp.id
                        scope       = ($requiredScopes -join ' ')
                    } -DryRun:$isDryRun
                }
            }
        }

        $sidTag = 'kdc_enable_cloud_group_sids'
        $existingTags = if ($storageApp.PSObject.Properties['tags'] -and $storageApp.tags) { @($storageApp.tags) } else { @() }
        if ($existingTags -notcontains $sidTag -and $PSCmdlet.ShouldProcess($storageAppName, "Add tag $sidTag")) {
            $null = Invoke-EntraGraph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($storageApp.id)" -Body @{
                tags = @($existingTags + $sidTag)
            } -DryRun:$isDryRun
        }
        $entraKerberosReady = $true
    }
    else {
        Write-Warning "Entra Kerberos storage application '$storageAppName' (with 0 owners) was not found. Enable Entra Kerberos on the storage account first."
    }
}

# ---- 5. Conditional Access Policies (report-only default) ----
$repoRoot = Split-Path -Parent $PSScriptRoot
$policyDir = Join-Path $repoRoot 'policies/conditional-access'
$caManifestList = [System.Collections.Generic.List[object]]::new()

if (Test-Path -LiteralPath $policyDir) {
    $policyFiles = @(Get-ChildItem -LiteralPath $policyDir -Filter '*.json' | Sort-Object Name)
    foreach ($pf in $policyFiles) {
        $rawTemplate = Get-Content -LiteralPath $pf.FullName -Raw -Encoding UTF8
        $renderedJson = $rawTemplate.Replace('{{avdUsersGroupId}}', [string]$usersGroup.id).Replace('{{breakGlassExcludeGroupId}}', [string]$breakGlassGroup.id)
        $policyDef = $renderedJson | ConvertFrom-Json -Depth 20

        $baseTitle = [string]$policyDef.displayName
        $policyDisplayName = if ($baseTitle.StartsWith('[avd-ops]')) {
            "$stamp" + $baseTitle.Substring('[avd-ops]'.Length)
        }
        elseif ($baseTitle.StartsWith($stamp)) {
            $baseTitle
        }
        else {
            "$stamp $baseTitle"
        }

        $policyState = if ($policyDef.PSObject.Properties['state'] -and $policyDef.state) {
            [string]$policyDef.state
        }
        else {
            'enabledForReportingButNotEnforced'
        }

        $conditionsBody = @{
            applications = @{
                includeApplications = @($policyDef.conditions.applications.includeApplications)
            }
            users        = @{
                includeGroups = @($policyDef.conditions.users.includeGroups)
                excludeGroups = @($policyDef.conditions.users.excludeGroups)
            }
        }
        if ($storageKerberosAppId) {
            $existingExcludes = if ($policyDef.conditions.applications.PSObject.Properties['excludeApplications'] -and $policyDef.conditions.applications.excludeApplications) {
                @($policyDef.conditions.applications.excludeApplications)
            }
            else {
                @()
            }
            if ($existingExcludes -notcontains $storageKerberosAppId) {
                $existingExcludes += $storageKerberosAppId
            }
            $conditionsBody.applications['excludeApplications'] = @($existingExcludes)
        }

        $policyPayload = @{
            displayName     = $policyDisplayName
            state           = $policyState
            conditions      = $conditionsBody
            grantControls   = $policyDef.grantControls
            sessionControls = $policyDef.sessionControls
        }

        $escapedPolicyName = $policyDisplayName.Replace("'", "''")
        $caFilterUri = Get-EntraGraphFilterUri -Collection 'identity/conditionalAccess/policies' -Filter "displayName eq '$escapedPolicyName'"
        $existingPolicies = @(Invoke-EntraGraph -Method GET -Uri $caFilterUri -DryRun:$isDryRun)
        if ($existingPolicies.Count -gt 1) {
            throw "Multiple Conditional Access policies match displayName '$policyDisplayName'."
        }

        if ($existingPolicies.Count -eq 1) {
            $existingPol = $existingPolicies[0]
            if ($PSCmdlet.ShouldProcess($policyDisplayName, 'Update Conditional Access policy')) {
                $null = Invoke-EntraGraph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existingPol.id)" -Body $policyPayload -DryRun:$isDryRun
            }
            $policyId = [string]$existingPol.id
            $runObjects.Add([ordered]@{
                type        = 'conditionalAccessPolicy'
                role        = $pf.BaseName
                id          = $policyId
                displayName = $policyDisplayName
                created     = $false
                stateful    = $false
            })
        }
        else {
            if ($PSCmdlet.ShouldProcess($policyDisplayName, 'Create Conditional Access policy')) {
                $createdPol = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body $policyPayload -DryRun:$isDryRun
                $policyId = [string]$createdPol.id
                $runObjects.Add([ordered]@{
                    type        = 'conditionalAccessPolicy'
                    role        = $pf.BaseName
                    id          = $policyId
                    displayName = $policyDisplayName
                    created     = $true
                    stateful    = $false
                })
            }
            else {
                $policyId = Get-EntraDeterministicGuid -Seed "whatif-ca:$policyDisplayName"
            }
        }

        $caManifestList.Add([pscustomobject][ordered]@{
            displayName = $policyDisplayName
            state       = $policyState
            policyId    = $policyId
        })
    }
}

# ---- 6. Optional Greenfield Lab User Seeding (-SeedLabUsers) ----
if ($SeedLabUsers) {
    $orgs = @(Invoke-EntraGraph -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains' -DryRun:$isDryRun)
    $defaultDomain = 'contoso.com'
    if ($orgs.Count -gt 0 -and $orgs[0].PSObject.Properties['verifiedDomains'] -and $orgs[0].verifiedDomains) {
        $defDomObj = @($orgs[0].verifiedDomains | Where-Object { $_.isDefault -eq $true }) | Select-Object -First 1
        if (-not $defDomObj) { $defDomObj = @($orgs[0].verifiedDomains) | Select-Object -First 1 }
        if ($defDomObj -and $defDomObj.name) { $defaultDomain = [string]$defDomObj.name }
    }

    $labUpn = "avd-user1-$Prefix-$Environment@$defaultDomain"
    $labDisplayName = "$stamp AVD Lab User 1"
    $userFilterUri = Get-EntraGraphFilterUri -Collection 'users' -Filter "userPrincipalName eq '$labUpn'" -Select 'id,userPrincipalName,displayName'
    $existingUsers = @(Invoke-EntraGraph -Method GET -Uri $userFilterUri -DryRun:$isDryRun)
    $labUser = $existingUsers | Select-Object -First 1

    if (-not $labUser) {
        if ($PSCmdlet.ShouldProcess($labDisplayName, "Create greenfield lab user ($labUpn)")) {
            $labPassword = Get-EntraRandomPassword
            $labUser = Invoke-EntraGraph -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body @{
                accountEnabled    = $true
                displayName       = $labDisplayName
                mailNickname      = "avd-user1-$Prefix-$Environment"
                userPrincipalName = $labUpn
                usageLocation     = 'US'
                passwordProfile   = @{
                    forceChangePasswordNextSignIn = $true
                    password                      = $labPassword
                }
            } -DryRun:$isDryRun
            $runObjects.Add([ordered]@{
                type        = 'user'
                role        = 'labUser1'
                id          = [string]$labUser.id
                displayName = $labDisplayName
                created     = $true
                stateful    = $true
            })
        }
    }
    else {
        $runObjects.Add([ordered]@{
            type        = 'user'
            role        = 'labUser1'
            id          = [string]$labUser.id
            displayName = $labDisplayName
            created     = $false
            stateful    = $true
        })
    }

    if ($labUser) {
        $currentMembers = @(Invoke-EntraGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($usersGroup.id)/members?`$select=id" -DryRun:$isDryRun)
        $alreadyMember = @($currentMembers | Where-Object { $_.id -eq $labUser.id }).Count -gt 0
        if (-not $alreadyMember -and $PSCmdlet.ShouldProcess($usersGroup.displayName, "Add lab user $labDisplayName")) {
            $null = Invoke-EntraGraph -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($usersGroup.id)/members/`$ref" -Body @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($labUser.id)"
            } -DryRun:$isDryRun
            foreach ($ro in $runObjects) {
                if ($ro.type -eq 'group' -and $ro.id -eq $usersGroup.id) {
                    $ro.stateful = $true
                }
            }
        }

        if ($availableSku -and $PSCmdlet.ShouldProcess($labDisplayName, "Assign existing SKU $($availableSku.skuPartNumber)")) {
            $null = Invoke-EntraGraph -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($labUser.id)/assignLicense" -Body @{
                addLicenses    = @(@{ skuId = [string]$availableSku.skuId })
                removeLicenses = @()
            } -DryRun:$isDryRun
        }
    }
}

# ---- 7. Emit entra-manifest.json and entra-run-manifest.json ----
$manifest = [ordered]@{
    schema             = 'avd-ops-entra-manifest/v1'
    environment        = $Environment
    prefix             = $Prefix
    groups             = [pscustomobject][ordered]@{
        avdUsersGroupId            = [string]$usersGroup.id
        avdAdminsGroupId           = [string]$adminsGroup.id
        sessionHostsDynamicGroupId = [string]$dynamicHostsGroup.id
        breakGlassExcludeGroupId   = [string]$breakGlassGroup.id
    }
    conditionalAccess  = @($caManifestList)
    entraKerberosReady = [bool]$entraKerberosReady
}

$runManifest = [ordered]@{
    schema      = 'avd-ops-entra-run-manifest/v1'
    environment = $Environment
    prefix      = $Prefix
    stamp       = $stamp
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    poolGroups  = $poolGroupMap
    objects     = @($runObjects)
}

$outParent = Split-Path -Parent $OutputPath
if ($outParent -and -not (Test-Path -LiteralPath $outParent)) {
    $null = New-Item -ItemType Directory -Path $outParent -Force
}
$manifestJson = $manifest | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText(($PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)), $manifestJson + "`n", [System.Text.UTF8Encoding]::new($false))

$runParent = Split-Path -Parent $RunManifestPath
if ($runParent -and -not (Test-Path -LiteralPath $runParent)) {
    $null = New-Item -ItemType Directory -Path $runParent -Force
}
$runManifestJson = $runManifest | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText(($PSCmdlet.GetUnresolvedProviderPathFromPSPath($RunManifestPath)), $runManifestJson + "`n", [System.Text.UTF8Encoding]::new($false))

$pythonExe = Resolve-EntraPythonCommand
$validateScript = Join-Path $PSScriptRoot 'validate.py'
$validationOutput = & $pythonExe $validateScript --manifest $OutputPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Contract validation failed for $OutputPath`: $($validationOutput -join "`n")"
}

return [pscustomobject]$manifest
