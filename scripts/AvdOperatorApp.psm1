# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
  Pure helpers and guardrails for the opt-in avd-ops operator Enterprise App bootstrap.
#>

Set-StrictMode -Version Latest

$script:GitHubIssuer = 'https://token.actions.githubusercontent.com'
$script:BlockedCredentials = @('passwordAddition', 'customPasswordAddition', 'symmetricKeyAddition')

# Built-in Entra directory role template IDs allowed to run the bootstrap (Privileged Role Administrator or Global Administrator).
$script:AllowedCallerRoleTemplateIds = @(
    '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
)

function Get-AvdOperatorProp {
    <#
    .SYNOPSIS
      Returns a property value from a hashtable or PSObject, or null.
    #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-AvdOperatorPlanesConfig {
    <#
    .SYNOPSIS
      Loads and validates the operator planes contract JSON.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()][string]$ConfigPath = (Join-Path $PSScriptRoot '../contracts/operator-planes.json')
    )
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Operator planes contract not found at '$ConfigPath'."
    }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-AvdOperatorPlanesSafe -Config $cfg
    return $cfg
}

function Test-AvdOperatorDeniedRole {
    <#
    .SYNOPSIS
      Tests whether an appRole value or ID is on the deny list.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][object]$DenyList
    )
    $deniedIds = @($DenyList.ids | ForEach-Object { [string]$_ })
    if ($deniedIds -contains $Id.ToLowerInvariant()) {
        return $true
    }
    foreach ($pattern in @($DenyList.values)) {
        if ($Value -like [string]$pattern) {
            return $true
        }
    }
    return $false
}

function Assert-AvdOperatorPlanesSafe {
    <#
    .SYNOPSIS
      Verifies that no plane in the contract includes a denied appRole.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config
    )
    $deny = $Config.denyList
    foreach ($planeProp in $Config.planes.PSObject.Properties) {
        $planeName = $planeProp.Name
        $plane = $planeProp.Value
        $allRoles = @($plane.appRoles)
        $optProp = $plane.PSObject.Properties['optionalAppRoles']
        if ($optProp -and $null -ne $optProp.Value) {
            foreach ($optGroup in $optProp.Value.PSObject.Properties) {
                $allRoles += @($optGroup.Value)
            }
        }
        foreach ($r in $allRoles) {
            if (Test-AvdOperatorDeniedRole -Value ([string]$r.value) -Id ([string]$r.id) -DenyList $deny) {
                throw "Plane '$planeName' contains denied appRole '$($r.value)' ($($r.id))."
            }
        }
    }
}

function Get-AvdOperatorRequestedRole {
    <#
    .SYNOPSIS
      Collects deduplicated Graph appRoles requested for the given planes.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string[]]$Planes,
        [Parameter()][switch]$IncludeWin365
    )
    $byId = [ordered]@{}
    foreach ($p in $Planes) {
        $planeProp = $Config.planes.PSObject.Properties[$p]
        if (-not $planeProp) {
            throw "Unknown operator plane '$p'."
        }
        $roles = @($planeProp.Value.appRoles)
        if ($p -eq 'intune' -and $IncludeWin365.IsPresent) {
            $optProp = $planeProp.Value.PSObject.Properties['optionalAppRoles']
            if ($optProp -and $optProp.Value.PSObject.Properties['includeWin365']) {
                $roles += @($optProp.Value.includeWin365)
            }
        }
        foreach ($r in $roles) {
            $id = ([string]$r.id).ToLowerInvariant()
            if (-not $byId.Contains($id)) {
                $byId[$id] = [pscustomobject]@{
                    value = [string]$r.value
                    id    = $id
                }
            }
        }
    }
    return @($byId.Values)
}

function Get-AvdOperatorSubject {
    <#
    .SYNOPSIS
      Builds an immutable GitHub environment OIDC subject claim.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$OwnerId,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$RepoId,
        [Parameter(Mandatory)][string]$Environment
    )
    if ($OwnerId -notmatch '^\d+$' -or $RepoId -notmatch '^\d+$') {
        throw "Owner and repo IDs must be GitHub numeric IDs (got '$OwnerId', '$RepoId')."
    }
    if ($Owner -notmatch '^[A-Za-z0-9-]+$' -or $Repo -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Invalid GitHub owner/repo name: '$Owner/$Repo'."
    }
    if ($Environment -notmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw "Invalid GitHub environment name: '$Environment'."
    }
    return "repo:$Owner@$OwnerId/$Repo@$RepoId`:environment:$Environment"
}

function Get-AvdOperatorCredentialName {
    <#
    .SYNOPSIS
      Builds a deterministic federated identity credential name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RepoId,
        [Parameter(Mandatory)][string]$Environment
    )
    if ($RepoId -notmatch '^\d+$') {
        throw "Repo ID must be numeric (got '$RepoId')."
    }
    $sanitizedEnv = ($Environment -replace '[^A-Za-z0-9_-]', '-')
    $name = "gh-$RepoId-$sanitizedEnv"
    if ($name.Length -gt 120) {
        throw "Federated credential name '$name' exceeds Entra 120-character limit."
    }
    return $name
}

function Get-AvdOperatorPolicyBody {
    <#
    .SYNOPSIS
      Builds the appManagementPolicy payload that blocks secrets and keys.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$AppDisplayName
    )
    return @{
        displayName  = "$AppDisplayName no secrets"
        description  = "Blocks passwords and symmetric keys on $AppDisplayName (federated credentials only)."
        isEnabled    = $true
        restrictions = @{
            passwordCredentials = @($script:BlockedCredentials | ForEach-Object {
                @{
                    restrictionType = $_
                    state           = 'enabled'
                    maxLifetime     = $null
                }
            })
        }
    }
}

function Get-AvdOperatorStampName {
    <#
    .SYNOPSIS
      Builds the operator application displayName for a stamp.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string[]]$Planes
    )
    $planeSuffix = (@($Planes | Sort-Object -Unique) -join '-')
    return "[avd-ops-$Prefix-$Environment] operator-$planeSuffix"
}

function Assert-AvdOperatorCaller {
    <#
    .SYNOPSIS
      Verifies that the signed-in caller is an interactive user holding Global Admin or Privileged Role Admin.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][object]$CallerMe,
        [Parameter()][object[]]$CallerMemberOf = @()
    )
    if ($null -eq $CallerMe) {
        throw 'Unable to resolve signed-in caller (/me). Service principals cannot run the operator bootstrap.'
    }
    $odataType = [string](Get-AvdOperatorProp $CallerMe '@odata.type')
    if ($odataType -and $odataType -ne '#microsoft.graph.user') {
        throw "Caller must be an interactive Entra user, not '$odataType'."
    }
    $upn = [string](Get-AvdOperatorProp $CallerMe 'userPrincipalName')
    $id = [string](Get-AvdOperatorProp $CallerMe 'id')
    if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($upn)) {
        throw 'Caller (/me) did not return a user id and userPrincipalName; service principals are refused.'
    }

    $hasAllowedRole = $false
    foreach ($m in @($CallerMemberOf | Where-Object { $_ })) {
        $mType = [string](Get-AvdOperatorProp $m '@odata.type')
        $roleTemplateId = ([string](Get-AvdOperatorProp $m 'roleTemplateId')).ToLowerInvariant()
        if ($mType -eq '#microsoft.graph.directoryRole' -and $script:AllowedCallerRoleTemplateIds -contains $roleTemplateId) {
            $hasAllowedRole = $true
            break
        }
    }
    if (-not $hasAllowedRole) {
        throw "Caller '$upn' must hold Privileged Role Administrator or Global Administrator to consent operator app roles."
    }
    return $id
}

function Assert-AvdOperatorAppClean {
    <#
    .SYNOPSIS
      Verifies that an operator application has no secrets, one owner (caller), and only immutable environment FICs.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'FederatedCredentials holds OIDC federated identity credential objects, not passwords or secrets.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$App,
        [Parameter(Mandatory)][object[]]$Owners,
        [Parameter(Mandatory)][string]$CallerUserId,
        [Parameter()][object[]]$FederatedCredentials = @()
    )
    $pwdCreds = @(Get-AvdOperatorProp $App 'passwordCredentials' | Where-Object { $_ })
    $keyCreds = @(Get-AvdOperatorProp $App 'keyCredentials' | Where-Object { $_ })
    if ($pwdCreds.Count -gt 0 -or $keyCreds.Count -gt 0) {
        throw "Operator app '$($App.appId)' has existing passwordCredentials ($($pwdCreds.Count)) or keyCredentials ($($keyCreds.Count)). Refusing to consent."
    }
    $ownerIds = @($Owners | Where-Object { $_ } | ForEach-Object { [string](Get-AvdOperatorProp $_ 'id') })
    if ($ownerIds.Count -ne 1 -or $ownerIds[0] -ne $CallerUserId) {
        throw "Operator app '$($App.appId)' must have exactly one owner (caller '$CallerUserId'); found [$($ownerIds -join ', ')]."
    }
    foreach ($fic in @($FederatedCredentials | Where-Object { $_ })) {
        $subj = [string](Get-AvdOperatorProp $fic 'subject')
        $cme = Get-AvdOperatorProp $fic 'claimsMatchingExpression'
        if ($null -ne $cme) {
            throw "Operator app '$($App.appId)' has a flexible federated credential (claimsMatchingExpression), which is not allowed."
        }
        if ($subj -notmatch '^repo:[A-Za-z0-9-]+@\d+/[A-Za-z0-9._-]+@\d+:environment:[A-Za-z0-9._-]+$') {
            throw "Operator app '$($App.appId)' has non-immutable or non-environment FIC subject '$subj'."
        }
    }
}

function Resolve-AvdOperatorGraphRole {
    <#
    .SYNOPSIS
      Resolves requested appRoles against the Microsoft Graph service principal and deny list.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$RequestedRoles,
        [Parameter(Mandatory)][object]$GraphServicePrincipal,
        [Parameter(Mandatory)][object]$DenyList
    )
    $spAppRoles = @(Get-AvdOperatorProp $GraphServicePrincipal 'appRoles' | Where-Object { $_ })
    $resolved = @()
    foreach ($req in $RequestedRoles) {
        if (Test-AvdOperatorDeniedRole -Value $req.value -Id $req.id -DenyList $DenyList) {
            throw "Refusing denied appRole '$($req.value)' ($($req.id))."
        }
        $match = @($spAppRoles | Where-Object { $_.value -eq $req.value } | Select-Object -First 1)
        if ($match.Count -eq 0 -or $null -eq $match[0]) {
            throw "Graph service principal does not expose appRole '$($req.value)' in this cloud."
        }
        $spId = ([string]$match[0].id).ToLowerInvariant()
        if ($spId -ne $req.id.ToLowerInvariant()) {
            throw "Graph appRole ID mismatch for '$($req.value)': contract='$($req.id)', Graph SP='$spId'."
        }
        $resolved += [pscustomobject]@{
            value = $req.value
            id    = $spId
        }
    }
    return $resolved
}

function Get-AvdOperatorOidcAudience {
    <#
    .SYNOPSIS
      Returns the expected OIDC audience for the target cloud from cloud-environments.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Cloud,
        [Parameter()][string]$ContractPath = (Join-Path $PSScriptRoot '../contracts/cloud-environments.json')
    )
    $raw = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $match = @($raw.environments | Where-Object { $_.id -eq $Cloud } | Select-Object -First 1)
    if ($match.Count -eq 0 -or $null -eq $match[0].PSObject.Properties['oidcAudience']) {
        throw "Missing oidcAudience in '$ContractPath' for cloud '$Cloud'."
    }
    return [string]$match[0].oidcAudience
}

Export-ModuleMember -Function @(
    'Get-AvdOperatorPlanesConfig',
    'Get-AvdOperatorOidcAudience',
    'Test-AvdOperatorDeniedRole',
    'Assert-AvdOperatorPlanesSafe',
    'Get-AvdOperatorRequestedRole',
    'Get-AvdOperatorSubject',
    'Get-AvdOperatorCredentialName',
    'Get-AvdOperatorPolicyBody',
    'Get-AvdOperatorStampName',
    'Assert-AvdOperatorCaller',
    'Assert-AvdOperatorAppClean',
    'Resolve-AvdOperatorGraphRole'
)
