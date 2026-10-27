# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
  Safely tears down Entra ID objects created by a specific Deploy-AvdEntra.ps1 run manifest.
  Refuses to delete stateful resources (seeded lab users or populated groups) without -DiscardLastCopy,
  and never deletes pre-existing objects (created = false) or objects lacking the [avd-ops-<prefix>-<env>] stamp.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()][string]$RunManifestPath = './entra-run-manifest.json',
    [Parameter()][switch]$DiscardLastCopy,
    [Parameter()][switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name 'AvdEntra')) {
    Import-Module (Join-Path $PSScriptRoot 'AvdEntra.psm1')
}

$isDryRun = [bool]$DryRun -or ($env:AVD_OPS_DRY_RUN -eq '1')

if (-not (Test-Path -LiteralPath $RunManifestPath)) {
    throw "Run manifest not found at '$RunManifestPath'. Cannot safely tear down without a run manifest."
}

$runManifest = Get-Content -LiteralPath $RunManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
if ($runManifest.schema -ne 'avd-ops-entra-run-manifest/v1') {
    throw "Unsupported run manifest schema '$($runManifest.schema)'."
}

$stamp = [string]$runManifest.stamp
if ($stamp -notmatch '^\[avd-ops-[a-z0-9-]+-(dev|test|prod)\]$') {
    throw "Invalid stamp '$stamp' in run manifest."
}

$allObjects = @($runManifest.objects)
$candidates = [System.Collections.Generic.List[object]]::new()
$skipped = [System.Collections.Generic.List[object]]::new()

foreach ($obj in $allObjects) {
    $displayName = [string]$obj.displayName
    if ($obj.created -ne $true) {
        $skipped.Add([pscustomobject]@{
            id          = [string]$obj.id
            displayName = $displayName
            type        = [string]$obj.type
            reason      = 'pre-existing (created=false)'
        })
        continue
    }
    if (-not $displayName.StartsWith($stamp)) {
        $skipped.Add([pscustomobject]@{
            id          = [string]$obj.id
            displayName = $displayName
            type        = [string]$obj.type
            reason      = "displayName does not start with stamp '$stamp'"
        })
        continue
    }
    $candidates.Add($obj)
}

# Check for stateful resources before any deletion occurs
$statefulNames = [System.Collections.Generic.List[string]]::new()
foreach ($cand in $candidates) {
    $isStateful = ($cand.PSObject.Properties['stateful'] -and [bool]$cand.stateful) -or ($cand.type -eq 'user')
    if (-not $isStateful -and $cand.type -eq 'group') {
        $members = @(Invoke-EntraGraph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($cand.id)/members?`$select=id&`$top=1" -DryRun:$isDryRun)
        if ($members.Count -gt 0) {
            $isStateful = $true
        }
    }
    if ($isStateful) {
        $statefulNames.Add([string]$cand.displayName)
    }
}

if ($statefulNames.Count -gt 0 -and -not $DiscardLastCopy) {
    throw "Refusing to delete stateful Entra resources ($($statefulNames -join ', ')) without -DiscardLastCopy. Pass -DiscardLastCopy to confirm permanent deletion."
}

$deleted = [System.Collections.Generic.List[object]]::new()
$orderedCandidates = @($candidates | Sort-Object {
    switch ($_.type) {
        'conditionalAccessPolicy' { 1 }
        'user'                    { 2 }
        'application'             { 3 }
        'group'                   { 4 }
        default                   { 5 }
    }
})

foreach ($cand in $orderedCandidates) {
    $deleteUri = switch ($cand.type) {
        'conditionalAccessPolicy' { "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($cand.id)" }
        'user'                    { "https://graph.microsoft.com/v1.0/users/$($cand.id)" }
        'application'             { "https://graph.microsoft.com/v1.0/applications/$($cand.id)" }
        'group'                   { "https://graph.microsoft.com/v1.0/groups/$($cand.id)" }
        default                   { throw "Unsupported object type '$($cand.type)' in run manifest." }
    }
    if ($PSCmdlet.ShouldProcess($cand.displayName, "Delete $($cand.type) ($($cand.id))")) {
        $null = Invoke-EntraGraph -Method DELETE -Uri $deleteUri -DryRun:$isDryRun
        $deleted.Add([pscustomobject]@{
            id          = [string]$cand.id
            displayName = [string]$cand.displayName
            type        = [string]$cand.type
        })
    }
}

return [pscustomobject]@{
    Stamp   = $stamp
    Deleted = @($deleted)
    Skipped = @($skipped)
}
