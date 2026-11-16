# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    Import-Module (Join-Path $script:RepoRoot 'scripts/AvdEntra.psm1') -Force
    Import-Module (Join-Path $script:RepoRoot 'scripts/AvdOperatorApp.psm1') -Force
    $script:InitScript = Join-Path $script:RepoRoot 'scripts/Initialize-AvdOperatorApp.ps1'
    $script:RemoveScript = Join-Path $script:RepoRoot 'scripts/Remove-AvdOperatorApp.ps1'
    $script:PlanesJsonPath = Join-Path $script:RepoRoot 'contracts/operator-planes.json'
    $script:TestCfg = Get-AvdOperatorPlanesConfig -ConfigPath $script:PlanesJsonPath
    $global:PesterIntuneRoles = @(Get-AvdOperatorRequestedRoles -Config $script:TestCfg -Planes @('intune'))
}

AfterAll {
    Remove-Variable -Name PesterIntuneRoles -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Initialize-AvdOperatorApp & AvdOperatorApp Red-Team Guardrails' {
    It 'enforces deny list by value and ID across contracts/operator-planes.json and AST' {
        $cfg = Get-AvdOperatorPlanesConfig -ConfigPath $script:PlanesJsonPath
        $cfg.schema | Should -Be 'avd-ops-operator-planes/v1'

        $deniedIds = @($cfg.denyList.ids | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $deniedIds | Should -Contain '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'
        $deniedIds | Should -Contain '06b708a9-e830-4db3-a914-8e69da51d44f'
        $deniedIds | Should -Contain '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
        $deniedIds | Should -Contain '19dbc75e-c2e2-444c-a770-ec69d8559fc7'

        foreach ($p in @('entra', 'intune')) {
            $roles = Get-AvdOperatorRequestedRoles -Config $cfg -Planes @($p) -IncludeWin365
            $roles.Count | Should -BeGreaterThan 0
            foreach ($r in $roles) {
                (Test-AvdOperatorDeniedRole -Value $r.value -Id $r.id -DenyList $cfg.denyList) | Should -BeFalse
            }
        }

        # AST scan: denied GUIDs must not appear as string literals in operator scripts
        foreach ($file in @($script:InitScript, $script:RemoveScript, (Join-Path $script:RepoRoot 'scripts/AvdOperatorApp.psm1'))) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
            $literals = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value.ToLowerInvariant() })
            foreach ($did in $deniedIds) {
                ($literals -contains $did) | Should -BeFalse -Because "Denied GUID '$did' must not appear in $file"
            }
        }
    }

    It 'validates parameter constraints via AST (no GitHubBranch, Subject, ClaimsMatchingExpression, or Audience)' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:InitScript, [ref]$null, [ref]$null)
        $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $paramNames | Should -Not -Contain 'GitHubBranch'
        $paramNames | Should -Not -Contain 'Subject'
        $paramNames | Should -Not -Contain 'ClaimsMatchingExpression'
        $paramNames | Should -Not -Contain 'Audience'
        $paramNames | Should -Contain 'Planes'
        $paramNames | Should -Contain 'GitHubRepo'
        $paramNames | Should -Contain 'GitHubEnvironment'
    }

    It 'builds immutable GitHub environment subjects and rejects non-numeric IDs or wildcards' {
        $subj = Get-AvdOperatorSubject -Owner 'contoso' -OwnerId '12345' -Repo 'avd-ops' -RepoId '67890' -Environment 'sandbox'
        $subj | Should -Be 'repo:contoso@12345/avd-ops@67890:environment:sandbox'
        { Get-AvdOperatorSubject -Owner 'contoso' -OwnerId 'abc' -Repo 'avd-ops' -RepoId '67890' -Environment 'sandbox' } | Should -Throw
        { Get-AvdOperatorSubject -Owner 'contoso' -OwnerId '12345' -Repo 'avd-ops' -RepoId '67890' -Environment '*' } | Should -Throw
    }

    It 'refuses -Environment prod without -ConfirmProd and -Cloud usgov without -AllowUntestedUsGov' {
        { & $script:InitScript -Environment prod -Planes intune -GitHubRepo 'contoso/lab' -GitHubEnvironment 'prod' -DryRun } | Should -Throw '*ConfirmProd*'
        { & $script:InitScript -Cloud usgov -Planes entra -GitHubRepo 'contoso/lab' -GitHubEnvironment 'gov' -DryRun } | Should -Throw '*AllowUntestedUsGov*'
    }

    It 'refuses multi-plane request without -AllowUnionOfRights' {
        { & $script:InitScript -Planes @('entra', 'intune') -GitHubRepo 'contoso/lab' -GitHubEnvironment 'lab' -DryRun } | Should -Throw '*AllowUnionOfRights*'
    }

    It 'executes -DryRun and -WhatIf with zero non-GET calls and zero /addPassword calls' {
        $global:PesterMockCalls = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraGraph {
            $global:PesterMockCalls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            if ($Uri -like '*/v1.0/me[?]*') {
                return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = '11111111-1111-1111-1111-111111111111'; userPrincipalName = 'admin@example.com' }
            }
            if ($Uri -like '*/v1.0/me/memberOf*') {
                return @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.directoryRole'; roleTemplateId = '62e90394-69f5-4237-9190-012177145e10' })
            }
            if ($Uri -like '*/v1.0/servicePrincipals?*00000003-0000-0000-c000-000000000000*') {
                return @([pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; appRoles = $global:PesterIntuneRoles })
            }
            return @()
        }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("op-dryrun-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        try {
            $manifestPath = Join-Path $tmp 'op-manifest.json'
            $res = & $script:InitScript -Planes intune -GitHubRepo 'contoso/lab' -GitHubEnvironment 'lab' -GitHubOwnerId '111' -GitHubRepoId '222' -RunManifestPath $manifestPath -WhatIf
            $nonGet = @($global:PesterMockCalls | Where-Object { $_.Method -ne 'GET' })
            $nonGet.Count | Should -Be 0
            $addPwd = @($global:PesterMockCalls | Where-Object { $_.Uri -like '*/addPassword*' })
            $addPwd.Count | Should -Be 0
            $res.ficSubject | Should -Be 'repo:contoso@111/lab@222:environment:lab'
        } finally {
            Remove-Variable -Name PesterMockCalls -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects caller without Privileged Role Administrator or Global Administrator' {
        $me = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = '11111111-1111-1111-1111-111111111111'; userPrincipalName = 'user@example.com' }
        $roles = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.directoryRole'; roleTemplateId = '00000000-0000-0000-0000-000000000000' })
        { Assert-AvdOperatorCaller -CallerMe $me -CallerMemberOf $roles } | Should -Throw '*Privileged Role Administrator or Global Administrator*'
        { Assert-AvdOperatorCaller -CallerMe $null -CallerMemberOf @() } | Should -Throw '*Service principals cannot*'
    }

    It 'rejects app with multiple owners, existing credentials, or non-environment FIC subject' {
        $callerId = '11111111-1111-1111-1111-111111111111'
        $cleanApp = [pscustomobject]@{ appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; passwordCredentials = @(); keyCredentials = @() }
        $dirtyPwdApp = [pscustomobject]@{ appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; passwordCredentials = @(@{ keyId = '1' }); keyCredentials = @() }
        { Assert-AvdOperatorAppClean -App $dirtyPwdApp -Owners @([pscustomobject]@{ id = $callerId }) -CallerUserId $callerId } | Should -Throw '*existing passwordCredentials*'
        { Assert-AvdOperatorAppClean -App $cleanApp -Owners @([pscustomobject]@{ id = $callerId }, [pscustomobject]@{ id = '999' }) -CallerUserId $callerId } | Should -Throw '*exactly one owner*'
        { Assert-AvdOperatorAppClean -App $cleanApp -Owners @([pscustomobject]@{ id = $callerId }) -CallerUserId $callerId -FederatedCredentials @([pscustomobject]@{ subject = 'repo:org/repo:ref:refs/heads/main' }) } | Should -Throw '*non-immutable*'
    }

    It 'enforces appManagementPolicy before appRoleAssignments and deletes in exact order on teardown' {
        $global:PesterMockOps = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraGraph {
            $global:PesterMockOps.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            if ($Method -eq 'GET' -and $Uri -like '*/v1.0/me[?]*') {
                return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = '11111111-1111-1111-1111-111111111111'; userPrincipalName = 'admin@example.com' }
            }
            if ($Method -eq 'GET' -and $Uri -like '*/v1.0/me/memberOf*') {
                return @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.directoryRole'; roleTemplateId = '62e90394-69f5-4237-9190-012177145e10' })
            }
            if ($Method -eq 'GET' -and $Uri -like '*/v1.0/servicePrincipals?*00000003-0000-0000-c000-000000000000*') {
                return @([pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; appRoles = $global:PesterIntuneRoles })
            }
            if ($Method -eq 'POST' -and $Uri -like '*/v1.0/applications') {
                return [pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; appId = '44444444-4444-4444-4444-444444444444' }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/v1.0/servicePrincipals') {
                return [pscustomobject]@{ id = '55555555-5555-5555-5555-555555555555'; appId = '44444444-4444-4444-4444-444444444444' }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/beta/policies/appManagementPolicies') {
                return [pscustomobject]@{ id = '66666666-6666-6666-6666-666666666666' }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/federatedIdentityCredentials') {
                return [pscustomobject]@{ id = '77777777-7777-7777-7777-777777777777' }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/appRoleAssignments') {
                return [pscustomobject]@{ id = '88888888-8888-8888-8888-888888888888' }
            }
            if ($Method -eq 'GET' -and $Uri -like '*/v1.0/applications?`$filter=appId*') {
                return @([pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; appId = '44444444-4444-4444-4444-444444444444' })
            }
            return @()
        }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("op-live-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        try {
            $manifestPath = Join-Path $tmp 'op-manifest.json'
            $null = & $script:InitScript -Planes intune -GitHubRepo 'contoso/lab' -GitHubEnvironment 'lab' -GitHubOwnerId '111' -GitHubRepoId '222' -RunManifestPath $manifestPath -Confirm:$false

            $policyRefIdx = ($global:PesterMockOps | ForEach-Object { $_.Uri }).IndexOf('https://graph.microsoft.com/beta/applications/33333333-3333-3333-3333-333333333333/appManagementPolicies/$ref')
            $firstGrantIdx = ($global:PesterMockOps | ForEach-Object { $_.Uri }).IndexOf('https://graph.microsoft.com/v1.0/servicePrincipals/55555555-5555-5555-5555-555555555555/appRoleAssignments')
            $policyRefIdx | Should -BeGreaterThan -1
            $firstGrantIdx | Should -BeGreaterThan $policyRefIdx

            $global:PesterMockOps.Clear()
            & $script:RemoveScript -RunManifestPath $manifestPath -DiscardLastCopy -Confirm:$false
            $deletes = @($global:PesterMockOps | Where-Object { $_.Method -eq 'DELETE' } | ForEach-Object { $_.Uri })
            $deletes.Count | Should -Be 7
            $deletes[0] | Should -BeLike '*/appRoleAssignments/*'
            $deletes[1] | Should -BeLike '*/appRoleAssignments/*'
            $deletes[2] | Should -BeLike '*/appRoleAssignments/*'
            $deletes[3] | Should -BeLike '*/federatedIdentityCredentials/*'
            $deletes[4] | Should -BeLike '*/servicePrincipals/*'
            $deletes[5] | Should -BeLike '*/applications/*'
            $deletes[6] | Should -BeLike '*/directory/deletedItems/*'
        } finally {
            Remove-Variable -Name PesterMockOps -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
