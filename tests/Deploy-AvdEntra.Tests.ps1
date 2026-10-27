# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'avd-entra Control Plane (Phase 4 Offline Suite)' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:DeployScript = Join-Path $script:RepoRoot 'scripts/Deploy-AvdEntra.ps1'
        $script:RemoveScript = Join-Path $script:RepoRoot 'scripts/Remove-AvdEntra.ps1'
        $script:ModulePath = Join-Path $script:RepoRoot 'scripts/AvdEntra.psm1'
        Import-Module $script:ModulePath -Force
    }

    BeforeEach {
        Clear-EntraDryRunStore
        $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("avd-entra-test-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:TempDir -Force
        $script:ManifestFile = Join-Path $script:TempDir 'entra-manifest.json'
        $script:RunManifestFile = Join-Path $script:TempDir 'entra-run-manifest.json'
    }

    AfterEach {
        Clear-EntraDryRunStore
        if (Test-Path -LiteralPath $script:TempDir) {
            Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Creates stamped groups, dynamic host group, and report-only CA policy on first run and reuses them on second run' {
        $result1 = & $script:DeployScript `
            -Prefix 'avd' `
            -Environment 'dev' `
            -PoolNames @('pool1', 'pool2') `
            -StorageAccountFqdn 'stavddev01.file.core.windows.net' `
            -InitializeGraphApp `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        $result1.schema | Should -Be 'avd-ops-entra-manifest/v1'
        $result1.environment | Should -Be 'dev'
        $result1.prefix | Should -Be 'avd'
        $result1.entraKerberosReady | Should -BeTrue
        $result1.groups.avdUsersGroupId | Should -Not -BeNullOrEmpty
        $result1.groups.avdAdminsGroupId | Should -Not -BeNullOrEmpty
        $result1.groups.sessionHostsDynamicGroupId | Should -Not -BeNullOrEmpty
        $result1.groups.breakGlassExcludeGroupId | Should -Not -BeNullOrEmpty
        $result1.conditionalAccess.Count | Should -BeGreaterOrEqual 1
        $result1.conditionalAccess[0].state | Should -Be 'enabledForReportingButNotEnforced'
        $result1.conditionalAccess[0].displayName | Should -Match '^\[avd-ops-avd-dev\]'

        $run1 = Get-Content -LiteralPath $script:RunManifestFile -Raw | ConvertFrom-Json -Depth 10
        $run1.stamp | Should -Be '[avd-ops-avd-dev]'
        @($run1.objects | Where-Object { $_.created -eq $true }).Count | Should -Be $run1.objects.Count

        # Second run against the same in-memory Graph state must reuse all objects (created = false)
        $result2 = & $script:DeployScript `
            -Prefix 'avd' `
            -Environment 'dev' `
            -PoolNames @('pool1', 'pool2') `
            -StorageAccountFqdn 'stavddev01.file.core.windows.net' `
            -InitializeGraphApp `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        $result2.groups.avdUsersGroupId | Should -Be $result1.groups.avdUsersGroupId
        $result2.groups.sessionHostsDynamicGroupId | Should -Be $result1.groups.sessionHostsDynamicGroupId

        $run2 = Get-Content -LiteralPath $script:RunManifestFile -Raw | ConvertFrom-Json -Depth 10
        @($run2.objects | Where-Object { $_.created -eq $false }).Count | Should -Be $run2.objects.Count
    }

    It 'Blocks teardown of stateful resources (seeded lab users / populated groups) without -DiscardLastCopy' {
        $null = & $script:DeployScript `
            -Prefix 'avd' `
            -Environment 'test' `
            -SeedLabUsers `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        {
            & $script:RemoveScript -RunManifestPath $script:RunManifestFile -DryRun -Confirm:$false
        } | Should -Throw '*DiscardLastCopy*'

        $teardown = & $script:RemoveScript `
            -RunManifestPath $script:RunManifestFile `
            -DiscardLastCopy `
            -DryRun `
            -Confirm:$false

        $teardown.Deleted.Count | Should -BeGreaterOrEqual 5
    }

    It 'Never deletes pre-existing objects (created=false) or objects without matching stamp' {
        $null = & $script:DeployScript `
            -Prefix 'avd' `
            -Environment 'dev' `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        # Second run marks all objects as created=false
        $null = & $script:DeployScript `
            -Prefix 'avd' `
            -Environment 'dev' `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        $teardown = & $script:RemoveScript `
            -RunManifestPath $script:RunManifestFile `
            -DryRun `
            -Confirm:$false

        $teardown.Deleted.Count | Should -Be 0
        $teardown.Skipped.Count | Should -BeGreaterOrEqual 5
    }
}
