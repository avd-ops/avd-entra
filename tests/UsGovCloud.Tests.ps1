# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'avd-entra Azure US Government & GCC High (usgov) Suite' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:DeployScript = Join-Path $script:RepoRoot 'scripts/Deploy-AvdEntra.ps1'
        $script:RemoveScript = Join-Path $script:RepoRoot 'scripts/Remove-AvdEntra.ps1'
        $script:ModulePath = Join-Path $script:RepoRoot 'scripts/AvdEntra.psm1'
        $script:ContractPath = Join-Path $script:RepoRoot 'contracts/cloud-environments.json'
        Import-Module $script:ModulePath -Force
    }

    BeforeEach {
        Clear-EntraDryRunStore
        $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("avd-entra-usgov-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:TempDir -Force
        $script:ManifestFile = Join-Path $script:TempDir 'entra-manifest.json'
        $script:RunManifestFile = Join-Path $script:TempDir 'entra-run-manifest.json'
    }

    AfterEach {
        Clear-EntraDryRunStore
        if (Test-Path -LiteralPath 'Function:\global:Get-AzContext') {
            Remove-Item -LiteralPath 'Function:\global:Get-AzContext' -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath 'Function:\global:Get-MgContext') {
            Remove-Item -LiteralPath 'Function:\global:Get-MgContext' -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath 'Function:\global:Connect-MgGraph') {
            Remove-Item -LiteralPath 'Function:\global:Connect-MgGraph' -Force -ErrorAction SilentlyContinue
        }
        Import-Module $script:ModulePath -Force
        if (Test-Path -LiteralPath $script:TempDir) {
            Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Declares [ValidateSet("commercial", "usgov")] $Cloud and [ValidateSet("standard", "itar-cui")] $ComplianceProfile on Deploy-AvdEntra.ps1 and Remove-AvdEntra.ps1' {
        foreach ($scriptPath in @($script:DeployScript, $script:RemoveScript)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $cloudParam = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Cloud' }
            $cloudParam | Should -Not -BeNullOrEmpty
            $cloudValidate = $cloudParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
            @($cloudValidate.PositionalArguments.Value) | Should -Be @('commercial', 'usgov')

            $profileParam = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ComplianceProfile' }
            $profileParam | Should -Not -BeNullOrEmpty
            $profileValidate = $profileParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
            @($profileValidate.PositionalArguments.Value) | Should -Be @('standard', 'itar-cui')
        }
    }

    It 'Static AST scan finds zero hardcoded commercial cloud hosts in scripts/*.ps1 and scripts/*.psm1' {
        $forbiddenPattern = '(management\.azure\.com|graph\.microsoft\.com|login\.microsoftonline\.com|api\.bap\.microsoft\.com|\.windows\.net)'
        $scriptsDir = Join-Path $script:RepoRoot 'scripts'
        $psFiles = @(Get-ChildItem -LiteralPath $scriptsDir -Include '*.ps1', '*.psm1' -Recurse)
        $psFiles.Count | Should -BeGreaterOrEqual 3

        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $psFiles) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $stringLiterals = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
            }, $true)
            foreach ($lit in $stringLiterals) {
                if ($lit.Value -match $forbiddenPattern) {
                    $violations.Add("$($file.Name):$($lit.Extent.StartLineNumber) -> $($lit.Value)")
                }
            }
        }
        $violations.Count | Should -Be 0
    }

    It 'Resolves commercial and usgov environments from C26 contracts/cloud-environments.json' {
        Test-Path -LiteralPath $script:ContractPath | Should -BeTrue
        $comm = Resolve-AvdCloudEnvironment -Cloud 'commercial'
        $usgov = Resolve-AvdCloudEnvironment -Cloud 'usgov'

        $comm.azCloudName | Should -Be 'AzureCloud'
        $comm.entraEnvironment | Should -Be 'Global'
        $comm.mgGraphEnvironment | Should -Be 'Global'
        $comm.graphEndpoint | Should -Be 'https://graph.microsoft.com'
        $comm.loginEndpoint | Should -Be 'https://login.microsoftonline.com'
        $comm.defaultComplianceProfile | Should -Be 'standard'

        $usgov.azCloudName | Should -Be 'AzureUSGovernment'
        $usgov.entraEnvironment | Should -Be 'USGov'
        $usgov.mgGraphEnvironment | Should -Be 'USGov'
        $usgov.graphEndpoint | Should -Be 'https://graph.microsoft.us'
        $usgov.loginEndpoint | Should -Be 'https://login.microsoftonline.us'
        $usgov.storageEndpointSuffix | Should -Be 'core.usgovcloudapi.net'
        $usgov.defaultComplianceProfile | Should -Be 'itar-cui'
    }

    It 'Connects to MgGraph with -Environment USGov for usgov and -Environment Global for commercial' {
        $script:CapturedMgEnvironment = $null
        function global:Connect-MgGraph {
            param([string]$Environment, [string[]]$Scopes, [switch]$NoWelcome)
            $script:CapturedMgEnvironment = $Environment
            return [pscustomobject]@{ Environment = $Environment; Scopes = $Scopes; NoWelcome = [bool]$NoWelcome }
        }

        $govConn = Connect-AvdEntraGraph -Cloud 'usgov'
        $script:CapturedMgEnvironment | Should -Be 'USGov'
        $govConn.MgGraphEnvironment | Should -Be 'USGov'
        $govConn.GraphEndpoint | Should -Be 'https://graph.microsoft.us'

        $commConn = Connect-AvdEntraGraph -Cloud 'commercial'
        $script:CapturedMgEnvironment | Should -Be 'Global'
        $commConn.MgGraphEnvironment | Should -Be 'Global'
        $commConn.GraphEndpoint | Should -Be 'https://graph.microsoft.com'
    }

    It 'Fails closed on cross-cloud context mismatch between Az, az CLI, MgGraph, and manifest cloud' {
        $ok = Assert-AvdCloudMatch `
            -Cloud 'usgov' `
            -AzContext ([pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'AzureUSGovernment' } }) `
            -MgContext ([pscustomobject]@{ Environment = 'USGov' }) `
            -AzCliCloudName 'AzureUSGovernment' `
            -ManifestCloud 'usgov'
        $ok.Verified | Should -BeTrue

        # Simulated mismatch: Az = AzureUSGovernment but MgGraph = Global
        {
            Assert-AvdCloudMatch `
                -Cloud 'usgov' `
                -AzContext ([pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'AzureUSGovernment' } }) `
                -MgContext ([pscustomobject]@{ Environment = 'Global' })
        } | Should -Throw '*Cloud boundary mismatch*'

        # Simulated mismatch: Az = AzureCloud when target is usgov
        {
            Assert-AvdCloudMatch `
                -Cloud 'usgov' `
                -AzContext ([pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'AzureCloud' } })
        } | Should -Throw '*Cloud boundary mismatch*'

        # Simulated mismatch: az CLI = AzureCloud when target is usgov
        {
            Assert-AvdCloudMatch `
                -Cloud 'usgov' `
                -AzCliCloudName 'AzureCloud'
        } | Should -Throw '*Cloud boundary mismatch*'

        # Simulated mismatch: ManifestCloud = commercial when target is usgov
        {
            Assert-AvdCloudMatch `
                -Cloud 'usgov' `
                -ManifestCloud 'commercial'
        } | Should -Throw '*Cloud boundary mismatch*'
    }

    It 'Aborts Deploy-AvdEntra.ps1 before any Graph call when Az (AzureUSGovernment) and MgGraph (Global) disagree' {
        function global:Get-AzContext {
            return [pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'AzureUSGovernment' } }
        }
        function global:Get-MgContext {
            return [pscustomobject]@{ Environment = 'Global' }
        }

        {
            & $script:DeployScript `
                -Cloud 'usgov' `
                -Prefix 'avd' `
                -Environment 'dev' `
                -OutputPath $script:ManifestFile `
                -RunManifestPath $script:RunManifestFile `
                -DryRun
        } | Should -Throw '*Cloud boundary mismatch*'

        Test-Path -LiteralPath $script:ManifestFile | Should -BeFalse
    }

    It 'Routes all Graph calls to https://graph.microsoft.us, applies itar-cui phishing-resistant MFA strength, and stamps cloud=usgov in manifests' {
        function global:Get-AzContext {
            return [pscustomobject]@{ Environment = [pscustomobject]@{ Name = 'AzureUSGovernment' } }
        }
        function global:Get-MgContext {
            return [pscustomobject]@{ Environment = 'USGov' }
        }

        $result = & $script:DeployScript `
            -Cloud 'usgov' `
            -Prefix 'avd' `
            -Environment 'prod' `
            -PoolNames @('pool1') `
            -StorageAccountFqdn 'stavdgov01.file.core.usgovcloudapi.net' `
            -InitializeGraphApp `
            -IncludeWin365 `
            -SeedLabUsers `
            -OutputPath $script:ManifestFile `
            -RunManifestPath $script:RunManifestFile `
            -DryRun

        $result.cloud | Should -Be 'usgov'
        $result.complianceProfile | Should -Be 'itar-cui'
        $result.entraKerberosReady | Should -BeTrue
        $result.conditionalAccess.Count | Should -BeGreaterOrEqual 1
        $result.conditionalAccess[0].complianceProfile | Should -Be 'itar-cui'
        $result.conditionalAccess[0].authenticationStrength | Should -Contain 'windowsHelloForBusiness'
        $result.conditionalAccess[0].authenticationStrength | Should -Contain 'fido2'
        $result.conditionalAccess[0].authenticationStrength | Should -Contain 'x509CertificateMultiFactor'

        $manifestJson = Get-Content -LiteralPath $script:ManifestFile -Raw | ConvertFrom-Json -Depth 10
        $manifestJson.cloud | Should -Be 'usgov'
        $manifestJson.complianceProfile | Should -Be 'itar-cui'

        $runJson = Get-Content -LiteralPath $script:RunManifestFile -Raw | ConvertFrom-Json -Depth 10
        $runJson.cloud | Should -Be 'usgov'
        $runJson.complianceProfile | Should -Be 'itar-cui'

        # Verify every outbound Graph URI targeted https://graph.microsoft.us and zero targeted .com or .windows.net
        $store = & (Get-Module AvdEntra) { $script:DryRunStore }
        $store.requests.Count | Should -BeGreaterThan 0
        foreach ($req in $store.requests) {
            $req.Uri | Should -Match '^https://graph\.microsoft\.us/v1\.0/'
            $req.Uri | Should -Not -Match 'graph\.microsoft\.com'
            $req.Uri | Should -Not -Match '\.windows\.net'
        }

        # Verify the Conditional Access policy POST payload in DryRunStore has phishing-resistant MFA combinations
        $caPol = @($store.policies.Values) | Select-Object -First 1
        $caPol | Should -Not -BeNullOrEmpty
        $caPol.grantControls.authenticationStrength.allowedCombinations | Should -Contain 'windowsHelloForBusiness'
        $caPol.grantControls.authenticationStrength.allowedCombinations | Should -Contain 'fido2'
        $caPol.grantControls.authenticationStrength.allowedCombinations | Should -Contain 'x509CertificateMultiFactor'
        $caPol.sessionControls.signInFrequency.value | Should -Be 4
        $caPol.sessionControls.persistentBrowser.mode | Should -Be 'never'

        # Verify cross-cloud teardown guard blocks commercial teardown against a usgov run manifest
        {
            & $script:RemoveScript `
                -Cloud 'commercial' `
                -RunManifestPath $script:RunManifestFile `
                -DiscardLastCopy `
                -DryRun `
                -Confirm:$false
        } | Should -Throw '*Cloud boundary mismatch*'

        # Verify usgov teardown routes DELETE calls to https://graph.microsoft.us
        $teardown = & $script:RemoveScript `
            -Cloud 'usgov' `
            -RunManifestPath $script:RunManifestFile `
            -DiscardLastCopy `
            -DryRun `
            -Confirm:$false
        $teardown.Cloud | Should -Be 'usgov'
        $teardown.Deleted.Count | Should -BeGreaterOrEqual 5
        foreach ($req in $store.requests) {
            $req.Uri | Should -Match '^https://graph\.microsoft\.us/v1\.0/'
        }
    }
}
