# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()][string]$Prefix = 'avd',
    [Parameter()][ValidateSet('dev', 'test', 'prod')][string]$Environment = 'dev',
    [Parameter()][string]$OutputPath = './entra-manifest.json'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ShouldProcess("Entra ID ($Prefix-$Environment)", 'Deploy AVD groups and report-only Conditional Access')) {
    & bash ./scripts/deploy-entra.sh $Prefix $Environment $OutputPath
}
