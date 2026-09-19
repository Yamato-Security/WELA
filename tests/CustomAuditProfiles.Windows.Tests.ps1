$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
$context=Get-WelaHostContext
$before=Get-WelaEffectiveAuditPolicy
$path=Join-Path ([IO.Path]::GetTempPath()) ('wela-custom-native-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    $exe=(Get-Process -Id $PID).Path
    & $exe -NoProfile -File (Join-Path $root 'WELA.ps1') audit-settings -Profile custom-example -ProfileFile (Join-Path $root 'config/custom-audit-profile.example.json') -SaclMode Skip -PlanPath $path
    $code=$LASTEXITCODE
    if ($code -ne 0) { throw "Native read-only custom audit failed: $code" }
    $report=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($report.role -ne $context.Role -or $report.build -ne $context.Build -or $report.policies.Count -ne 59 -or -not $report.CustomProfileSource.Sha256) { throw 'Custom file/context/provenance was not retained.' }
    $after=Get-WelaEffectiveAuditPolicy
    foreach ($guid in $before.Keys) { if ($after[$guid] -ne $before[$guid]) { throw "Audit policy changed during read-only smoke: $guid" } }
    Write-Host 'PASS: custom file public audit uses actual Windows context and 59 effective masks; all masks unchanged. No setting writes or event-generation claims.'
} finally { if (Test-Path -LiteralPath $path) {Remove-Item -LiteralPath $path -Force} }
$global:LASTEXITCODE=0
