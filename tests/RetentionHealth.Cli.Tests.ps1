$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$shell=(Get-Process -Id $PID).Path
$script:checks=0
function Assert-Cli([string[]]$Arguments,[int]$Expected,[string]$Text) {
    $ErrorActionPreference='Continue'
    $out=(& $shell -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1 | Out-String)
    $code=$LASTEXITCODE
    $ErrorActionPreference='Stop'
    if ($code -ne $Expected -or $out -notmatch [regex]::Escape($Text)) { throw "CLI check failed: $($Arguments -join ' ')`n$out" }
    $script:checks++
}
Assert-Cli @('retention-health','-Help') 0 'Read-only local native'
Assert-Cli @('configure','-RetentionConfigPath','operator.json') 1 'Retention options require'
Assert-Cli @('version','-RetentionPreviousPath','previous.json') 1 'Retention options require'
foreach ($option in @('DryRun','Auto')) { Assert-Cli @('retention-health',('-'+$option)) 1 'retention-health is read-only' }
Assert-Cli @('retention-health','-Profile','wela') 1 'retention-health is read-only'
Assert-Cli @('retention-health','-BackupPath','new-backup') 1 'retention-health is read-only'
Assert-Cli @('retention-health','-WefAction','Configure') 1 'require wef-source'
Assert-Cli @('retention-health','-RetentionConfigPath','missing-retention-fixture.json') 1 '[Failed] Retention health'
Write-Host "RetentionHealth.Cli.Tests: $script:checks public CLI checks passed."
$global:LASTEXITCODE=0
