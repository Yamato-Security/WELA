$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$engine=(Get-Process -Id $PID).Path
$script:checks=0
function Check-Cli {
    param([string[]]$Arguments,[bool]$Success,[string]$Match)
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{$output=(& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1 | Out-String);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    if(($Success -and $code -ne 0) -or (-not $Success -and $code -eq 0) -or $output -notmatch $Match){throw "CLI guard failed: $($Arguments -join ' '), exit $code : $output"}
    $script:checks++
}
Check-Cli @('smb-runtime','-Help') $true 'smb-runtime'
Check-Cli @('smb-runtime','-Profile','test','-Help') $false 'dedicated options'
Check-Cli @('help','-SmbRuntimeAction','Activate') $false 'SmbRuntime options require'
Check-Cli @('smb-runtime','-SmbAction','Configure','-Help') $false 'dedicated options'
Check-Cli @('smb-runtime','-DryRun') $false 'DryRun is supported only'
Check-Cli @('smb-runtime','-SmbRuntimeAction','Activate','-DryRun','-Help') $true 'smb-runtime'
Check-Cli @('smb-runtime','-BackupPath','unused','-Help') $false 'dedicated options'
Write-Host "PASS: $script:checks public SMB runtime CLI guards"
# Expected child failures are assertions, not the enclosing Actions step result.
$global:LASTEXITCODE=0
