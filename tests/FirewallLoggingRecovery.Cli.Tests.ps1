$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$engine=(Get-Process -Id $PID).Path;$n=0
function Check([string[]]$Arguments,[string]$Pattern,[int]$Expected=1){
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{$output=& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    if(($Expected -eq 0 -and $code -ne 0) -or ($Expected -ne 0 -and $code -eq 0) -or ($output -join ' ') -notmatch $Pattern){throw "Unexpected CLI $($Arguments -join ' '): $code $output"};$script:n++
}
Check @('firewall-recovery','-Help') 'FirewallRecoveryPlanHash' 0
Check @('configure','-FirewallRecoveryProfile','Domain') 'require firewall-recovery'
Check @('firewall-recovery','-FirewallAction','Configure') 'dedicated'
Check @('firewall-recovery','-RecoveryAction','Restore') 'dedicated|require audit-recovery'
Check @('firewall-recovery','-FirewallRecoveryProfile','All') 'ValidateSet|does not belong'
Check @('firewall-recovery','-FirewallRecoveryAction','Plan','-Auto') 'requires one profile'
Check @('firewall-recovery','-FirewallRecoveryAction','Restore','-DryRun') 'reviewed plan/hash'
Check @('firewall-recovery','-FirewallRecoveryAction','Restore','-FirewallRecoveryPlanPath','missing','-FirewallRecoveryPlanHash',('a'*64),'-DryRun','-FirewallRecoveryOutputPath','must-not-exist') 'reviewed plan/hash'
$global:LASTEXITCODE=0
Write-Host "Firewall recovery public CLI: $n checks passed."
