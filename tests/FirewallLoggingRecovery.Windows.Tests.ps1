param([switch]$AllowDisposableLoggingWrite)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){Write-Host 'Skipped: native Windows required.';exit 0}
if(-not $AllowDisposableLoggingWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted logging-write opt-in is required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
foreach($file in @('Configuration','FirewallLogging','AuditRecovery','WefArrival','WecUpdate','ChannelRead','FirewallLoggingRecovery')){. (Join-Path $repo "scripts/$file.ps1")}
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-firewall-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $root
$logDirectory=Join-Path $root 'owned-logs';$null=New-Item -ItemType Directory -Path $logDirectory
$script:checks=0;$script:cliIndex=0;$before=$null;$cleanup=$false
function Assert-Native($Value,$Message){if(-not $Value){throw $Message};$script:checks++;Write-Host "PASS: $Message"}
function Save-Native($Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),(Get-WelaFirewallRecoveryKey $Value),[Text.UTF8Encoding]::new($false))}
function Invoke-FixtureCli([string[]]$Arguments,[int]$Expected=0){
    $script:cliIndex++;$old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{$output=& $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    $output | Out-File -LiteralPath (Join-Path $root ("cli-$script:cliIndex.txt")) -Encoding utf8
    if(-not (($Expected -eq 0 -and $code -eq 0) -or ($Expected -ne 0 -and $code -ne 0))){throw "Public $($Arguments[0]) exit $code (expected $Expected): $($output -join ' ')"}
    Assert-Native $true "Public $($Arguments[0]) exit $code (expected $Expected)"
}
try {
    $before=Get-WelaFirewallRecoveryState;Save-Native 'safety-before.json' $before
    # All test-only changes are the four logging fields and a new owned directory.
    # The product never changes destination ACLs, service state, enforcement or rules.
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$sid=$owner.User;$acl.SetOwner($sid)}finally{$owner.Dispose()}
    $service=([Security.Principal.NTAccount]::new('NT SERVICE\mpssvc')).Translate([Security.Principal.SecurityIdentifier])
    foreach($principal in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($service,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $logDirectory -AclObject $acl
    foreach($profile in @('Domain','Private','Public')){
        NetSecurity\Set-NetFirewallProfile -Name $profile -PolicyStore PersistentStore -LogAllowed False -LogBlocked False -LogMaxSizeKilobytes 4096 -LogFileName (Join-Path $logDirectory "$profile.log") -Confirm:$false -ErrorAction Stop
    }
    $prepared=Get-WelaFirewallRecoveryState;Save-Native 'prepared.json' $prepared
    $original=Join-Path $root 'original.json';$backup=Join-Path $root 'configure-backup'
    Invoke-FixtureCli @('firewall-logging','-FirewallAction','Configure','-Auto','-BackupPath',$backup,'-ResultsPath',$original)
    $originalReport=Get-Content -LiteralPath $original -Raw | ConvertFrom-Json
    Assert-Native (@($originalReport.Results | Where-Object Status -ceq 'Applied').Count -eq 3) 'Public Configure produced three actual completed Applied journals'
    $configured=Get-WelaFirewallRecoveryState;Save-Native 'configured.json' $configured
    $planDirectory=Join-Path $root 'plan'
    Invoke-FixtureCli @('firewall-recovery','-FirewallRecoveryProfile','Domain','-FirewallRecoveryJournalPath',(Join-Path $backup 'before.jsonl'),'-FirewallRecoveryResultsPath',$original,'-FirewallRecoveryOutputPath',$planDirectory)
    $planPath=Join-Path $planDirectory 'plan.json';$planHash=(Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $restoreArgs=@('firewall-recovery','-FirewallRecoveryAction','Restore','-FirewallRecoveryPlanPath',$planPath,'-FirewallRecoveryPlanHash',$planHash)
    Invoke-FixtureCli ($restoreArgs+@('-DryRun'))
    Assert-Native ((Get-WelaFirewallRecoveryKey (Get-WelaFirewallRecoveryState)) -ceq (Get-WelaFirewallRecoveryKey $configured)) 'Public dry run preserves complete native state'
    NetSecurity\Set-NetFirewallProfile -Name Domain -PolicyStore PersistentStore -LogMaxSizeKilobytes 24576 -Confirm:$false -ErrorAction Stop
    $drift=Get-WelaFirewallRecoveryState
    Invoke-FixtureCli ($restoreArgs+@('-DryRun')) 1
    Assert-Native ((Get-WelaFirewallRecoveryKey (Get-WelaFirewallRecoveryState)) -ceq (Get-WelaFirewallRecoveryKey $drift)) 'Changed confirmed After tuple is refused without mutation'
    NetSecurity\Set-NetFirewallProfile -Name Domain -PolicyStore PersistentStore -LogMaxSizeKilobytes 16384 -Confirm:$false -ErrorAction Stop
    $restoreDirectory=Join-Path $root 'restore'
    Invoke-FixtureCli ($restoreArgs+@('-Auto','-FirewallRecoveryOutputPath',$restoreDirectory))
    $result=Get-Content -LiteralPath (Join-Path $restoreDirectory 'result.json') -Raw | ConvertFrom-Json
    Assert-Native ($result.Status -ceq 'LocalLoggingRestored' -and $result.WriteAttempted -and $result.ReadyRuleCredit -eq 0) 'Public recovery confirms the actual local four-field tuple without Sigma credit'
    $recovered=Get-WelaFirewallRecoveryState;Save-Native 'recovered.json' $recovered
    Assert-Native ((Get-WelaFirewallRecoveryKey $recovered.Profiles.PersistentStore.Domain.Logging) -ceq (Get-WelaFirewallRecoveryKey $prepared.Profiles.PersistentStore.Domain.Logging)) 'Selected local logging tuple exactly matches its original before values'
    Assert-Native ((Get-WelaFirewallRecoveryInvariant $recovered Domain) -ceq (Get-WelaFirewallRecoveryInvariant $configured Domain)) 'Enforcement, other profiles and both-store rule/filter configurations remain unchanged'
    foreach($artifact in $result.Artifacts){Assert-Native ((Get-FileHash -LiteralPath (Join-Path $restoreDirectory $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $artifact.Sha256) "Verified retained receipt $($artifact.Name)"}
    $again=Join-Path $root 'again';Invoke-FixtureCli ($restoreArgs+@('-Auto','-FirewallRecoveryOutputPath',$again))
    $againResult=Get-Content -LiteralPath (Join-Path $again 'result.json') -Raw | ConvertFrom-Json
    Assert-Native ($againResult.Status -ceq 'AlreadyRestored' -and -not $againResult.WriteAttempted) 'Public repeated recovery is idempotent without a setter'
} finally {
    $errors=@()
    if($before){
        foreach($profile in @('Domain','Private','Public')){
            try{Set-WelaFirewallRecoveryLogging $profile $before.Profiles.PersistentStore.$profile.Logging}catch{$errors+="$profile cleanup: $($_.Exception.Message)"}
        }
        try{$final=Get-WelaFirewallRecoveryState;Save-Native 'safety-after.json' $final;if((Get-WelaFirewallRecoveryKey $final) -cne (Get-WelaFirewallRecoveryKey $before)){throw 'Complete final native firewall configuration differs from original safety snapshot.'}}catch{$errors+=$_.Exception.Message}
    }
    # Service handles may briefly retain the old owned path after restoring all profiles.
    if(-not $errors.Count){
        for($attempt=0;$attempt -lt 10;$attempt++){
            try{Remove-Item -LiteralPath $logDirectory -Recurse -Force -ErrorAction Stop;break}catch{if($attempt -eq 9){$errors+=$_.Exception.Message}else{Start-Sleep -Milliseconds 500}}
        }
    }
    $cleanup=-not $errors.Count
    Save-Native 'acceptance.json' ([pscustomobject]@{Build=$before.Context.Build;Engine=$PSVersionTable.PSVersion.ToString();Checks=$checks;CleanupVerified=$cleanup;CleanupErrors=$errors;Scope='Actual public Configure/Plan/Restore, drift refusal and idempotence; all original profile logging, enforcement and bounded native rule/filter configuration restored. No event/Sigma proof.'})
    if($errors.Count){throw "Fixture cleanup failed; evidence at $root : $($errors -join '; ')"}
}
$global:LASTEXITCODE=0
Write-Host "PASS: $checks native firewall recovery checks; exact safety cleanup. Evidence: $root"
