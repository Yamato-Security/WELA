param([switch]$AllowDisposableChannelWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableChannelWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/ControlApplicability.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/AuditRecovery.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/EventLogRecovery.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
$engine=(Get-Process -Id $PID).Path
function Invoke-RecoveryFixtureCli {param([string[]]$Arguments,[int]$Expected=0)
 $prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$lines=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 if(($Expected -eq 0 -and $code -ne 0) -or ($Expected -ne 0 -and $code -eq 0)){throw "Public CLI $code : $($lines -join ' ')"}
}
$log='ForwardedEvents';$before=Read-WelaEventRecoveryChannel $log;$policies=Get-WelaEffectiveAuditPolicy
$root=Join-Path $env:RUNNER_TEMP ('wela-event-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$primary=$null
try{
 $null=Invoke-WelaNative wevtutil.exe @('sl',$log,'/ms:33554432','/rt:true','/ab:false')
 $prepared=Read-WelaEventRecoveryChannel $log
 Assert ((Get-WelaRecoveryKey $prepared.Guard) -ceq (Get-WelaRecoveryKey $before.Guard)) 'Preparation preserves enable/path/ACL/provider fields'
 Invoke-RecoveryFixtureCli @('configure-eventlogs','-LogProfile','asd-collector-archive-2021-10','-ApplyLogMode','-Auto','-BackupPath',"$root/journal",'-ResultsPath',"$root/original.json")
 $original=Get-Content "$root/original.json" -Raw|ConvertFrom-Json
 Assert ($original.Results.Count -eq 1 -and $original.Results[0].Status -eq 'Applied') 'Genuine public Configure evidence'
 $configured=Read-WelaEventRecoveryChannel $log
 Assert ($configured.MaximumSizeInBytes -eq 2147483648 -and $configured.LogMode -eq 'AutoBackup') 'Native configured size/mode observed'
 Invoke-RecoveryFixtureCli @('eventlog-recovery','-EventRecoveryJournalPath',"$root/journal/before.jsonl",'-EventRecoveryOriginalResultsPath',"$root/original.json",'-EventRecoveryLog',$log,'-EventRecoveryOutputPath',"$root/plan")
 $plan=Get-Content "$root/plan/manifest.json" -Raw|ConvertFrom-Json
 Assert ($plan.Status -eq 'ReviewRequired' -and (Get-WelaRecoveryKey (Read-WelaEventRecoveryChannel $log)) -ceq (Get-WelaRecoveryKey $configured)) 'Public Plan makes no channel changes'
 $apply=@('eventlog-recovery','-EventRecoveryAction','Restore','-EventRecoveryPlanPath',"$root/plan/plan.json",'-EventRecoveryPlanHash',$plan.PlanHash)
 Invoke-RecoveryFixtureCli ($apply+@('-EventRecoveryOutputPath',"$root/unknown-option",'-EventRecoveryAllowShrink','-EventRecoveryAllowRetentionChange','-WhatIf')) 1
 Assert (-not (Test-Path "$root/unknown-option") -and (Get-WelaRecoveryKey (Read-WelaEventRecoveryChannel $log)) -ceq (Get-WelaRecoveryKey $configured)) 'Unknown WhatIf refuses before output or native restoration'
 Invoke-RecoveryFixtureCli ($apply+@('-EventRecoveryOutputPath',"$root/without-consent")) 1
 $refused=Get-Content "$root/without-consent/manifest.json" -Raw|ConvertFrom-Json
 Assert ($refused.Status -eq 'Refused' -and -not $refused.NativeWriteAttempted) 'Shrinking requires independent explicit consent'
 # Actual concurrent-size drift, then exact fixture restoration, exercises public refusal.
 $null=Invoke-WelaNative wevtutil.exe @('sl',$log,'/ms:2147549184')
 Invoke-RecoveryFixtureCli ($apply+@('-EventRecoveryOutputPath',"$root/drift",'-EventRecoveryAllowShrink','-EventRecoveryAllowRetentionChange')) 1
 $drift=Get-Content "$root/drift/manifest.json" -Raw|ConvertFrom-Json
 Assert ($drift.Status -eq 'Refused' -and -not $drift.NativeWriteAttempted) 'Actual native size drift refuses restoration'
 $null=Invoke-WelaNative wevtutil.exe @('sl',$log,'/ms:2147483648')
 Invoke-RecoveryFixtureCli ($apply+@('-EventRecoveryOutputPath',"$root/restored",'-EventRecoveryAllowShrink','-EventRecoveryAllowRetentionChange'))
 $restored=Get-Content "$root/restored/manifest.json" -Raw|ConvertFrom-Json
 Assert ($restored.Status -eq 'RestoredAndVerified' -and $restored.NativeWriteAttempted -and $restored.ReadyRuleCredit -eq 0) 'Native public restoration verified'
 Assert ((Get-WelaRecoveryKey (Read-WelaEventRecoveryChannel $log)) -ceq (Get-WelaRecoveryKey $prepared)) 'Exact prepared size/mode and all preserved fields restored'
 Invoke-RecoveryFixtureCli ($apply+@('-EventRecoveryOutputPath',"$root/replay",'-EventRecoveryAllowShrink','-EventRecoveryAllowRetentionChange')) 1
 $replay=Get-Content "$root/replay/manifest.json" -Raw|ConvertFrom-Json
 Assert ($replay.Status -eq 'Refused' -and -not $replay.NativeWriteAttempted) 'Consumed plan cannot overwrite recovered state'
 Write-Host "Native event-log recovery passed $count assertions; no record preservation or sustained retention claim."
}catch{$primary=$_}
finally{
 $errorText=''
 try{
  $arguments=@('sl',$log,('/ms:'+$before.MaximumSizeInBytes))
  switch($before.LogMode){'Circular'{$arguments+=@('/rt:false','/ab:false')};'Retain'{$arguments+=@('/rt:true','/ab:false')};'AutoBackup'{$arguments+=@('/rt:true','/ab:true')}}
  $null=Invoke-WelaNative wevtutil.exe $arguments
  if((Get-WelaRecoveryKey (Read-WelaEventRecoveryChannel $log)) -cne (Get-WelaRecoveryKey $before)){throw 'Original channel configuration differs after cleanup.'}
  $now=Get-WelaEffectiveAuditPolicy;foreach($guid in $policies.Keys){if($now[$guid] -ne $policies[$guid]){throw 'Original audit mask changed.'}}
 }catch{$errorText=$_.Exception.Message}
 $cleanup=[ordered]@{CleanupVerified=($errorText -eq '');Before=$before;After=(Read-WelaEventRecoveryChannel $log);AuditMasksCompared=$policies.Count;Diagnostic=$errorText}
 $cleanup|ConvertTo-Json -Depth 12|Set-Content "$root/cleanup.json" -Encoding UTF8
 if($errorText){throw "Cleanup failed: $errorText; primary: $primary"}
 Write-Host 'Original channel size/mode, enable/path/ACL/provider fields and all audit masks restored.'
}
if($primary){throw $primary}
$global:LASTEXITCODE=0
