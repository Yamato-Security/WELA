$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/AuditRecovery.ps1"
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/EventLogConfiguration.ps1"
. "$repo/scripts/EventLogRecovery.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-event-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$oldComputer=$env:COMPUTERNAME;$env:COMPUTERNAME='TEST'
function Get-WelaEventRecoveryContext {[pscustomobject][ordered]@{Host=[ordered]@{Computer='TEST';MachineGuid='1'};Reader='S-1-5-21-fixture'}}
function Get-WelaEventLogState {param($Log);[pscustomobject]@{Log=$Log;ReadStatus='Available';MaximumSizeInBytes=$script:bytes;LogMode=$script:mode;FileSize=123;IsEnabled=$false;Diagnostic=''}}
function Invoke-WelaNative {param($FilePath,$Arguments);foreach($arg in $Arguments){if($arg -like '/ms:*'){$script:bytes=[long]$arg.Substring(4)}};if($Arguments -contains '/ab:true'){$script:mode='AutoBackup'}}
function Read-WelaEventRecoveryChannel {param($Log);$script:reads++;if($script:scenario -eq 'fresh-drift' -and $script:reads -eq 2){$script:bytes+=65536};[pscustomobject]@{Log=$Log;MaximumSizeInBytes=$script:bytes;LogMode=$script:mode;Guard=[ordered]@{IsEnabled=$false;Path='Original';SecurityDescriptor=$script:acl}}}
function Set-WelaEventRecoveryChannel {param($Definition);Assert (Test-Path $script:pending) 'Pending receipt precedes write';$script:writes++;if($script:scenario -eq 'native-fail'){throw 'native failure'};if($script:scenario -ne 'false-success'){$script:bytes=$Definition.RecoverTo.MaximumSizeInBytes;$script:mode=$Definition.RecoverTo.LogMode};if($script:scenario -eq 'preservation'){$script:acl='changed'}}
try {
 foreach($case in @('ok','no-shrink','no-mode','hash','tamper','duplicate','drift','fresh-drift','source','native-fail','false-success','preservation','historical-drift')){
  $script:scenario='';$script:bytes=33554432L;$script:mode='Retain';$script:acl='Original';$script:writes=0;$script:reads=0
  $dir=Join-Path $root $case;$null=New-Item -ItemType Directory $dir
  $context=New-WelaConfigurationContext -Auto -BackupPath "$dir/journal"
  Set-WelaEventLogProfileControls -Context $context -Profile 'asd-collector-archive-2021-10' -ApplyLogMode
  $result=Complete-WelaConfiguration -Context $context -Scope 'event-log-size-and-mode-only' -ResultsPath "$dir/original.json"
  Assert ($result.ExitCode -eq 0 -and $result.Results[0].Status -eq 'Applied') 'Genuine configuration callback creates completed evidence'
  $plan=Invoke-WelaEventLogRecovery Plan -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -Log ForwardedEvents -OutputPath "$dir/plan"
  Assert ($plan.Status -eq 'ReviewRequired' -and $plan.ExitCode -eq 0) "Plan $case : $($plan.Diagnostic)"
  Assert ($script:writes -eq 0) 'Plan never restores'
  $planPath="$dir/plan/plan.json";$hash=$plan.PlanHash
  if($case -eq 'hash'){$hash='a'*64}
  if($case -in @('tamper','duplicate')){
   $text=[IO.File]::ReadAllText($planPath)
   if($case -eq 'tamper'){$text=$text.Replace('33554432','67108864')}else{$text=$text.Replace('"SchemaVersion":','"SchemaVersion":1,"SchemaVersion":')}
   [IO.File]::WriteAllText($planPath,$text);$hash=(Get-FileHash $planPath).Hash.ToLowerInvariant()
  }
  if($case -eq 'source'){[IO.File]::AppendAllText("$dir/original.json",' ')}
  if($case -eq 'historical-drift'){
   $original=Get-Content "$dir/original.json" -Raw|ConvertFrom-Json;$original.Results[0].After.MaximumSizeInBytes+=65536;$original|ConvertTo-Json -Depth 15|Set-Content "$dir/original.json"
   $bad=Invoke-WelaEventLogRecovery Plan -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -Log ForwardedEvents -OutputPath "$dir/bad-plan"
   Assert ($bad.Status -eq 'Refused' -and $bad.Diagnostic -match 'unexplained drift') 'Independent postwrite buffer growth cannot be undone as WELA-owned change'
  }
  $script:scenario=$case;$script:reads=0;$script:pending="$dir/restore/before-restore.json"
  if($case -eq 'drift'){$script:bytes+=65536}
  $restore=Invoke-WelaEventLogRecovery Restore -PlanPath $planPath -PlanHash $hash -OutputPath "$dir/restore" -AllowShrink:($case -ne 'no-shrink') -AllowRetentionChange:($case -ne 'no-mode')
  Assert (($restore.ExitCode -eq 0) -eq ($case -eq 'ok')) "Restore $case : $($restore.Diagnostic)"
  Assert (Test-Path "$dir/restore/manifest.json") 'Manifest retained'
  if($case -eq 'ok'){
   Assert ($script:bytes -eq 33554432 -and $script:mode -eq 'Retain' -and $restore.Status -eq 'RestoredAndVerified' -and $restore.ReadyRuleCredit -eq 0) 'Original immediate-prewrite size/mode restored'
   $replay=Invoke-WelaEventLogRecovery Restore -PlanPath $planPath -PlanHash $hash -OutputPath "$dir/replay" -AllowShrink -AllowRetentionChange
   Assert ($replay.Status -eq 'Refused' -and $script:writes -eq 1) 'Old post-configuration plan is not replayed'
  }elseif($case -in @('native-fail','false-success','preservation')){Assert ($restore.Status -eq 'RestoreAttemptedUnverified' -and $script:writes -eq 1) 'Partial failure explicit'}
  else{Assert ($script:writes -eq 0 -and -not $restore.NativeWriteAttempted) 'Refusal occurs before write'}
 }
 # Reject PowerShell boolean-to-string comparison coercion in completed evidence.
 $goodResult=[IO.File]::ReadAllText("$root/ok/original.json");$goodJournal=[IO.File]::ReadAllText("$root/ok/journal/before.jsonl")
 foreach($field in @('Status','Kind','Id','Scope','ComputerName','Phase','StateLog','ReadStatus','TargetLog','DesiredMode')){
  $r=ConvertFrom-WelaArrivalJson $goodResult;$j=@($goodJournal -split '\r?\n'|Where-Object {$_ -match '\S'}|ForEach-Object {ConvertFrom-WelaArrivalJson $_})
  switch($field){
   Status {$r.Results[0].Status=$true}
   Kind {$r.Results[0].Kind=$true}
   Id {$r.Results[0].Id=$true}
   Scope {$r.Scope=$true}
   ComputerName {$j[0].ComputerName=$true}
   Phase {$j[1].Phase=$true}
   StateLog {$r.Results[0].After.Log=$true}
   ReadStatus {$r.Results[0].After.ReadStatus=$true}
   TargetLog {$j[0].Target.Log=$true;$r.Results[0].Target.Log=$true}
   DesiredMode {$j[0].Desired.SizeMode=$true;$r.Results[0].Desired.SizeMode=$true}
  }
  $r|ConvertTo-Json -Depth 20|Set-Content "$root/typed-result.json"
  @($j|ForEach-Object {$_|ConvertTo-Json -Depth 20 -Compress})|Set-Content "$root/typed-journal.jsonl"
  Reject {Get-WelaEventRecoveryDefinition "$root/typed-journal.jsonl" "$root/typed-result.json" ForwardedEvents} 'mistyped recovery text|Exactly one result'
 }
}finally{$env:COMPUTERNAME=$oldComputer;Remove-Item $root -Recurse -Force}
Write-Host "Event-log recovery passed: $count assertions."
