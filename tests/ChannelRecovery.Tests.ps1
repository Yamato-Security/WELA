$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
Import-Module "$repo/modules/NativeChannelAccess.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/NativeChannelConfiguration.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/ChannelRecovery.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Copy-State($Value){ConvertFrom-WelaArrivalJson (Get-WelaChannelRecoveryKey $Value)}
function Get-WelaChannelRecoveryContext {[pscustomobject]@{Host=[ordered]@{Computer='TEST';MachineGuid='owned-host'};Reader='owned-logon'}}
function Get-WelaChannelReader {[pscustomobject]@{UserSid='TEST';TokenId='token';ModifiedId=$script:token}}
# Portable tests exercise authority, reconstruction and write ordering; real descriptor
# bytes are exercised separately by the native public Configure/Restore workflow.
function Get-WelaChannelRecoveryDescriptorKey {param($Sddl) if($Sddl -cnotin @('original','original+read','foreign')){throw 'Invalid fixture descriptor'};$Sddl}
function Get-WelaChannelAccessPlan {param($SecurityDescriptor) if($SecurityDescriptor -ceq 'original'){[pscustomobject]@{State='GrantRequired';ProposedDescriptor='original+read'}}else{[pscustomobject]@{State='GrantPresent'}}}
function Test-WelaChannelDescriptorEqual {param($First,$Second) $First -ceq $Second}
function Get-WelaNativeChannel {param($Name) [pscustomobject][ordered]@{Name=$Name;State=$(if($script:settings.IsEnabled){'Enabled'}else{'Disabled'});IsEnabled=$script:settings.IsEnabled;LogMode=$script:settings.LogMode;SecurityDescriptor=$script:settings.SecurityDescriptor;MaximumSizeInBytes=$script:settings.MaximumSizeInBytes;ProviderNames='Microsoft-Windows-CAPI2';MetadataErrors=[pscustomobject]@{};Error=$null}}
function Invoke-WelaNative {param($FilePath,$Arguments) foreach($arg in $Arguments){if($arg -like '/ms:*'){$script:settings.MaximumSizeInBytes=[long]$arg.Substring(4)};if($arg -like '/ca:*'){$script:settings.SecurityDescriptor=$arg.Substring(4)};if($arg -ceq '/e:true'){$script:settings.IsEnabled=$true}}}
function Read-WelaChannelRecoveryState {
 param($Channel)
 $script:reads++
 if($script:case -eq 'fresh-drift' -and $script:reads -eq 2){$script:settings.MaximumSizeInBytes+=65536}
 [pscustomobject]@{Channel=$Channel;Settings=(Copy-State $script:settings);Guard=[ordered]@{Path=$script:path;Provider='CAPI2';Other='preserved'}}
}
function Set-WelaChannelRecoveryField {
 param($Definition,$Field)
 $script:writes++
 Assert (Test-Path (Join-Path $script:output ('pending-'+$script:writes+'-'+$Field+'.json'))) 'Durable per-field pending receipt precedes each write.'
 if($script:case -eq 'native-fail' -and $script:writes -eq 2){throw 'Native second write failed'}
 if($script:case -ne 'false-success'){$script:settings.$Field=$Definition.RecoverTo.$Field}
 if($script:case -eq 'preservation'){$script:path='changed'}
 if($script:case -eq 'token'){$script:token='changed'}
 if($script:writes -eq 3 -and $script:case -eq 'last-history'){[IO.File]::AppendAllText($script:originalFile,' ')}
 if($script:writes -eq 3 -and $script:case -eq 'last-artifact'){[IO.File]::AppendAllText((Join-Path $script:output 'pending-3-IsEnabled.json'),' ')}
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-channel-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$oldComputer=$env:COMPUTERNAME;$env:COMPUTERNAME='TEST';$channel='Microsoft-Windows-CAPI2/Operational'
function Original([string]$Dir,[bool]$Grant=$true){
 $script:settings=[pscustomobject][ordered]@{IsEnabled=$false;MaximumSizeInBytes=1052672L;LogMode='Circular';SecurityDescriptor='original'};$script:case='';$script:token='stable';$script:path='preserved';$script:reads=0;$script:writes=0
 $profile=Get-WelaNativeChannelProfile;$plans=@(Get-WelaNativeChannelPlan -Profile $profile -GrantEventLogReaders:$Grant|Where-Object {$_.Definition.channel -ceq $channel})
 $context=New-WelaConfigurationContext -Auto -BackupPath "$Dir/journal"
 Set-WelaNativeChannelControls $context $plans $profile.id
 $r=Complete-WelaConfiguration $context -Scope 'native-channel-settings-only'
 $r|Add-Member NoteProperty Action Configure;$r|Add-Member NoteProperty ChannelProfile $profile.id;$r|Add-Member NoteProperty GrantEventLogReadersRequested $Grant
 $r|ConvertTo-Json -Depth 20|Set-Content "$Dir/original.json" -Encoding UTF8
 Assert ($r.Results.Count -eq 1 -and $r.Results[0].Status -ceq 'Applied') 'Actual shared configuration callbacks produce original journal/result evidence.'
}
try {
 foreach($scenario in @('ok','no-grant','no-shrink','no-disable','no-revoke','hash','tamper','duplicate','drift','fresh-drift','source','native-fail','false-success','preservation','token','last-history','last-artifact')){
  $dir=Join-Path $root $scenario;$null=New-Item -ItemType Directory $dir;Original $dir ($scenario -ne 'no-grant')
  $plan=Invoke-WelaChannelRecovery -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -Channel $channel -OutputPath "$dir/plan"
  Assert ($plan.Status -ceq 'ReviewRequired' -and $plan.ExitCode -eq 0) "Plan $scenario : $($plan.Diagnostic)"
  Assert ($script:writes -eq 0) 'Plan does not mutate.'
  $planPath="$dir/plan/plan.json";$hash=$plan.PlanHash
  if($scenario -eq 'hash'){$hash='f'*64}
  if($scenario -in @('tamper','duplicate')){$text=[IO.File]::ReadAllText($planPath);if($scenario -eq 'tamper'){$text=$text.Replace('1052672','2097152')}else{$text=$text.Replace('"SchemaVersion":','"SchemaVersion":1,"SchemaVersion":')};[IO.File]::WriteAllText($planPath,$text);$hash=(Get-FileHash $planPath).Hash.ToLowerInvariant()}
  if($scenario -eq 'source'){[IO.File]::AppendAllText("$dir/original.json",' ')}
  if($scenario -eq 'drift'){$script:settings.SecurityDescriptor='foreign'}
  $script:case=$scenario;$script:originalFile="$dir/original.json";$script:reads=0;$script:output="$dir/restore"
  $r=Invoke-WelaChannelRecovery Restore -PlanPath $planPath -PlanHash $hash -OutputPath $script:output -AllowShrink:($scenario -ne 'no-shrink') -AllowDisable:($scenario -ne 'no-disable') -AllowRevoke:($scenario -notin @('no-revoke','no-grant'))
  Assert (($r.ExitCode -eq 0) -eq ($scenario -in @('ok','no-grant'))) "Restore $scenario : $($r.Diagnostic)"
  Assert ($r.ReadyRuleCredit -eq 0 -and (Test-Path "$dir/restore/manifest.json")) 'Outcome evidence is retained without Sigma credit.'
  if($scenario -in @('ok','no-grant')){
   Assert ($script:settings.SecurityDescriptor -ceq 'original' -and -not $script:settings.IsEnabled -and $script:settings.MaximumSizeInBytes -eq 1052672 -and $r.Status -ceq 'RestoredAndVerified') 'Original changed fields restored.'
   Assert ($r.ConfirmedFields.Count -eq $(if($scenario -eq 'ok'){3}else{2})) 'Only originally changed fields are written and confirmed.'
   $again=Invoke-WelaChannelRecovery Restore -PlanPath $planPath -PlanHash $hash -OutputPath "$dir/replay" -AllowShrink -AllowDisable -AllowRevoke
   Assert ($again.Status -ceq 'Refused') 'Completed old plan cannot be replayed.'
  }elseif($scenario -in @('native-fail','false-success','preservation','token','last-history','last-artifact')){
   Assert ($r.Status -ceq 'RestoreAttemptedUnverified' -and $script:writes -gt 0) 'Possible partial write is explicit; no rollback is inferred.'
   if($scenario -eq 'native-fail'){Assert ($r.ConfirmedFields.Count -eq 1 -and $script:settings.MaximumSizeInBytes -eq 1052672 -and $script:settings.SecurityDescriptor -ceq 'original+read' -and $script:settings.IsEnabled) 'Second-write failure retains one confirmed step and stops before disable.'}
  }else{Assert ($r.Status -ceq 'Refused' -and $script:writes -eq 0) 'Unreviewed or drifted input refuses before write.'}
  foreach($artifact in $r.Artifacts){$matches=(Get-FileHash (Join-Path $r.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256;Assert ($matches -eq (-not ($scenario -eq 'last-artifact' -and $artifact.Name -ceq 'pending-3-IsEnabled.json'))) 'Retained hashes expose the deliberately changed artifact; all other bytes match.'}
 }
 $dir=Join-Path $root 'history';$null=New-Item -ItemType Directory $dir;Original $dir
 $savedResult=[IO.File]::ReadAllText("$dir/original.json");$savedJournal=[IO.File]::ReadAllText("$dir/journal/before.jsonl")
 $cases=@('Status','Kind','Id','Action','Scope','ChannelProfile','Channel','Profile','Version','ComputerName','State','IsEnabled','MaximumSizeInBytes','LogMode','SecurityDescriptor','AfterDrift','DesiredDrift','ExtraAce','NoGrantAuthority','DuplicateJournal')
 foreach($bad in $cases){
  $r=ConvertFrom-WelaArrivalJson $savedResult;$e=ConvertFrom-WelaArrivalJson $savedJournal
  switch($bad){
   {$_ -in @('Status','Kind','Id')} {$r.Results[0].$bad=$true}
   {$_ -in @('Action','Scope','ChannelProfile')} {$r.$bad=$true}
   {$_ -in @('Channel','Profile')} {$e.Target.$bad=$true;$r.Results[0].Target.$bad=$true}
   {$_ -in @('Version','ComputerName')} {$e.$bad=$true}
   {$_ -in @('State','IsEnabled','MaximumSizeInBytes','LogMode','SecurityDescriptor')} {$e.Before.$bad=if($bad -eq 'IsEnabled'){'false'}else{$true};$r.Results[0].Before=Copy-State $e.Before}
   'AfterDrift' {$r.Results[0].After.MaximumSizeInBytes+=65536}
   'DesiredDrift' {$e.Desired.MaximumSizeInBytes+=65536;$r.Results[0].Desired=Copy-State $e.Desired}
   'ExtraAce' {$e.Desired.SecurityDescriptor='foreign';$r.Results[0].Desired=Copy-State $e.Desired;$r.Results[0].After.SecurityDescriptor='foreign'}
   'NoGrantAuthority' {$r.GrantEventLogReadersRequested=$false}
  }
  $r|ConvertTo-Json -Depth 20|Set-Content "$dir/original.json" -Encoding UTF8
  $text=$e|ConvertTo-Json -Depth 20 -Compress;if($bad -eq 'DuplicateJournal'){$text+="`n"+$text};[IO.File]::WriteAllText("$dir/journal/before.jsonl",$text)
  $p=Invoke-WelaChannelRecovery -JournalPath "$dir/journal/before.jsonl" -OriginalResultsPath "$dir/original.json" -Channel $channel -OutputPath "$dir/reject-$bad"
  Assert ($p.Status -ceq 'Refused' -and -not $p.NativeWriteAttempted) "History $bad rejected before any write: $($p.Diagnostic)"
 }
}finally{$env:COMPUTERNAME=$oldComputer;Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count channel recovery authority/order/partial-outcome assertions. Native descriptors require the Windows fixture."
