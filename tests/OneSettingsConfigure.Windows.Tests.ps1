# Only this opted-in disposable fixture may prepare/restore the selected policy and channel.
param([switch]$AllowDisposableOneSettingsWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess -or -not $AllowDisposableOneSettingsWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable native64 GitHub-hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
foreach($module in @('AuditProfiles','EventLogSettings','NativeProviders','NativeChannelAccess')){Import-Module "$repo/modules/$module.psm1" -Force}
foreach($scriptName in @('Configuration','NativeChannelConfiguration','AuditNotifications','WefArrival')){. "$repo/scripts/$scriptName.ps1"}
$count=0;$errors=@();$primary=$null;$policyTouched=$false;$channelTouched=$false
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 32|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 32 -Compress}
function Masks($Value){@($Value.Keys|Sort-Object|ForEach-Object{"$_=$($Value[$_])"}) -join ';'}
$path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';$valueName='EnableOneSettingsAuditing';$channelName='Microsoft-Windows-Privacy-Auditing/Operational'
function Policy {Get-WelaRegistryState $path $valueName}
function Read-Raw([string]$Name){$native=Invoke-WelaNative wevtutil.exe @('gl',$Name,'/f:xml');$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.LoadXml(($native.Output -join "`n"));$doc.OuterXml}
function Services {@(Get-Service Winmgmt,EventLog,DiagTrack -ErrorAction Stop|Sort-Object Name|ForEach-Object{[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status;StartType=[string]$_.StartType}})}
function Read-PolicyKey($Key,[int]$Depth=0){
 if($Depth -gt 8 -or ++$script:registryCount -gt 256){throw 'DataCollection fixture inventory exceeds depth/key bounds.'}
 $values=@(foreach($n in @($Key.GetValueNames()|Sort-Object)){
  if($Depth -eq 0 -and $n -ieq $valueName){continue}
  [pscustomobject][ordered]@{Name=$n;Type=[string]$Key.GetValueKind($n);Value=$Key.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
 })
 $acl=if($PSVersionTable.PSVersion.Major -ge 6){[Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($Key)}else{$Key.GetAccessControl()}
 $children=@(foreach($n in @($Key.GetSubKeyNames()|Sort-Object)){$child=$Key.OpenSubKey($n);try{if(-not $child){throw 'DataCollection child disappeared.'};[pscustomobject]@{Name=$n;State=Read-PolicyKey $child ($Depth+1)}}finally{if($child){$child.Dispose()}}})
 [pscustomobject][ordered]@{Values=$values;OwnerGroupDacl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access);Children=$children}
}
function Unselected {
 $baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$key=$null
 try{$key=$baseKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\DataCollection');$script:registryCount=0;$tree=if($key){Read-PolicyKey $key}else{$null}}finally{if($key){$key.Dispose()};$baseKey.Dispose()}
 $state=[pscustomobject][ordered]@{OtherDataCollection=$tree;SecurityChannel=Read-Raw 'Security';SystemChannel=Read-Raw 'System';ApplicationChannel=Read-Raw 'Application';Capi2Channel=Read-Raw 'Microsoft-Windows-CAPI2/Operational';SecurityWarning=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' WarningLevel;CrashOnAuditFail=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' CrashOnAuditFail;Services=Services}
 if((Key $state).Length -gt 4194304){throw 'Unselected fixture inventory exceeds four MiB characters.'};$state
}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;
public static class WelaOneSettingsFixturePipe {
 public static async Task<string> Read(TextReader reader) {
  var text=new StringBuilder();var buffer=new char[2048];while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();if(n>1048576-text.Length)throw new InvalidDataException("Public fixture output exceeded one Mi characters.");text.Append(buffer,0,n);}
 }
}
'@
$engine=(Get-Process -Id $PID).Path
foreach($service in @('Winmgmt','EventLog')){if((Get-Service $service).Status -ne 'Running'){throw 'Fixture observation dependencies must already be running.'}}
$hostState=Get-WelaNotificationHost
if($hostState.Status -cne 'Supported' -or $hostState.ProductType -ne 3 -or $hostState.DomainRole -ne 2 -or $hostState.Build -notin @(20348,26100)){throw 'Only disposable standalone Server2022/2025 is supported.'}
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-onesettings-native-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
function Public([string]$Label,[string[]]$Arguments,[int]$Expected=0,[switch]$NoReport){
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',"$repo/WELA.ps1",'audit-notifications')+$Arguments
 if(-not $NoReport){$all+=@('-ResultsPath',"$root/$Label.json")}
 foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Ambiguous fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object{'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try{
  if(-not $process.Start()){throw 'Owned public child did not start.'};$started=$true
  $stdout=[WelaOneSettingsFixturePipe]::Read($process.StandardOutput);$stderr=[WelaOneSettingsFixturePipe]::Read($process.StandardError)
  if(-not $process.WaitForExit(180000)){throw "Public $Label exceeded three minutes."}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public output drain exceeded five seconds.'}
  $text=$stdout.Result+"`n"+$stderr.Result;[IO.File]::WriteAllText((Join-Path $root ($Label+'.txt')),$text)
  Assert ($process.ExitCode -eq $Expected) "Public $Label exit $($process.ExitCode), expected $Expected : $text"
  if(-not $NoReport){$report=Get-Content -LiteralPath "$root/$Label.json" -Raw|ConvertFrom-Json;Assert ($report.ExitCode -eq $Expected -and $report.Scope -ceq 'audit-notifications' -and $report.EventGeneration -match 'Not verified') 'Actual public result agrees with process exit and keeps event generation unverified.';return $report}
 }finally{
  if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.Exception.Message}};if(-not $exited){$script:errors+='Owned process termination is unconfirmed.'}}
  try{$process.Dispose()}catch{$script:errors+=$_.Exception.Message}
 }
}
$before=Policy;$channelBefore=Get-WelaNativeChannel $channelName;$rawBefore=if(Test-WelaNativeChannelSnapshot $channelBefore){Read-Raw $channelName}else{$null};$unselected=Unselected;$masks=Get-WelaEffectiveAuditPolicy
Assert ($masks.Count -eq 59) 'Original59 native audit masks are observed.'
Save 'original.json' ([ordered]@{Policy=$before;Channel=$channelBefore;ChannelXml=$rawBefore;Unselected=$unselected;Masks=$masks;Host=$hostState;Engine=$PSVersionTable.PSVersion.ToString()})
$base=@('-NotificationControl','OneSettings')
function Preserve($PolicyState,$ChannelXml){Assert ((Key (Policy)) -ceq (Key $PolicyState)) 'Selected typed policy preserved.';if($ChannelXml){Assert ((Read-Raw $channelName) -ceq $ChannelXml) 'Selected channel complete XML preserved.'};Assert ((Key (Unselected)) -ceq (Key $unselected)) 'Other typed policy values, descendants, owner/group/DACL, channels, warning/fail policy and services preserved.';Assert ((Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $masks)) 'All59 effective native audit masks preserved.'}
try{
 if($hostState.Build -eq 26100){
  $plan=Public 'unsupported-plan' ($base+@('-NotificationAction','Plan')) 1
  Assert ($plan.Plan.Count -eq 1 -and $plan.Plan[0].Status -ceq 'Unknown' -and $plan.Plan[0].Before.Diagnostic -match 'lacks reviewed source support') 'Server2025 uses the explicit reviewed-source refusal.'
  foreach($dry in @($false,$true)){$label=if($dry){'unsupported-dry'}else{'unsupported-configure'};$options=$base+@('-NotificationAction','Configure','-Auto','-BackupPath',"$root/$label-backup");if($dry){$options+='-DryRun'};$report=Public $label $options 1;Assert ($report.Results.Count -eq 1 -and $report.Results[0].Status -ceq 'Failed' -and -not(Test-Path "$root/$label-backup/before.jsonl")) 'Unsupported native Configure/DryRun writes no selected policy or journal.';Preserve $before $rawBefore}
  Public 'unsupported-dependent' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/unsupported-dependent-backup")) 1 -NoReport
  Assert (-not(Test-Path "$root/unsupported-dependent-backup")) 'Unsupported dependent-channel request refuses before output journal.'
  Preserve $before $rawBefore
 }else{
  $definition=@(Get-WelaNotificationDefinitions|Where-Object Id -CEQ OneSettings)[0];$initial=Get-WelaNotificationSnapshot $definition
  Assert ($initial.Status -ceq 'Supported' -and $before.KeyExists -and $rawBefore) 'Real2022 ADMX, existing key and channel prerequisites are required.'
  Save 'definition.json' $initial.DefinitionEvidence
  $policyTouched=$true;if((Policy).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $valueName}
  $channelTouched=$true;$null=Invoke-WelaNative wevtutil.exe @('sl',$channelName,'/e:false','/ms:1048576')
  $seed=Policy;$seedChannel=Get-WelaNativeChannel $channelName;$seedXml=Read-Raw $channelName
  Save 'prepared.json' @{Policy=$seed;Channel=$seedChannel;ChannelXml=$seedXml}
  Assert ($seedChannel.MaximumSizeInBytes -ge 1048576) 'Native prepared buffer remains above the technical minimum; use actual rounded readback.'
  $plan=Public 'plan' ($base+@('-NotificationAction','Plan','-EnablePrivacyChannel'))
  Assert ($plan.Plan.Count -eq 1 -and $plan.Plan[0].Status -ceq 'ChangeRequired' -and -not $plan.Plan[0].Before.Policy.ValueExists -and $plan.PrivacyChannelPlan.Count -eq 1) 'Public Plan observes actual absence and the explicit channel dependency.'
  $dry=Public 'dry' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-DryRun','-BackupPath',"$root/dry-backup"))
  Assert ($dry.DryRun -and $dry.Results.Count -eq 2 -and @($dry.Results|Where-Object Status -CNE Skipped).Count -eq 0 -and -not(Test-Path "$root/dry-backup")) 'DryRun previews both selected operations without a journal.'
  Public 'whatif' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/whatif-backup",'-WhatIf')) 1 -NoReport
  Assert (-not(Test-Path "$root/whatif-backup")) 'Unrecognized preview refuses before any command dispatch.'
  Preserve $seed $seedXml
  $plain=Public 'policy' ($base+@('-NotificationAction','Configure','-Auto','-BackupPath',"$root/policy-backup"))
  $policyAfter=Policy
  Assert ($plain.Results.Count -eq 1 -and $plain.Results[0].Status -ceq 'Applied' -and $policyAfter.Type -ceq 'DWord' -and $policyAfter.Value -eq 1 -and (Key $plain.Results[0].Before.Policy) -ceq (Key $seed) -and (Key $plain.Results[0].After.Policy) -ceq (Key $policyAfter)) 'Plain public Configure writes only the exact OneSettingsDWORD1 and binds native before/after.'
  Assert ($plain.PrivacyChannelPlan.Count -eq 0 -and (Read-Raw $channelName) -ceq $seedXml) 'Policy-only Configure leaves the disabled channel unchanged.'
  $journal=@(Get-Content "$root/policy-backup/before.jsonl"|ConvertFrom-Json);Assert ($journal.Count -eq 1 -and $journal[0].Target.Path -ceq $path -and $journal[0].Target.Name -ceq $valueName -and (Key $journal[0].Before.Policy) -ceq (Key $seed)) 'Original missing value is preserved exactly in the durable journal.'
  $dependent=Public 'dependent' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/dependent-backup"))
  $enabled=Get-WelaNativeChannel $channelName;$enabledXml=Read-Raw $channelName
  Save 'enabled.json' @{Policy=Policy;Channel=$enabled;ChannelXml=$enabledXml}
  Assert ($dependent.Results.Count -eq 2 -and $dependent.Results[0].Status -ceq 'AlreadyCompliant' -and $dependent.Results[1].Status -ceq 'Applied') 'Verified producer policy precedes one actual dependent channel change.'
  $expected=[xml]$seedXml;$expected.DocumentElement.SetAttribute('enabled','true')
  Assert ($enabled.IsEnabled -and $enabled.MaximumSizeInBytes -eq $seedChannel.MaximumSizeInBytes -and $enabledXml -ceq $expected.OuterXml) 'Only channel Enabled changes; existing larger buffer, retention, full descriptor and metadata survive.'
  $journal=@(Get-Content "$root/dependent-backup/before.jsonl"|ConvertFrom-Json);Assert ($journal.Count -eq 1 -and $journal[0].Kind -ceq 'NativeChannel' -and $journal[0].Target.Channel -ceq $channelName -and (Key $journal[0].Before) -ceq (Key $seedChannel)) 'Channel-only journal contains its exact native original configuration.'
  Preserve $policyAfter $enabledXml
  $repeat=Public 'repeat' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/repeat-backup"))
  Assert ($repeat.Results.Count -eq 2 -and @($repeat.Results|Where-Object Status -CNE AlreadyCompliant).Count -eq 0 -and -not(Test-Path "$root/repeat-backup/before.jsonl")) 'Repeated public Configure is idempotent with no native write journal.'
  Preserve $policyAfter $enabledXml
  $null=New-ItemProperty -LiteralPath $path -Name $valueName -Value 0 -PropertyType DWord -Force
  $null=Invoke-WelaNative wevtutil.exe @('sl',$channelName,'/e:false')
  $zero=Policy;$disabled=Get-WelaNativeChannel $channelName
  $combined=Public 'combined' ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/combined-backup"))
  Assert ($combined.Results.Count -eq 2 -and @($combined.Results|Where-Object Status -CNE Applied).Count -eq 0 -and (Policy).Value -eq 1 -and (Read-Raw $channelName) -ceq $enabledXml) 'Actual combined call applies policy then channel fromDWORD0/disabled.'
  $journal=@(Get-Content "$root/combined-backup/before.jsonl"|ConvertFrom-Json)
  Assert ($journal.Count -eq 2 -and $journal[0].Kind -ceq 'Registry' -and $journal[1].Kind -ceq 'NativeChannel' -and (Key $journal[0].Before.Policy) -ceq (Key $zero) -and (Key $journal[1].Before) -ceq (Key $disabled)) 'Combined durable originals prove the exact two-control ordering and typed preparation.'
  foreach($case in @(@{Id='wrong-type';Type='String';Value='owned-invalid-dword'},@{Id='unknown-value';Type='DWord';Value=2})){
   Remove-ItemProperty -LiteralPath $path -Name $valueName;$null=New-ItemProperty -LiteralPath $path -Name $valueName -PropertyType $case.Type -Value $case.Value
   $null=Invoke-WelaNative wevtutil.exe @('sl',$channelName,'/e:false');$invalid=Policy;$invalidXml=Read-Raw $channelName
   $refused=Public $case.Id ($base+@('-NotificationAction','Configure','-Auto','-BackupPath',"$root/$($case.Id)-backup")) 1
   Assert ($refused.Results.Count -eq 1 -and $refused.Results[0].Status -ceq 'Failed' -and -not(Test-Path "$root/$($case.Id)-backup/before.jsonl")) 'Actual unreviewed type/value fails without coercion or journal.'
   Public ($case.Id+'-dependent') ($base+@('-NotificationAction','Configure','-EnablePrivacyChannel','-Auto','-BackupPath',"$root/$($case.Id)-dependent-backup")) 1 -NoReport
   Assert (-not(Test-Path "$root/$($case.Id)-dependent-backup")) 'Unsupported producer prevents dependent channel action.'
   Preserve $invalid $invalidXml
  }
 }
 Save 'completed.json' @{Assertions=$count;Build=$hostState.Build;ActualAppliedControls=$(if($hostState.Build -eq 20348){4}else{0});EventGenerationVerified=$false;Scope='Public selected policy/channel settings only; no telemetry, forwarding or Sigma credit.'}
}catch{$primary=$_}
finally{
 if($policyTouched){try{if((Policy).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $valueName};if($before.ValueExists){$null=New-ItemProperty -LiteralPath $path -Name $valueName -Value $before.Value -PropertyType $before.Type}}catch{$errors+='Policy restoration: '+$_.Exception.Message}}
 if($channelTouched){try{$null=Invoke-WelaNative wevtutil.exe @('sl',$channelName,('/e:'+$channelBefore.IsEnabled.ToString().ToLowerInvariant()),('/ms:'+$channelBefore.MaximumSizeInBytes),('/ca:'+$channelBefore.SecurityDescriptor))}catch{$errors+='Channel restoration: '+$_.Exception.Message}}
 $policyOk=$false;$channelOk=$false;$otherOk=$false;$masksOk=$false;$after=$null;$rawAfter=$null;$otherAfter=$null;$maskAfter=$null
 try{$after=Policy;$policyOk=(Key $after) -ceq (Key $before)}catch{$errors+='Policy readback: '+$_.Exception.Message}
 try{$rawAfter=if($rawBefore){Read-Raw $channelName}else{$null};$channelOk=$rawAfter -ceq $rawBefore -and (Key (Get-WelaNativeChannel $channelName)) -ceq (Key $channelBefore)}catch{$errors+='Channel readback: '+$_.Exception.Message}
 try{$otherAfter=Unselected;$otherOk=(Key $otherAfter) -ceq (Key $unselected)}catch{$errors+='Unselected readback: '+$_.Exception.Message}
 try{$maskAfter=Get-WelaEffectiveAuditPolicy;$masksOk=(Masks $maskAfter) -ceq (Masks $masks)}catch{$errors+='Audit mask readback: '+$_.Exception.Message}
 Save 'cleanup.json' @{Failure=[string]$primary;Errors=$errors;PolicyRestored=$policyOk;ChannelRestored=$channelOk;UnselectedPreserved=$otherOk;All59MasksPreserved=$masksOk;Complete=($policyOk -and $channelOk -and $otherOk -and $masksOk -and -not $errors.Count);Policy=$after;ChannelXml=$rawAfter;Unselected=$otherAfter;Masks=$maskAfter}
}
$artifacts=@(Get-ChildItem -LiteralPath $root -File -Recurse|ForEach-Object{[ordered]@{Path=$_.FullName.Substring($root.Length+1);Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
$sources=@('WELA.ps1','scripts/AuditNotifications.ps1','scripts/Configuration.ps1','scripts/NativeChannelConfiguration.ps1','scripts/WefArrival.ps1','modules/NativeProviders.psm1','modules/NativeChannelAccess.psm1','modules/EventLogSettings.psm1','modules/AuditProfiles.psm1','tests/OneSettingsConfigure.Windows.Tests.ps1')|ForEach-Object{[ordered]@{Path=$_;Sha256=(Get-FileHash -LiteralPath (Join-Path $repo $_) -Algorithm SHA256).Hash.ToLowerInvariant()}}
Save 'manifest.json' @{Status=$(if($primary -or -not $policyOk -or -not $channelOk -or -not $otherOk -or -not $masksOk -or $errors.Count){'Failed'}else{'Passed'});Commit=$env:GITHUB_SHA;Host=$hostState;Engine=$PSVersionTable.PSVersion.ToString();Assertions=$count;Artifacts=$artifacts;Sources=@($sources);EventGenerationVerified=$false;ForwardingVerified=$false;ReadyRuleCredit=0}
if($primary){throw $primary};if(-not $policyOk -or -not $channelOk -or -not $otherOk -or -not $masksOk -or $errors.Count){throw ('OneSettings native cleanup was not verified: '+($errors -join '; '))}
Write-Host "PASS: $count public native OneSettings assertions; selected typed policy and full channel restored, unrelated state preserved."
exit 0
