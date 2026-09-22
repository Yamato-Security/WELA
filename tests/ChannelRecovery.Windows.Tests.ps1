param([switch]$AllowDisposableChannelWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableChannelWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows channel-write opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
Import-Module "$repo/modules/NativeProviders.psm1" -Force
Import-Module "$repo/modules/NativeChannelAccess.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/NativeChannelConfiguration.ps1"
$count=0;$errors=@();$primary=$null
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Read-Raw([string]$Name){$r=Invoke-WelaNative wevtutil.exe @('gl',$Name,'/f:xml');$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.LoadXml(($r.Output -join "`n"));return ,$doc}
function Guard-Raw($Xml){$copy=$Xml.CloneNode($true);$copy.DocumentElement.RemoveAttribute('enabled');$copy.DocumentElement.RemoveAttribute('channelAccess');foreach($node in @($copy.SelectNodes("/*/*[local-name()='logging']/*[local-name()='maxSize']"))){$null=$node.ParentNode.RemoveChild($node)};$copy.OuterXml}
function Save($Name,$Value){$Value|ConvertTo-Json -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Threading.Tasks;
public static class WelaChannelRecoveryFixturePipe {
 public static async Task<string> Read(TextReader reader) {
  var text=new StringBuilder(); var buffer=new char[1024];
  while(true) { int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false); if(n==0)return text.ToString();
   if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeded 1Mi characters.");text.Append(buffer,0,n); }
 }
}
'@
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-channel-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
function Public([string]$Name,[string[]]$Arguments,[int]$Expected=0){
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',"$repo/WELA.ps1")+$Arguments
 foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Unsupported fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try {
  if(-not $process.Start()){throw 'Public process did not start'};$started=$true
  $stdout=[WelaChannelRecoveryFixturePipe]::Read($process.StandardOutput);$stderr=[WelaChannelRecoveryFixturePipe]::Read($process.StandardError)
  if(-not $process.WaitForExit(120000)){throw 'Public command exceeded two minutes.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public command output drain timed out.'}
  $text=$stdout.Result+"`n"+$stderr.Result;[IO.File]::WriteAllText((Join-Path $root ($Name+'.txt')),$text)
  Assert ($process.ExitCode -eq $Expected) "Public $Name exit $($process.ExitCode) expected $Expected : $text"
 }finally{
  if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.Exception.Message}};if(-not $exited){$script:errors+='Owned public process termination unconfirmed'}}
  try{$process.Dispose()}catch{$script:errors+=$_.Exception.Message}
 }
}
$profile=Get-WelaNativeChannelProfile;$before=@{};$raw=@{};$policies=Get-WelaEffectiveAuditPolicy
foreach($control in $profile.controls){$name=$control.channel;$before[$name]=Get-WelaNativeChannel $name;if(Test-WelaNativeChannelSnapshot $before[$name]){$raw[$name]=Read-Raw $name}}
$capi='Microsoft-Windows-CAPI2/Operational';$app='Microsoft-Windows-AppLocker/EXE and DLL'
$expectedConfigure=if(@($before.Values|Where-Object State -eq 'Not installed').Count){1}else{0}
Save 'before.json' $before;$rawText=@{};foreach($name in $raw.Keys){$rawText[$name]=$raw[$name].OuterXml};Save 'raw-before.json' $rawText
try {
 $os=Get-CimInstance Win32_OperatingSystem
 Assert ($os.ProductType -eq 3 -and $os.BuildNumber -in @('20348','26100')) 'Reviewed disposable Server 2022/2025 required.'
 Assert ($raw.ContainsKey($capi) -and $raw.ContainsKey($app)) 'Readable CAPI2 and AppLocker channels required.'
 Assert (@($before.Values|Where-Object State -notin @('Enabled','Disabled','Not installed')).Count -eq 0) 'Unreadable original settings refuse fixture mutation.'
 # Owned disposable preparation removes only this group read ACE, preserving every
 # captured original byte for final cleanup. Product recovery never uses this shortcut.
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($before[$capi].SecurityDescriptor)
 for($i=$descriptor.DiscretionaryAcl.Count-1;$i -ge 0;$i--){$ace=$descriptor.DiscretionaryAcl[$i];if($ace -is [Security.AccessControl.CommonAce] -and $ace.AceQualifier -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -eq 'S-1-5-32-573' -and ($ace.AccessMask -band 1)){$descriptor.DiscretionaryAcl.RemoveAce($i)}}
 $withoutRead=$descriptor.GetSddlForm('All');Assert ((Get-WelaChannelAccessPlan $withoutRead).State -ceq 'GrantRequired') 'Actual descriptor permits one lossless read-only grant.'
 $null=Invoke-WelaNative wevtutil.exe @('sl',$app,'/ms:2147483648')
 foreach($scenario in @('grant','no-grant')){
  $null=Invoke-WelaNative wevtutil.exe @('sl',$capi,'/e:false','/ms:1048576',('/ca:'+$withoutRead))
  $prepared=Get-WelaNativeChannel $capi;Save ($scenario+'-prepared.json') $prepared
  $journal=Join-Path $root ($scenario+'-original-journal');$resultPath=Join-Path $root ($scenario+'-original.json')
  $options=@('channel-settings','-ChannelAction','Configure','-Auto','-BackupPath',$journal,'-ResultsPath',$resultPath);if($scenario -ceq 'grant'){$options+='-GrantEventLogReaders'}
  Public ($scenario+'-configure') $options $expectedConfigure
  $original=Get-Content $resultPath -Raw|ConvertFrom-Json;$selected=@($original.Results|Where-Object {$_.Target.Channel -ceq $capi})
  Assert ($selected.Count -eq 1 -and $selected[0].Status -ceq 'Applied') 'Public Configure supplies a genuinely Applied selected operation.'
  $configured=Get-WelaNativeChannel $capi;Assert ($configured.IsEnabled -and $configured.MaximumSizeInBytes -eq 102432768) 'Actual enable and size changes observed.'
  $others=@{};foreach($name in $raw.Keys){if($name -cne $capi){$others[$name]=(Read-Raw $name).OuterXml}}
  $planDir=Join-Path $root ($scenario+'-plan')
  Public ($scenario+'-plan') @('channel-recovery','-ChannelRecoveryJournalPath',"$journal/before.jsonl",'-ChannelRecoveryOriginalResultsPath',$resultPath,'-ChannelRecoveryChannel',$capi,'-ChannelRecoveryOutputPath',$planDir)
  $plan=Get-Content "$planDir/manifest.json" -Raw|ConvertFrom-Json
  Assert ($plan.Status -ceq 'ReviewRequired' -and -not $plan.NativeWriteAttempted -and (Get-FileHash "$planDir/plan.json").Hash.ToLowerInvariant() -ceq $plan.PlanHash) 'Public Plan is read-only with an independently checked exact hash.'
  $restoreArgs=@('channel-recovery','-ChannelRecoveryAction','Restore','-ChannelRecoveryPlanPath',"$planDir/plan.json",'-ChannelRecoveryPlanHash',$plan.PlanHash)
  $consents=@('-ChannelRecoveryAllowShrink','-ChannelRecoveryAllowDisable');if($scenario -ceq 'grant'){$consents+='-ChannelRecoveryAllowRevoke'}
  foreach($consent in $consents){
   $refuseDir=Join-Path $root ($scenario+'-missing-'+$consent.TrimStart('-'))
   Public ($scenario+'-missing-'+$consent.TrimStart('-')) ($restoreArgs+@('-ChannelRecoveryOutputPath',$refuseDir)+@($consents|Where-Object {$_ -cne $consent})) 1
   $r=Get-Content "$refuseDir/manifest.json" -Raw|ConvertFrom-Json;Assert ($r.Status -ceq 'Refused' -and -not $r.NativeWriteAttempted -and (Test-WelaNativeChannelSnapshotEqual $configured (Get-WelaNativeChannel $capi))) 'Each required consent refuses before native write.'
  }
  $whatIf=Join-Path $root ($scenario+'-whatif');Public ($scenario+'-whatif') ($restoreArgs+@('-ChannelRecoveryOutputPath',$whatIf,'-WhatIf')+$consents) 1
  Assert (-not (Test-Path $whatIf)) 'Unsupported preview option refuses before dispatch/output.'
  # Real native drift between reviewed plan and Restore must not be undone.
  $null=Invoke-WelaNative wevtutil.exe @('sl',$capi,('/ms:'+($configured.MaximumSizeInBytes+65536)))
  $drift=Join-Path $root ($scenario+'-drift');Public ($scenario+'-drift') ($restoreArgs+@('-ChannelRecoveryOutputPath',$drift)+$consents) 1
  $r=Get-Content "$drift/manifest.json" -Raw|ConvertFrom-Json;Assert ($r.Status -ceq 'Refused' -and -not $r.NativeWriteAttempted -and (Get-WelaNativeChannel $capi).MaximumSizeInBytes -eq ($configured.MaximumSizeInBytes+65536)) 'Actual native drift refuses without overwriting the later setting.'
  $null=Invoke-WelaNative wevtutil.exe @('sl',$capi,('/ms:'+$configured.MaximumSizeInBytes))
  $restoredDir=Join-Path $root ($scenario+'-restore');Public ($scenario+'-restore') ($restoreArgs+@('-ChannelRecoveryOutputPath',$restoredDir)+$consents)
  $r=Get-Content "$restoredDir/manifest.json" -Raw|ConvertFrom-Json
  Assert ($r.Status -ceq 'RestoredAndVerified' -and $r.NativeWriteAttempted -and $r.ConfirmedFields.Count -eq $(if($scenario -ceq 'grant'){3}else{2})) 'Every originally changed field has verified durable restoration.'
  Assert (Test-WelaNativeChannelSnapshotEqual $prepared (Get-WelaNativeChannel $capi)) 'Actual original enable/size/descriptor/retention tuple restored.'
  Assert ((Guard-Raw (Read-Raw $capi)) -ceq (Guard-Raw $raw[$capi])) 'All other raw selected-channel configuration fields preserved.'
  foreach($name in $others.Keys){Assert ((Read-Raw $name).OuterXml -ceq $others[$name]) 'Recovery does not touch another profile channel.'}
  foreach($artifact in $r.Artifacts){Assert ((Get-FileHash (Join-Path $restoredDir $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Restoration artifact hash matches actual bytes.'}
  $replay=Join-Path $root ($scenario+'-replay');Public ($scenario+'-replay') ($restoreArgs+@('-ChannelRecoveryOutputPath',$replay)+$consents) 1
  $r=Get-Content "$replay/manifest.json" -Raw|ConvertFrom-Json;Assert ($r.Status -ceq 'Refused' -and -not $r.NativeWriteAttempted) 'Restored old plan refuses replay.'
 }
 Write-Host "PASS: $count actual public channel Configure/Restore assertions."
}catch{$primary=$_;Write-Host $_;Get-ChildItem -LiteralPath $root -Filter manifest.json -Recurse|ForEach-Object {Write-Host ([IO.File]::ReadAllText($_.FullName))}}
finally {
 foreach($name in $raw.Keys){try{$s=$before[$name];$null=Invoke-WelaNative wevtutil.exe @('sl',$name,('/e:'+$s.IsEnabled.ToString().ToLowerInvariant()),('/ms:'+$s.MaximumSizeInBytes),('/ca:'+$s.SecurityDescriptor));if(-not (Test-WelaNativeChannelSnapshotEqual $s (Get-WelaNativeChannel $name)) -or (Read-Raw $name).OuterXml -cne $raw[$name].OuterXml){throw 'Original full channel metadata differs after fixture cleanup'}}catch{$errors+=$name+': '+$_.Exception.Message}}
 try{$current=Get-WelaEffectiveAuditPolicy;foreach($guid in $policies.Keys){if($policies[$guid] -ne $current[$guid]){$errors+='Audit policy changed: '+$guid}}}catch{$errors+=$_.Exception.Message}
 Save 'cleanup.json' ([ordered]@{Complete=($errors.Count -eq 0);Errors=$errors;OriginalChannels=@($raw.Keys);AuditMasksCompared=$policies.Count;PrimaryError=[string]$primary;EventRecordsRestored=$false;Boundary='Fixture restores exact original configuration; shrinking may discard intervening records. No retention or forwarding proof.'})
}
$artifacts=@(Get-ChildItem -LiteralPath $root -File -Recurse|ForEach-Object {[ordered]@{Path=$_.FullName.Substring($root.Length+1);Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
Save 'acceptance.json' ([ordered]@{Status=$(if($primary -or $errors.Count){'Failed'}else{'Passed'});Commit=$env:GITHUB_SHA;Engine=$PSVersionTable.PSVersion.ToString();Assertions=$count;Artifacts=$artifacts;ReadyRuleCredit=0})
if($errors.Count){throw ('Cleanup failed: '+($errors -join '; '))};if($primary){throw $primary};exit 0
