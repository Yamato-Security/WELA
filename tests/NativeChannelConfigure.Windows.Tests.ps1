param([switch]$AllowDisposableChannelWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableChannelWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
Import-Module "$repo/modules/NativeProviders.psm1" -Force
Import-Module "$repo/modules/NativeChannelAccess.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/NativeChannelConfiguration.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Binary($Value){$bytes=New-Object byte[] $Value.BinaryLength;$Value.GetBinaryForm($bytes,0);[Convert]::ToBase64String($bytes)}
function Read-Raw([string]$Name){
 $r=Invoke-WelaNative wevtutil.exe @('gl',$Name,'/f:xml')
 $x=New-Object Xml.XmlDocument;$x.XmlResolver=$null;$x.LoadXml(($r.Output -join "`n"));return ,$x
}
function Guard-Raw($Xml){
 $x=$Xml.CloneNode($true);$x.DocumentElement.RemoveAttribute('enabled')
 foreach($name in @('channelAccess','maxSize')){foreach($node in @($x.SelectNodes("//*[local-name()='$name']"))){$null=$node.ParentNode.RemoveChild($node)}}
 return $x.OuterXml
}
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-channel-configure-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$profile=Get-WelaNativeChannelProfile
$before=@{};$raw=@{};$policies=Get-WelaEffectiveAuditPolicy
foreach($control in $profile.controls){$name=$control.channel;$before[$name]=Get-WelaNativeChannel $name;if(Test-WelaNativeChannelSnapshot $before[$name]){$raw[$name]=Read-Raw $name}}
$before|ConvertTo-Json -Depth 14|Set-Content "$root/before.json" -Encoding UTF8
$missing=@($before.Values|Where-Object State -eq 'Not installed').Count
$expected=if($missing){1}else{0}
$capi='Microsoft-Windows-CAPI2/Operational';$app='Microsoft-Windows-AppLocker/EXE and DLL'
$primary=$null
function Run-Cli([string]$Name,[string[]]$Options){
 $prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$lines=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" channel-settings @Options -ResultsPath "$root/$Name.json" 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 $lines|Out-String|Set-Content "$root/$Name.txt" -Encoding UTF8
 Assert ($code -eq $expected) "Public $Name exit $code expected $expected : $($lines -join ' ')"
 $report=Get-Content "$root/$Name.json" -Raw|ConvertFrom-Json
 Assert ($report.ExitCode -eq $code -and $report.ForwardingReadiness -eq 'Not verified') 'Report agrees with native command exit and makes no forwarding claim'
 return $report
}
try{
 Assert ($raw.ContainsKey($capi) -and $raw.ContainsKey($app)) 'CAPI2 and AppLocker channels are required for this disposable fixture'
 Assert (@($before.Values|Where-Object { $_.State -notin @('Enabled','Disabled','Not installed') }).Count -eq 0) 'Unreadable original metadata refuses fixture writes'
 # Fixture-only remove this group read grant so the public opt-in must append it.
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($before[$capi].SecurityDescriptor)
 for($i=$descriptor.DiscretionaryAcl.Count-1;$i -ge 0;$i--){
  $ace=$descriptor.DiscretionaryAcl[$i]
  if($ace -is [Security.AccessControl.CommonAce] -and $ace.AceQualifier -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -eq 'S-1-5-32-573' -and ($ace.AccessMask -band 1)){$descriptor.DiscretionaryAcl.RemoveAce($i)}
 }
 $withoutRead=$descriptor.GetSddlForm('All');$access=Get-WelaChannelAccessPlan $withoutRead
 Assert ($access.State -eq 'GrantRequired') 'Prepared actual descriptor supports one lossless read-only grant'
 $null=Invoke-WelaNative wevtutil.exe @('sl',$capi,'/e:false','/ms:1048576',('/ca:'+$withoutRead))
 # A large existing log exposed numeric narrowing in older PowerShell planners.
 $null=Invoke-WelaNative wevtutil.exe @('sl',$app,'/ms:2147483648')
 $prepared=@{};foreach($name in $raw.Keys){$prepared[$name]=Get-WelaNativeChannel $name}
 $null=Run-Cli 'plan' @('-ChannelAction','Plan','-GrantEventLogReaders')
 $null=Run-Cli 'dry-run' @('-ChannelAction','Configure','-GrantEventLogReaders','-DryRun','-Auto','-BackupPath',"$root/unused")
 Assert (-not (Test-Path "$root/unused")) 'DryRun creates no journal'
 foreach($name in $raw.Keys){Assert (Test-WelaNativeChannelSnapshotEqual $prepared[$name] (Get-WelaNativeChannel $name)) 'Plan and DryRun preserve actual native channel settings'}
 $plain=Run-Cli 'configure' @('-ChannelAction','Configure','-Auto','-BackupPath',"$root/plain-journal")
 $plainCapi=Get-WelaNativeChannel $capi
 Assert ($plainCapi.IsEnabled -and $plainCapi.MaximumSizeInBytes -eq 102432768 -and (Test-WelaChannelDescriptorEqual $plainCapi.SecurityDescriptor $withoutRead)) 'Public Configure enables/resizes CAPI2 and preserves its ACL without explicit grant'
 Assert ((Get-WelaNativeChannel $app).MaximumSizeInBytes -eq 2147483648) 'A larger existing 2GiB buffer is preserved'
 $granted=Run-Cli 'grant' @('-ChannelAction','Configure','-GrantEventLogReaders','-Auto','-BackupPath',"$root/grant-journal")
 $actual=Get-WelaNativeChannel $capi
 Assert (Test-WelaChannelDescriptorEqual $actual.SecurityDescriptor $access.ProposedDescriptor) 'Native readback matches the precise planned grant descriptor'
 $afterAcl=[Security.AccessControl.RawSecurityDescriptor]::new($actual.SecurityDescriptor)
 Assert ($afterAcl.DiscretionaryAcl.Count -eq $descriptor.DiscretionaryAcl.Count+1) 'Exactly one native DACL ACE is added'
 $newAce=$afterAcl.DiscretionaryAcl[$access.AddedAceIndex]
 Assert ($newAce.SecurityIdentifier.Value -eq 'S-1-5-32-573' -and $newAce.AccessMask -eq 1 -and $newAce.AceFlags -eq 0 -and -not $newAce.IsCallback) 'Added grant is unconditional read only'
 $afterAcl.DiscretionaryAcl.RemoveAce($access.AddedAceIndex)
 Assert ((Binary $afterAcl) -ceq (Binary $descriptor)) 'Owner/group/SACL/flags and every original ACE byte/order survive native application'
 $again=Run-Cli 'idempotent' @('-ChannelAction','Configure','-GrantEventLogReaders','-Auto','-BackupPath',"$root/repeat-journal")
 Assert (@($again.Results|Where-Object Status -eq 'Applied').Count -eq 0) 'Repeated native configuration does not apply another mutation'
 Assert (-not (Test-Path "$root/repeat-journal/before.jsonl")) 'Idempotent invocation journals no write'
 $journal=@(Get-Content "$root/grant-journal/before.jsonl"|ForEach-Object {$_|ConvertFrom-Json})
 Assert ($journal.Count -eq 1 -and $journal[0].Target.Channel -eq $capi -and (Test-WelaChannelDescriptorEqual $journal[0].Before.SecurityDescriptor $withoutRead)) 'Durable actual pre-grant journal preserves the original descriptor'
 foreach($name in $raw.Keys){Assert ((Guard-Raw (Read-Raw $name)) -ceq (Guard-Raw $raw[$name])) 'Native channel path/retention/provider metadata remain unchanged'}
 Write-Host "PASS: $count native public channel configuration assertions."
}catch{$primary=$_}
finally{
 $errors=@()
 foreach($name in $raw.Keys){
  try{$s=$before[$name];$null=Invoke-WelaNative wevtutil.exe @('sl',$name,('/e:'+$s.IsEnabled.ToString().ToLowerInvariant()),('/ms:'+$s.MaximumSizeInBytes),('/ca:'+$s.SecurityDescriptor))
   if(-not (Test-WelaNativeChannelSnapshotEqual $s (Get-WelaNativeChannel $name)) -or (Read-Raw $name).OuterXml -cne $raw[$name].OuterXml){throw 'Original native channel configuration differs after cleanup'}
  }catch{$errors+="$name : $($_.Exception.Message)"}
 }
 $now=Get-WelaEffectiveAuditPolicy;foreach($guid in $policies.Keys){if($policies[$guid] -ne $now[$guid]){$errors+='Audit mask changed: '+$guid}}
 $after=@{};foreach($name in $before.Keys){$after[$name]=Get-WelaNativeChannel $name}
 [ordered]@{CleanupVerified=($errors.Count -eq 0);Before=$before;After=$after;AuditMasksCompared=$policies.Count;Diagnostic=$errors;Assertions=$count;PrimaryError=[string]$primary}|ConvertTo-Json -Depth 14|Set-Content "$root/cleanup.json" -Encoding UTF8
 if($errors.Count){throw "Cleanup failed: $($errors -join '; '); primary: $primary"}
 Write-Host 'Exact original channel metadata and all audit masks verified after cleanup; existing event records/retention duration not claimed.'
}
if($primary){throw $primary};$global:LASTEXITCODE=0
