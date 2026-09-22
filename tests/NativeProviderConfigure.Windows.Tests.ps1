param([switch]$AllowDisposableProviderWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableProviderWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows provider-write opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/EventLogSettings.psm1" -Force
Import-Module "$repo/modules/NativeProviders.psm1" -Force
Import-Module "$repo/modules/NativeChannelAccess.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/NativeChannelConfiguration.ps1"
. "$repo/scripts/NativeProviderPacks.ps1"
$count=0;$errors=@();$primary=$null;$mutated=@()
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 30|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Read-Raw([string]$Name){$r=Invoke-WelaNative wevtutil.exe @('gl',$Name,'/f:xml');$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.LoadXml(($r.Output -join "`n"));return ,$doc}
function Guard-Raw($Xml){$copy=$Xml.CloneNode($true);$copy.DocumentElement.RemoveAttribute('enabled');foreach($node in @($copy.SelectNodes("/*/*[local-name()='logging']/*[local-name()='maxSize']"))){$null=$node.ParentNode.RemoveChild($node)};$copy.OuterXml}
function Services {
 foreach($name in @('EventLog','Winmgmt','WinRM','TermService','DNS')){
  $state=Get-WelaNativeService $name
  if($state.State -eq 'Unknown'){throw "Service $name is unreadable"}
  [pscustomobject][ordered]@{Name=$name;State=$state.State;Start=$(if($state.State -ne 'Not installed'){[string](Get-Service -Name $name -ErrorAction Stop).StartType}else{$null})}
 }
}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 20 -Compress}
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Threading.Tasks;
public static class WelaProviderConfigureFixturePipe {
 public static async Task<string> Read(TextReader reader) {
  var text=new StringBuilder(); var buffer=new char[1024];
  while(true) { int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false); if(n==0)return text.ToString();
   if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeded 1Mi characters.");text.Append(buffer,0,n); }
 }
}
'@
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-provider-configure-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$wrapper=Join-Path $root 'public.ps1'
@'
param([string]$InputPath)
$ErrorActionPreference='Stop';$global:LASTEXITCODE=0
$p=Get-Content -LiteralPath $InputPath -Raw|ConvertFrom-Json
$a=@{ProviderAction=[string]$p.Action;ProviderPack=[string[]]$p.Names;ResultsPath=[string]$p.ResultsPath}
if($p.Action -ceq 'Configure'){$a.Auto=$true;$a.BackupPath=[string]$p.BackupPath}
if($p.DryRun){$a.DryRun=$true}
$extra=[string[]]$p.Extra
& ([string]$p.Script) provider-packs @a @extra
exit $global:LASTEXITCODE
'@ | Set-Content -LiteralPath $wrapper -Encoding UTF8
function Public([string]$Name,[string]$Action,[string[]]$Names,[switch]$DryRun,[int]$Expected=0,[string[]]$Extra=@()){
 $inputPath=Join-Path $root ($Name+'-input.json');$resultPath=Join-Path $root ($Name+'.json');$backup=Join-Path $root ($Name+'-journal')
 Save ($Name+'-input.json') @{Script="$repo/WELA.ps1";Action=$Action;Names=$Names;DryRun=[bool]$DryRun;ResultsPath=$resultPath;BackupPath=$backup;Extra=$Extra}
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',$wrapper,'-InputPath',$inputPath)
 foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Unsupported fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try {
  if(-not $process.Start()){throw 'Public process did not start'};$started=$true
  $stdout=[WelaProviderConfigureFixturePipe]::Read($process.StandardOutput);$stderr=[WelaProviderConfigureFixturePipe]::Read($process.StandardError)
  if(-not $process.WaitForExit(180000)){throw 'Public command exceeded three minutes.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public command output drain timed out.'}
  $text=$stdout.Result+"`n"+$stderr.Result;[IO.File]::WriteAllText((Join-Path $root ($Name+'.txt')),$text)
  Assert ($process.ExitCode -eq $Expected) "Public $Name exit $($process.ExitCode) expected $Expected : $text"
 }finally{
  if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.Exception.Message}};if(-not $exited){$script:errors+='Owned public process termination unconfirmed'}}
  try{$process.Dispose()}catch{$script:errors+=$_.Exception.Message}
 }
 if(Test-Path $resultPath){$r=Get-Content $resultPath -Raw|ConvertFrom-Json;Assert ($r.ExitCode -eq $Expected -and $r.ReadyRules -eq 0 -and $r.UnverifiedEvidence.Count -eq 4) 'Public result agrees with process exit and grants no readiness credit.';return $r}
 Assert ($Expected -eq 1 -and -not(Test-Path $backup)) 'Invalid CLI refuses before report or recovery directory creation.'
}
$catalog=Get-WelaProviderPackCatalog
$names=@('dns-client','capi2','winrm','rdp-client');$selected=@($catalog.packs|Where-Object {$names -contains $_.id})
$channels=@(@($catalog.packs.channel)+@('Security','System','Application','Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-DriverFrameworks-UserMode/Operational')|Sort-Object -Unique)
$before=@{};$raw=@{};$prepared=@{};$preparedRaw=@{};$services=@(Services);$policies=Get-WelaEffectiveAuditPolicy
foreach($channel in $channels){$before[$channel]=Get-WelaNativeChannel $channel;if(Test-WelaNativeChannelSnapshot $before[$channel]){$raw[$channel]=Read-Raw $channel}}
$rawText=@{};foreach($channel in $raw.Keys){$rawText[$channel]=$raw[$channel].OuterXml}
Save 'original.json' @{Channels=$before;RawXml=$rawText;Services=$services;AuditMasks=$policies;Engine=$PSVersionTable.PSVersion.ToString()}
function Stable-Selected {foreach($channel in $selected.channel){Assert (Test-WelaNativeChannelSnapshotEqual $configured[$channel] (Get-WelaNativeChannel $channel)) 'Idempotent/refused/partial invocation preserves the expected complete selected-channel tuple.'}}
function Preserved {
 foreach($channel in $channels){
  $now=Get-WelaNativeChannel $channel
  if($selected.channel -contains $channel){Assert ((Guard-Raw (Read-Raw $channel)) -ceq (Guard-Raw $preparedRaw[$channel])) 'Selected channel preserves complete descriptor, retention, path and publisher settings.'}
  elseif($raw.ContainsKey($channel)){Assert ((Read-Raw $channel).OuterXml -ceq $raw[$channel].OuterXml) 'Unselected registered channel retains every configuration field.'}
  else{Assert ((Key $now) -ceq (Key $before[$channel])) 'Uninstalled/unreadable nonselected channel observation remains unchanged.'}
 }
 Assert ((Key @(Services)) -ceq (Key $services)) 'EventLog, Winmgmt, WinRM, RDP and DNS service state/start types remain unchanged.'
 $nowMasks=Get-WelaEffectiveAuditPolicy;Assert ($nowMasks.Count -eq 59 -and $policies.Count -eq 59) 'All59 native audit masks are present.'
 foreach($guid in $policies.Keys){if($nowMasks[$guid] -ne $policies[$guid]){throw "Audit mask changed: $guid"}};$script:count++
}
try {
 Assert (@($services|Where-Object {$_.Name -in @('Winmgmt','EventLog') -and $_.State -ne 'Running'}).Count -eq 0) 'Metadata dependencies must already be running; fixture never starts services.'
 $os=Get-CimInstance Win32_OperatingSystem
 Assert ($os.ProductType -eq 3 -and $os.BuildNumber -in @('20348','26100')) 'Reviewed disposable Server2022/2025 required.'
 Assert (@($services|Where-Object {$_.Name -eq 'DNS' -and $_.State -eq 'Not installed'}).Count -eq 1) 'Fixture requires genuine DNS Server absence; no role is installed/removed for acceptance.'
 foreach($pack in $selected){Assert ($raw.ContainsKey($pack.channel)) "Actual selected channel required: $($pack.id)"}
 # First real public observation must support all four reviewed manifest gates.
 $initial=Public 'initial' 'Plan' $names
 foreach($entry in $initial.ControlsPlan){Assert ($entry.ProviderEvidence.CanConfigure -and $entry.ProviderEvidence.Schema.State -ceq 'Observed' -and $entry.ProviderEvidence.Schema.Provider -ceq $entry.Pack.provider) 'Exact actual provider/schema permits the selected pack.'}
 Assert ($initial.ControlsPlan.Count -eq 4) 'Exactly four explicit packs are observed.'
 foreach($channel in $raw.Keys){Assert ((Read-Raw $channel).OuterXml -ceq $raw[$channel].OuterXml) 'Initial public Plan preserves every registered channel configuration.'}
 foreach($pack in $selected){
  $channel=$pack.channel;$mutated+=,$channel
  $size=if($pack.id -ceq 'winrm'){2147483648L}else{1048576L}
  $nativeArguments=@('sl',$channel,'/e:false',('/ms:'+$size));if($pack.id -ceq 'capi2'){$nativeArguments+=@('/rt:true','/ab:false')}
  $null=Invoke-WelaNative wevtutil.exe $nativeArguments
  $prepared[$channel]=Get-WelaNativeChannel $channel;$preparedRaw[$channel]=Read-Raw $channel
 }
 $preparedText=@{};foreach($channel in $preparedRaw.Keys){$preparedText[$channel]=$preparedRaw[$channel].OuterXml}
 Save 'prepared.json' $prepared;Save 'prepared-xml.json' $preparedText
 $planned=Public 'plan' 'Plan' $names
 Assert (@($planned.ControlsPlan|Where-Object Status -cne 'ChangeRequired').Count -eq 0) 'Actual disabled/small prepared channels require change.'
 $dry=Public 'dry' 'Configure' $names -DryRun
 Assert ($dry.DryRun -and $dry.Results.Count -eq 4 -and @($dry.Results|Where-Object Status -cne 'Skipped').Count -eq 0 -and -not(Test-Path "$root/dry-journal")) 'Public DryRun skips all selected writes and creates no journal.'
 $null=Public 'whatif' 'Configure' $names -Expected 1 -Extra @('-WhatIf')
 $null=Public 'grant-option' 'Configure' $names -Expected 1 -Extra @('-GrantEventLogReaders')
 foreach($channel in $selected.channel){Assert (Test-WelaNativeChannelSnapshotEqual $prepared[$channel] (Get-WelaNativeChannel $channel)) 'Plan, DryRun and invalid options preserve prepared actual state.'}
 Preserved
 $configured=@{}
 $applied=Public 'configure' 'Configure' $names
 Assert ($applied.Action -ceq 'Configure' -and $applied.Scope -ceq 'native-channel-settings-only' -and $applied.Results.Count -eq 4 -and @($applied.Results|Where-Object Status -cne 'Applied').Count -eq 0) 'All four explicit configurations are actually Applied.'
 $journal=@(Get-Content "$root/configure-journal/before.jsonl"|ForEach-Object {$_|ConvertFrom-Json})
 Assert ($journal.Count -eq 4 -and @($journal|Where-Object {$selected.channel -notcontains $_.Target.Channel}).Count -eq 0) 'Exactly four selected changes have durable original journals.'
 foreach($pack in $selected){
  $channel=$pack.channel;$entry=@($applied.Results|Where-Object {$_.Target.Channel -ceq $channel});$j=@($journal|Where-Object {$_.Target.Channel -ceq $channel});$now=Get-WelaNativeChannel $channel;$configured[$channel]=$now
  $minimum=if($pack.id -ceq 'capi2'){102432768L}elseif($pack.id -ceq 'winrm'){2147483648L}else{33554432L}
  Assert ($entry.Count -eq 1 -and $j.Count -eq 1 -and (Test-WelaNativeChannelSnapshotEqual $j[0].Before $prepared[$channel]) -and (Test-WelaNativeChannelSnapshotEqual $entry[0].Before $prepared[$channel])) 'Native journal and result retain exact prepared before-state.'
  Assert ($now.IsEnabled -and $now.MaximumSizeInBytes -eq $minimum -and (Test-WelaNativeChannelSnapshotEqual $entry[0].After $now)) 'Exact native enable/floor/larger-buffer readback matches Applied after-state.'
  Assert ((Test-WelaChannelDescriptorEqual $now.SecurityDescriptor $prepared[$channel].SecurityDescriptor) -and $now.LogMode -ceq $prepared[$channel].LogMode -and -not $entry[0].Desired.AccessChangeRequested) 'Every descriptor byte and retention mode is preserved without a read grant.'
 }
 $configuredText=@{};foreach($channel in $selected.channel){$configuredText[$channel]=(Read-Raw $channel).OuterXml};Save 'configured-xml.json' $configuredText
 Assert ((Get-WelaNativeChannel 'Microsoft-Windows-CAPI2/Operational').LogMode -ceq 'Retain') 'An actual nondefault Retain setting survives provider configuration.'
 Preserved
 $repeat=Public 'repeat' 'Configure' $names
 Assert (@($repeat.Results|Where-Object Status -cne 'AlreadyCompliant').Count -eq 0 -and -not(Test-Path "$root/repeat-journal/before.jsonl")) 'Native repeat is idempotent and journals no write.'
 Stable-Selected
 $manual=Public 'manual' 'Configure' @('dns-server-analytical','dns-server-classic') -Expected 1
 Assert ($manual.Results.Count -eq 2 -and @($manual.Results|Where-Object Status -cne 'Failed').Count -eq 0 -and -not(Test-Path "$root/manual-journal/before.jsonl")) 'Both actual manual-only selections fail without channel mutation or journal.'
 Stable-Selected
 $missing=Public 'missing-dns' 'Configure' @('dns-server-audit') -Expected 1
 Assert ($missing.Results[0].Status -ceq 'Failed' -and $missing.ControlsPlan[0].ProviderEvidence.Service.State -ceq 'Not installed' -and -not(Test-Path "$root/missing-dns-journal/before.jsonl")) 'Missing actual DNS service cannot be replaced by an assumed server role.'
 Stable-Selected
 # A genuine partial public run must retain one success and one manual refusal.
 $capi='Microsoft-Windows-CAPI2/Operational';$null=Invoke-WelaNative wevtutil.exe @('sl',$capi,'/e:false');$partialBefore=Get-WelaNativeChannel $capi
 $partial=Public 'partial' 'Configure' @('capi2','dns-server-analytical') -Expected 1
 Assert (@($partial.Results|Where-Object Status -ceq 'Applied').Count -eq 1 -and @($partial.Results|Where-Object Status -ceq 'Failed').Count -eq 1 -and (Get-WelaNativeChannel $capi).IsEnabled) 'Actual partial configuration retains one verified change and explicit nonzero failure.'
 $partialJournal=@(Get-Content "$root/partial-journal/before.jsonl"|ForEach-Object {$_|ConvertFrom-Json})
 Assert ($partialJournal.Count -eq 1 -and $partialJournal[0].Target.Channel -ceq $capi -and (Test-WelaNativeChannelSnapshotEqual $partialJournal[0].Before $partialBefore)) 'Partial run journals only its actual selected write.'
 Stable-Selected
 Preserved
 Save 'completed.json' @{Status='Passed';Assertions=$count;ActualAppliedControls=5;IdempotentControls=4;ManualRefusals=3;MissingServiceRefusals=1;ReadyRuleCredit=0}
}catch{$primary=$_}
finally {
 foreach($channel in $mutated){
  try {
   $s=$before[$channel];$retention=if($s.LogMode -ceq 'Circular'){'false'}else{'true'};$backup=if($s.LogMode -ceq 'AutoBackup'){'true'}else{'false'}
   $null=Invoke-WelaNative wevtutil.exe @('sl',$channel,('/e:'+$s.IsEnabled.ToString().ToLowerInvariant()),('/ms:'+$s.MaximumSizeInBytes),('/ca:'+$s.SecurityDescriptor),('/rt:'+$retention),('/ab:'+$backup))
   if(-not(Test-WelaNativeChannelSnapshotEqual $s (Get-WelaNativeChannel $channel)) -or (Read-Raw $channel).OuterXml -cne $raw[$channel].OuterXml){throw 'Exact original channel configuration differs after cleanup.'}
  }catch{$errors+="$channel : $($_.Exception.Message)"}
 }
 $after=@{};$afterRaw=@{};foreach($channel in $channels){try{$after[$channel]=Get-WelaNativeChannel $channel;if($raw.ContainsKey($channel)){$afterRaw[$channel]=(Read-Raw $channel).OuterXml;if($afterRaw[$channel] -cne $raw[$channel].OuterXml){throw 'Original channel XML differs'}}elseif((Key $after[$channel]) -cne (Key $before[$channel])){throw 'Original unavailable observation differs'}}catch{$errors+="$channel : $($_.Exception.Message)"}}
 $serviceAfter=$null;try{$serviceAfter=@(Services);if((Key $serviceAfter) -cne (Key $services)){throw 'Service state/start type differs'}}catch{$errors+=$_.Exception.Message}
 $maskAfter=$null;try{$maskAfter=Get-WelaEffectiveAuditPolicy;if($maskAfter.Count -ne $policies.Count){throw 'Audit mask count differs'};foreach($guid in $policies.Keys){if($maskAfter[$guid] -ne $policies[$guid]){throw "Audit mask differs: $guid"}}}catch{$errors+=$_.Exception.Message}
 Save 'cleanup.json' @{CleanupVerified=($errors.Count -eq 0);Original=$before;After=$after;AfterRawXml=$afterRaw;ServicesBefore=$services;ServicesAfter=$serviceAfter;AuditMasksCompared=$policies.Count;AuditMasksAfter=$maskAfter;Errors=$errors;PrimaryError=[string]$primary;Assertions=$count}
}
$artifacts=@(Get-ChildItem -LiteralPath $root -File -Recurse|ForEach-Object {[ordered]@{Path=$_.FullName.Substring($root.Length+1);Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
$sourcePaths=@('WELA.ps1','scripts/Configuration.ps1','scripts/NativeChannelConfiguration.ps1','scripts/NativeProviderPacks.ps1','modules/AuditProfiles.psm1','modules/EventLogSettings.psm1','modules/NativeProviders.psm1','modules/NativeChannelAccess.psm1','config/native_channel_profile.json','config/native_provider_packs.json','config/security_rules.json','tests/NativeProviderConfigure.Windows.Tests.ps1')+@($catalog.ruleReviews|ForEach-Object {'config/'+$_.localPath})
$sources=@($sourcePaths|ForEach-Object {[ordered]@{Path=$_;Sha256=(Get-FileHash -LiteralPath (Join-Path $repo $_) -Algorithm SHA256).Hash}})
Save 'manifest.json' @{Status=$(if($primary -or $errors.Count){'Failed'}else{'Passed'});Commit=$env:GITHUB_SHA;Engine=$PSVersionTable.PSVersion.ToString();Assertions=$count;Artifacts=$artifacts;Sources=$sources;EventGenerationVerified=$false;ForwardingVerified=$false;ReadyRuleCredit=0}
if($errors.Count){throw "Fixture cleanup failed: $($errors -join '; '); primary=$primary"};if($primary){throw $primary}
Write-Host "PASS: $count native public provider-pack assertions and exact channel/service/audit cleanup. No event generation or Sigma proof."
exit 0
