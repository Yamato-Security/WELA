param([switch]$AllowDisposableNamespaceWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableNamespaceWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable hosted Windows namespace-write opt-in is required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/WmiNamespaceAuditing.ps1"
. "$repo/scripts/WmiProbe.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WmiSaclRecovery.ps1"
$script:checks=0;$errors=@();$primary=$null;$owned=@();$engine=(Get-Process -Id $PID).Path
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:checks++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 40 -Compress}
$root=Join-Path $env:RUNNER_TEMP ('wela-wmi-recovery-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
function Save($Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),(Key $Value),[Text.UTF8Encoding]::new($false))}
function Inventory {@(Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction Stop|ForEach-Object Name|Sort-Object)}
function Services {@(foreach($name in @('Winmgmt','EventLog','WinRM')){$s=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop;[pscustomobject][ordered]@{Name=$s.Name;State=$s.State;StartMode=$s.StartMode}})}
function Masks {$m=Get-WelaEffectiveAuditPolicy;$o=[ordered]@{};foreach($id in @($m.Keys|Sort-Object)){$o[$id]=$m[$id]};[pscustomobject]$o}
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Threading.Tasks;
public static class WelaWmiRecoveryFixturePipe {
 public static async Task<string> Read(TextReader reader) {
  var text=new StringBuilder();var buffer=new char[1024];
  while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();
   if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeds one Mi characters.");text.Append(buffer,0,n);}
 }
}
'@
function Public([string]$Name,[string[]]$Arguments,[int]$Expected=0){
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',"$script:checkout/WELA.ps1")+$Arguments
 foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Unsupported fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try{
  if(-not $process.Start()){throw 'Owned public child did not start.'};$started=$true
  $stdout=[WelaWmiRecoveryFixturePipe]::Read($process.StandardOutput);$stderr=[WelaWmiRecoveryFixturePipe]::Read($process.StandardError)
  if(-not $process.WaitForExit(120000)){throw 'Public command exceeded two minutes.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Owned public child output drain did not complete.'}
  $text=$stdout.Result+"`n"+$stderr.Result;[IO.File]::WriteAllText((Join-Path $root ($Name+'.txt')),$text)
  Assert ($process.ExitCode -eq $Expected) "Public $Name exit $($process.ExitCode) expected $Expected : $text"
 }finally{
  if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.Exception.Message}};if(-not $exited){$script:errors+='Owned public child termination unconfirmed'}}
  $process.Dispose()
 }
}
Initialize-WelaWmiInterop;Initialize-WelaWmiProbeNative
$beforeInventory=Inventory;$beforeServices=Services;$beforeMasks=Masks;$beforePrecedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
$originalParent=Get-WelaWmiNamespaceSnapshot 'root';$originalDefault=Get-WelaWmiNamespaceSnapshot 'root\default';$beforeToken=Get-WelaWmiRecoveryTokenKey
Save 'original-safety.json' ([ordered]@{Inventory=$beforeInventory;Services=$beforeServices;AuditMasks=$beforeMasks;Precedence=$beforePrecedence;Root=$originalParent;Default=$originalDefault;TokenKey=$beforeToken;Engine=$PSVersionTable.PSVersion.ToString()})
try{
 $os=Get-CimInstance Win32_OperatingSystem
 Assert ($os.ProductType -eq 3 -and $os.BuildNumber -in @('20348','26100')) 'Disposable Server2022/2025 required.'
 Assert (@($beforeMasks.PSObject.Properties).Count -eq 59) 'All59 original audit masks are present.'
 foreach($case in @('empty','unrelated')){
  $name='WelaRecovery_'+[guid]::NewGuid().ToString('N');$namespace='root\'+$name
  $factory=New-Object System.Management.ManagementClass -ArgumentList '\\.\root:__Namespace';$instance=$factory.CreateInstance();$instance.Name=$name
  $options=New-Object System.Management.PutOptions;$options.Type=[System.Management.PutType]::CreateOnly
  $createdPath=$instance.Put($options)
  $entry=[pscustomobject]@{Name=$name;Namespace=$namespace;Instance=$instance;Factory=$factory;Removed=$false};$owned+=,$entry
  Assert ($createdPath.RelativePath -ceq ('__NAMESPACE.Name="'+$name+'"')) 'Only the exclusively created namespace receives writes.'
  $prepared=Get-WelaWmiNamespaceSnapshot $namespace;$data=ConvertFrom-WelaArrivalJson $prepared.DescriptorJson
  Assert (@($data.SACL|Where-Object {$null -ne $_}).Count -eq 0) 'Owned namespace begins without existing SACL entries.'
  if($case -ceq 'unrelated'){
   $other=[pscustomobject]@{Namespace=$namespace;AccessMask=[uint32]2;AceType=2;AceFlags=[uint32]128;Sid='S-1-5-18'}
   $null=Set-WelaWmiNamespaceDescriptor $namespace $prepared.DescriptorJson @($other)
   $prepared=Get-WelaWmiNamespaceSnapshot $namespace
  }
  Save ($case+'-prepared.json') $prepared
  $script:checkout=Join-Path $root ($case+'-checkout');$null=New-Item -ItemType Directory $script:checkout
  foreach($directory in @('config','modules','scripts')){Copy-Item -LiteralPath (Join-Path $repo $directory) -Destination $script:checkout -Recurse}
  Copy-Item -LiteralPath "$repo/WELA.ps1" -Destination $script:checkout
  # Production retains canonical namespace selection. Only the owned disposable
  # copied catalog is redirected, preserving all real public Configure/Recover code.
  $catalogPath=Join-Path $script:checkout 'scripts/WmiNamespaceAuditing.ps1';$catalog=[IO.File]::ReadAllText($catalogPath)
  Assert ($catalog.Contains("'root\default'")) 'Expected canonical namespace entry exists in owned copied checkout.'
  [IO.File]::WriteAllText($catalogPath,$catalog.Replace("'root\default'","'$namespace'"),[Text.UTF8Encoding]::new($false))
  Copy-Item -LiteralPath $catalogPath -Destination (Join-Path $root ($case+'-redirected-WmiNamespaceAuditing.ps1'))
  $journal=Join-Path $root ($case+'-journal');$results=Join-Path $root ($case+'-original.json')
  Public ($case+'-dryrun') @('wmi-auditing','-WmiAction','Configure','-WmiNamespace',$namespace,'-Auto','-DryRun','-BackupPath',($journal+'-dryrun'),'-ResultsPath',($results+'-dryrun'))
  Assert (-not(Test-Path ($journal+'-dryrun')) -and (Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $prepared.DescriptorJson) 'Public dry-run writes no namespace SACL or journal.'
  Public ($case+'-configure') @('wmi-auditing','-WmiAction','Configure','-WmiNamespace',$namespace,'-Auto','-BackupPath',$journal,'-ResultsPath',$results)
  $configured=Get-WelaWmiNamespaceSnapshot $namespace;$original=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText($results))
  Assert ($original.Results.Count -eq 1 -and $original.Results[0].Status -ceq 'Applied') 'Genuine public Configure journal/result proves the original addition.'
  Assert (Test-WelaWmiDescriptorPreserved (ConvertFrom-WelaArrivalJson $prepared.DescriptorJson) (ConvertFrom-WelaArrivalJson $configured.DescriptorJson)) 'Original public append preserves all unrelated descriptor properties and ACEs.'
  $planDir=Join-Path $root ($case+'-plan')
  Public ($case+'-plan') @('wmi-sacl-recovery','-WmiRecoveryNamespace',$namespace,'-WmiRecoveryJournalPath',"$journal/before.jsonl",'-WmiRecoveryOriginalResultsPath',$results,'-WmiRecoveryOutputPath',$planDir)
  $plan=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText("$planDir/manifest.json"));$reviewed=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText("$planDir/plan.json"))
  Assert ($plan.Status -ceq 'ReviewRequired' -and -not $plan.WriteAttempted -and (Get-FileHash "$planDir/plan.json").Hash.ToLowerInvariant() -ceq $plan.PlanHash) 'Native public review is read-only and has an independently checked hash.'
  Assert ((Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $configured.DescriptorJson) 'Public Plan leaves the full descriptor unchanged.'
  foreach($p in $reviewed.Sources.PSObject.Properties){Assert ((Get-FileHash -LiteralPath (Join-Path $script:checkout $p.Name)).Hash.ToLowerInvariant() -ceq $p.Value) 'Plan binds exact installed copied sources.'}
  $recover=@('wmi-sacl-recovery','-WmiRecoveryAction','Recover','-WmiRecoveryPlanPath',"$planDir/plan.json",'-WmiRecoveryPlanHash',$plan.PlanHash)
  Public ($case+'-missing-consent') ($recover+@('-WmiRecoveryOutputPath',(Join-Path $root ($case+'-missing-consent')))) 1
  Assert ((Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $configured.DescriptorJson) 'Missing explicit audit-reduction consent preserves the native descriptor.'
  $recoverDir=Join-Path $root ($case+'-recover')
  Public ($case+'-recover') ($recover+@('-WmiRecoveryAllowAuditReduction','-WmiRecoveryOutputPath',$recoverDir))
  $recovered=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText("$recoverDir/manifest.json"));$after=Get-WelaWmiNamespaceSnapshot $namespace
  Assert ($recovered.Status -ceq 'AddedAceRemoved' -and $recovered.WriteAttempted -and $recovered.ReadyRuleCredit -eq 0 -and $recovered.PolicyChanges -eq 0) 'Public recovery confirms one proven removal without policy/event/Sigma credit.'
  $expected=Get-WelaWmiRecoveryExpectedDescriptor (ConvertFrom-WelaArrivalJson $configured.DescriptorJson) (Get-WelaWmiRecoveryKey $reviewed.AddedAce)
  Assert-WelaWmiRecoveryRemoved $expected (ConvertFrom-WelaArrivalJson $after.DescriptorJson)
  Assert ($after.DescriptorJson -ceq $recovered.After.DescriptorJson) 'Independent reopened descriptor matches confirmed native readback.'
  if($case -ceq 'unrelated'){Assert (@((ConvertFrom-WelaArrivalJson $after.DescriptorJson).SACL).Count -eq 1) 'Unrelated original audit ACE remains after recovery.'}
  else{Assert (@((ConvertFrom-WelaArrivalJson $after.DescriptorJson).SACL|Where-Object {$null -ne $_}).Count -eq 0) 'Sole added audit ACE is actually absent.'}
  Public ($case+'-replay') ($recover+@('-WmiRecoveryAllowAuditReduction','-WmiRecoveryOutputPath',(Join-Path $root ($case+'-replay')))) 1
  Assert ((Get-WelaWmiNamespaceSnapshot $namespace).DescriptorJson -ceq $after.DescriptorJson) 'Stale completed plan replay makes no descriptor change.'
  foreach($manifest in @($plan,$recovered)){foreach($artifact in $manifest.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $manifest.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Saved plan/recovery artifacts match actual hashes.'}}
  Save ($case+'-after.json') $after
  Remove-Item -LiteralPath $script:checkout -Recurse -Force
 }
}catch{$primary=$_;Write-Host ('Primary WMI recovery fixture failure: '+$_.Exception.Message)}
finally{
 foreach($entry in $owned){
  try{
   if($entry.Name -cnotmatch '^WelaRecovery_[a-f0-9]{32}$' -or $entry.Instance.Name -cne $entry.Name -or $entry.Instance.Path.RelativePath -cne ('__NAMESPACE.Name="'+$entry.Name+'"')){throw 'Owned namespace identity changed; refusing deletion.'}
   $children=@(Get-CimInstance -Namespace $entry.Namespace -ClassName __Namespace -ErrorAction Stop)
   if($children.Count){throw 'Owned namespace acquired unexpected children; refusing recursive deletion.'}
   $entry.Instance.Delete();$entry.Removed=$true
  }catch{$errors+=$_.Exception.Message}
  finally{try{$entry.Instance.Dispose();$entry.Factory.Dispose()}catch{$errors+=$_.Exception.Message}}
 }
 $inventoryOk=$false;$rootOk=$false;$defaultOk=$false;$servicesOk=$false;$masksOk=$false;$precedenceOk=$false;$tokenOk=$false
 try{$afterInventory=Inventory;$inventoryOk=(Key $afterInventory) -ceq (Key $beforeInventory)}catch{$errors+=$_.Exception.Message}
 try{$rootOk=(Get-WelaWmiNamespaceSnapshot 'root').DescriptorJson -ceq $originalParent.DescriptorJson;$defaultOk=(Get-WelaWmiNamespaceSnapshot 'root\default').DescriptorJson -ceq $originalDefault.DescriptorJson}catch{$errors+=$_.Exception.Message}
 try{$afterServices=Services;$servicesOk=(Key $afterServices) -ceq (Key $beforeServices)}catch{$errors+=$_.Exception.Message}
 try{$afterMasks=Masks;$masksOk=(Key $afterMasks) -ceq (Key $beforeMasks)}catch{$errors+=$_.Exception.Message}
 try{$afterPrecedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy;$precedenceOk=(Key $afterPrecedence) -ceq (Key $beforePrecedence)}catch{$errors+=$_.Exception.Message}
 try{$afterToken=Get-WelaWmiRecoveryTokenKey;$tokenOk=$afterToken -ceq $beforeToken}catch{$errors+=$_.Exception.Message}
 foreach($dir in @((Join-Path $root 'empty-checkout'),(Join-Path $root 'unrelated-checkout'))){try{if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force}}catch{$errors+=$_.Exception.Message}}
 $complete=$inventoryOk -and $rootOk -and $defaultOk -and $servicesOk -and $masksOk -and $precedenceOk -and $tokenOk -and @($owned|Where-Object {-not $_.Removed}).Count -eq 0 -and $errors.Count -eq 0
 Save 'cleanup.json' ([ordered]@{Complete=[bool]$complete;Assertions=$script:checks;OwnedNamespaces=@($owned|Select-Object Namespace,Removed);RootInventoryRestored=$inventoryOk;RootDescriptorUnchanged=$rootOk;RealDefaultDescriptorUnchanged=$defaultOk;ServicesUnchanged=$servicesOk;AuditMasksCompared=59;AuditMasksUnchanged=$masksOk;PrecedenceUnchanged=$precedenceOk;TokenRestored=$tokenOk;AfterInventory=$afterInventory;AfterServices=$afterServices;AfterMasks=$afterMasks;AfterPrecedence=$afterPrecedence;AfterToken=$afterToken;Errors=$errors;PrimaryFailure=$(if($primary){$primary.Exception.Message}else{$null})})
}
if($primary){throw $primary};Assert $complete 'Independent exact cleanup failed; retain evidence and discard disposable VM.'
Write-Host "PASS: $script:checks native public WMI recovery assertions and exact cleanup. Evidence: $root"
