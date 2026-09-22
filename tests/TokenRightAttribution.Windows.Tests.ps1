param([switch]$AllowDisposableAuditWrite)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess -or -not $AllowDisposableAuditWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable Windows fixture only.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $repo 'modules/AuditCatalog.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $repo 'scripts/WmiProbe.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $PSScriptRoot 'TokenRightAttributionEvidence.ps1')
Initialize-WelaWmiProbeNative
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-token-right-attribution-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Masks{$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
$guid='0CCE924A-69AE-11D9-BED3-505054503030';$auth='0CCE9231-69AE-11D9-BED3-505054503030'
$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$name='SCENoApplyLegacyAuditPolicy'
foreach($service in @('Winmgmt','EventLog')){if((Get-Service $service).Status -ne 'Running'){throw 'Observation services must already be running.'}}
$hostContext=Get-WelaDefaultContext
if(-not(Test-WelaDefaultContextComplete $hostContext) -or $hostContext.ProductType -ne 3 -or $hostContext.DomainRole -ne 2 -or $hostContext.Build -notin @(20348,26100)){throw 'Only reviewed disposable standalone Server2022/2025 hosts are accepted.'}
$provider=Get-WinEvent -ListProvider 'Microsoft-Windows-Security-Auditing'
$schema=@($provider.Events|Where-Object{$_.Id -eq 4703 -and $_.Version -eq 0})
if($schema.Count -ne 1 -or $provider.Id -ne [guid]'54849625-5478-4994-a5ba-3e3b0328c30d'){throw 'Exactly one installed version0 Security4703 schema is required.'}
$eventTask=[int]$schema[0].Task.Value
Save 'provider-diagnostic.json' @{TaskType=$schema[0].Task.GetType().FullName;TaskValue=$schema[0].Task.Value;TaskName=$schema[0].Task.Name;TaskDisplay=$schema[0].Task.DisplayName;Tasks=@($provider.Tasks|ForEach-Object{@{Value=$_.Value;Name=$_.Name;Display=$_.DisplayName;Guid=[string]$_.EventGuid}})}
$publisher=Invoke-WelaNative wevtutil.exe @('gp','Microsoft-Windows-Security-Auditing','/ge:true','/gm:false','/f:xml')
$publisherText=$publisher.Output -join "`n";if($publisherText.Length -gt 4194304){throw 'Native publisher metadata exceeds fixture bound.'};[IO.File]::WriteAllText((Join-Path $root 'publisher.xml'),$publisherText)
$computerProperties=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties();$computers=@([Environment]::MachineName,$computerProperties.HostName);if($computerProperties.DomainName){$computers+=$computerProperties.HostName+'.'+$computerProperties.DomainName};$computers=@($computers|Sort-Object -Unique)
function Channel{(Invoke-WelaNative wevtutil.exe @('gl','Security','/f:xml')).Output -join "`n"}
function Services{@(Get-Service Winmgmt,EventLog|Sort-Object Name|ForEach-Object{[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status;StartType=[string]$_.StartType}})}
$originalChannel=Channel;$originalServices=Services
$nativeListing=Invoke-WelaNative auditpol.exe @('/list','/subcategory:*','/v')
$listing=$nativeListing.Output -join "`n"
foreach($row in @(@{Name='Token Right Adjusted Events';Guid=$guid},@{Name='Authorization Policy Change';Guid=$auth})){
 if($listing -notmatch [regex]::Escape($row.Guid)){throw 'Native audit listing omits a selected exact GUID.'}
 if([Globalization.CultureInfo]::InstalledUICulture.TwoLetterISOLanguageName -eq 'en' -and -not @($nativeListing.Output|Where-Object{$_ -match [regex]::Escape($row.Guid) -and $_ -match [regex]::Escape($row.Name)}).Count){throw 'Native selected audit name and GUID disagree.'}
}
Save 'native-audit-catalog.json' @{Listing=$nativeListing.Output;Selected=@($guid,$auth)}
$canonical=(Import-WelaAuditProfiles).catalog
$mapping=Get-WelaEventMappingReview @(Import-Csv "$repo/config/eid_subcategory_mapping.csv") $canonical 4703
if($mapping.State -cne 'Conditional' -or $mapping.Candidates.Count -ne 2 -or $mapping.DetectionReady){throw 'Historical4703 candidates must remain conditional with no readiness credit.'}
Save 'mapping-review.json' $mapping
$sources=[ordered]@{}
foreach($file in @('tests/TokenRightAttribution.Windows.Tests.ps1','tests/TokenRightAttributionNative.cs','tests/TokenRightAttributionEvidence.ps1','tests/TokenRightAttribution.Tests.ps1','modules/AuditProfiles.psm1','modules/AuditCatalog.psm1','scripts/Configuration.ps1','scripts/WefArrival.ps1','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/ControlApplicability.ps1','config/audit_profiles.json','config/baselines.json','config/eid_subcategory_mapping.csv')){$sources[$file]=(Get-FileHash -LiteralPath "$repo/$file" -Algorithm SHA256).Hash.ToLowerInvariant()}
$beforeMasks=Get-WelaEffectiveAuditPolicy;$masks=Masks;$beforePrecedence=Get-WelaRegistryState $path $name;$beforeToken=[Wela.WmiProbe.Native]::Snapshot();$failure=$null;$errors=@()
Save 'original.json' @{Masks=$beforeMasks;Precedence=$beforePrecedence;Token=$beforeToken;Head=$env:GITHUB_SHA;Engine=$PSVersionTable.PSVersion.ToString();Host=$hostContext;Channel=$originalChannel;Services=$originalServices;Computers=$computers;Provider=[string]$provider.Id;Schema=@{Id=4703;Version=0;Task=$eventTask;Template=$schema[0].Template}}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;
public static class WelaTokenFixturePipe {
 public static async Task<string> Read(TextReader reader) {
  var text=new StringBuilder();var buffer=new char[2048];while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeded one Mi characters.");text.Append(buffer,0,n);}
 }
}
'@
function Worker([string]$Phase,[string]$Receipt){
 $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',$worker,$repo,$Receipt)
 foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Ambiguous fixture argument.'}}
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=(Get-Process -Id $PID).Path;$info.Arguments=(@($all|ForEach-Object{'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
 try{
  if(-not $process.Start()){throw 'Owned worker did not start.'};$started=$true
  $stdout=[WelaTokenFixturePipe]::Read($process.StandardOutput);$stderr=[WelaTokenFixturePipe]::Read($process.StandardError)
  if(-not $process.WaitForExit(90000)){throw 'Owned worker exceeded90seconds.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Owned worker drain exceeded5seconds.'}
  [IO.File]::WriteAllText((Join-Path $root ($Phase+'-worker.txt')),$stdout.Result+"`n"+$stderr.Result)
  if($process.ExitCode -ne 0){throw 'Owned native worker failed; see retained output.'}
  [pscustomobject]@{ProcessId=$process.Id;Executable=$info.FileName}
 }finally{
  if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.ToString()};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.ToString()};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.ToString()}};if(-not $exited){$script:errors+='Owned worker termination unconfirmed.'}}
  try{$process.Dispose()}catch{$script:errors+=$_.ToString()}
 }
}
$worker=Join-Path $root 'worker.ps1';$receipt=Join-Path $root 'worker.json'
@'
param($Repo,$Result)
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $Repo 'scripts/WmiProbeNative.cs')
Add-Type -Path (Join-Path $Repo 'tests/TokenRightAttributionNative.cs')
$executable=[Wela.TokenRightProbe.Native]::Executable()
$before=[Wela.WmiProbe.Native]::Snapshot()
$outcome=[Wela.TokenRightProbe.Native]::Run()
$after=[Wela.WmiProbe.Native]::Snapshot()
[pscustomobject]@{ProcessId=$PID;ProcessName=$executable;Before=$before;After=$after;Outcome=$outcome}|ConvertTo-Json -Depth 24|Set-Content -LiteralPath $Result -Encoding UTF8
if($outcome.Status -ne 'Adjusted' -or -not $outcome.Restored -or (($before|ConvertTo-Json -Depth 24 -Compress) -cne ($after|ConvertTo-Json -Depth 24 -Compress))){exit 1}
exit 0
'@|Set-Content -LiteralPath $worker -Encoding UTF8
try{
 if($beforeMasks.Count -ne 59){throw 'All59 masks required.'}
 Set-ItemProperty -LiteralPath $path -Name $name -Value 1 -Type DWord
 $phases=@(@{Name='TokenRightOnly';Token=1;Authorization=0},@{Name='AuthorizationOnly';Token=0;Authorization=1})
 $summaries=@()
 foreach($phase in $phases){
  Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $phase.Token -Mode exact
  Set-WelaEffectiveAuditPolicy -Guid $auth -Mask $phase.Authorization -Mode exact
  $prepared=Get-WelaEffectiveAuditPolicy
  foreach($entry in $beforeMasks.Keys){$expected=$beforeMasks[$entry];if($entry -eq $guid){$expected=$phase.Token};if($entry -eq $auth){$expected=$phase.Authorization};if($prepared[$entry] -ne $expected){throw 'Prepared native policy differs from the exact selected two-mask change.'}}
  Save ($phase.Name+'-prepared.json') @{Phase=$phase;Masks=$prepared;Precedence=Get-WelaRegistryState $path $name}
  $receipt=Join-Path $root ($phase.Name+'-worker.json')
  $record=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop;try{$watermark=[long]$record.RecordId}finally{$record.Dispose()}
  $launched=[Wela.WmiProbe.Native]::UtcNow().ToFileTimeUtc()
  $child=Worker $phase.Name $receipt
  $observed=[Wela.WmiProbe.Native]::UtcNow().ToFileTimeUtc()
  $result=Get-Content -Raw $receipt|ConvertFrom-Json
  if($result.ProcessId -ne $child.ProcessId -or $result.ProcessName -ine $child.Executable -or $result.Outcome.Status -isnot [string] -or $result.Outcome.Status -cne 'Adjusted' -or $result.Outcome.Restored -isnot [bool] -or -not $result.Outcome.Restored -or $result.Outcome.DisableStartedFileTime -lt $launched -or $result.Outcome.OperationCompletedFileTime -gt $observed){throw 'Owned worker receipt identity, status or measured operation interval is invalid.'}
  Assert-WelaTokenAttributionTimes $result.Outcome $launched $observed
  $context=[pscustomobject]@{ProcessId=$child.ProcessId;ProcessName=$child.Executable;Sid=$result.Before.Sid;AuthenticationId=$result.Before.AuthenticationId;Computers=$computers;Task=$eventTask;Watermark=$watermark;DisableStartedFileTime=$result.Outcome.DisableStartedFileTime;OperationCompletedFileTime=$result.Outcome.OperationCompletedFileTime}
  Save ($phase.Name+'-context.json') @{Context=$context;LaunchedFileTime=$launched;ObservedFileTime=$observed;Child=$child}
  $exactStart=[DateTime]::FromFileTimeUtc($result.Outcome.DisableStartedFileTime);$exactEnd=[DateTime]::FromFileTimeUtc($result.Outcome.OperationCompletedFileTime)
  $start=$exactStart.AddSeconds(-2);$end=$exactEnd.AddSeconds(2)
  $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4703 and TimeCreated[@SystemTime>='$($start.ToString('o'))' and @SystemTime<='$($end.ToString('o'))']]]"
  $candidates=@{};$queryErrors=@();$attributedEvents=@();$deadline=[DateTime]::UtcNow.AddSeconds(15)
  do{
   $reader=$null
   try{
    $nativeQuery=[System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Security',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$query)
    $reader=[System.Diagnostics.Eventing.Reader.EventLogReader]::new($nativeQuery)
    $statuses=@($reader.LogStatus);if($statuses.Count -ne 1 -or $statuses[0].LogName -cne 'Security' -or $statuses[0].StatusCode -ne 0){throw 'Native query lacks exactly one successful Security channel status.'}
    $count=0
    while($null -ne ($event=$reader.ReadEvent([TimeSpan]::FromSeconds(2)))){
     try{
      $count++;if($count -gt 512){throw 'Diagnostic candidate count exceeded512.'}
      $raw=$event.ToXml();if($raw.Length -gt 65536){throw 'Candidate XML exceeded64Ki characters.'}
      [xml]$xml=$raw;$data=@{};foreach($field in $xml.Event.EventData.Data){$data[[string]$field.Name]=[string]$field.'#text'}
      $match=Get-WelaTokenAttributionMatch $raw $context
      $candidates[[string]$event.RecordId]=[pscustomobject]@{RecordId=$event.RecordId;Xml=$raw;Data=$data;Attributed=($null -ne $match);Direction=if($match){$match.Direction}else{$null}}
     }finally{$event.Dispose()}
    }
   }catch{$queryErrors+=@($_.ToString());break}finally{if($reader){$reader.Dispose()}}
   $attributedEvents=@($candidates.Values|Where-Object{$_.Attributed}|Sort-Object RecordId)
   if($attributedEvents.Count -ge 2){break};Start-Sleep -Milliseconds 250
  }while([DateTime]::UtcNow -lt $deadline)
  Save ($phase.Name+'-candidates.json') @($candidates.Values|Sort-Object RecordId)
  Save ($phase.Name+'-events.json') $attributedEvents
  Save ($phase.Name+'-query.json') @{XPath=$query;ExactStart=$exactStart;ExactEnd=$exactEnd;QueryErrors=$queryErrors;CandidateCount=$candidates.Count;AttributedCount=$attributedEvents.Count;NoMatchingEvents=($candidates.Count -eq 0);DiagnosticOnly=$true}
  if($queryErrors.Count){throw 'Native4703 observation failed; see retained query errors.'}
  if($phase.Name -ceq 'TokenRightOnly' -and ($attributedEvents.Count -ne 2 -or @($attributedEvents|Where-Object Direction -CEQ Disable).Count -ne 1 -or @($attributedEvents|Where-Object Direction -CEQ Restore).Count -ne 1)){throw 'TokenRight-only requires exactly one actual disable and one restore4703.'}
  if($phase.Name -ceq 'AuthorizationOnly' -and $attributedEvents.Count -ne 0){throw 'Inverse phase produced an unexpected attributable event; do not generalize the mapping.'}
  if((Key (Get-WelaEffectiveAuditPolicy)) -cne (Key $prepared)){throw 'Prepared audit policy drifted during observation.'}
  $summaries+=@([pscustomobject]@{Phase=$phase.Name;CandidateCount=$candidates.Count;AttributedCount=$attributedEvents.Count;ReadComplete=$true;AdjustedAndRestored=($result.Outcome.Status -eq 'Adjusted' -and $result.Outcome.Restored)})
  Save 'summary.json' $summaries
  Write-Host "$($phase.Name): $($attributedEvents.Count) exact native4703 records, $($candidates.Count) bounded diagnostic candidates."
 }
 if(@($summaries|Where-Object{$_.AttributedCount -gt 0}).Count -eq 0){throw 'Neither selected policy phase produced an attributable4703 event.'}
}catch{$failure=$_.ToString();throw}finally{
 foreach($restoreGuid in @($guid,$auth)){try{Set-WelaEffectiveAuditPolicy -Guid $restoreGuid -Mask $beforeMasks[$restoreGuid] -Mode exact}catch{$errors+=$_.ToString()}}
 try{if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $path -Name $name -Value $beforePrecedence.Value -Type $beforePrecedence.Type}else{Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}}catch{$errors+=$_.ToString()}
 $afterToken=$null;$afterPrecedence=$null;$afterMasks=$null;$afterMaskKey=$null;$afterChannel=$null;$afterServices=$null
 try{$afterToken=[Wela.WmiProbe.Native]::Snapshot()}catch{$errors+=$_.ToString()}
 try{$afterPrecedence=Get-WelaRegistryState $path $name}catch{$errors+=$_.ToString()}
 try{$afterMasks=Get-WelaEffectiveAuditPolicy;$afterMaskKey=@($afterMasks.Keys|Sort-Object|ForEach-Object{"$_=$($afterMasks[$_])"}) -join ';'}catch{$errors+=$_.ToString()}
 try{$afterChannel=Channel}catch{$errors+=$_.ToString()}
 try{$afterServices=Services}catch{$errors+=$_.ToString()}
 $complete=$afterChannel -ceq $originalChannel -and (Key $afterServices) -ceq (Key $originalServices) -and $errors.Count -eq 0 -and $afterMaskKey -ceq $masks -and (Key $afterPrecedence) -ceq (Key $beforePrecedence) -and ((Key $beforeToken) -ceq (Key $afterToken))
 foreach($file in $sources.Keys){try{if((Get-FileHash -LiteralPath "$repo/$file" -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sources[$file]){$errors+='Fixture source drift: '+$file;$complete=$false}}catch{$errors+=$_.ToString();$complete=$false}}
 Save 'cleanup.json' @{Complete=$complete;Errors=$errors;Failure=$failure;AfterToken=$afterToken;AfterMasks=$afterMasks;AfterPrecedence=$afterPrecedence;AfterChannel=$afterChannel;AfterServices=$afterServices}
 $artifactHashes=@(Get-ChildItem -LiteralPath $root -File -Recurse|Sort-Object FullName|ForEach-Object{[pscustomobject]@{Path=$_.FullName.Substring($root.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
 Save 'manifest.json' @{Head=$env:GITHUB_SHA;Status=if($complete -and -not $failure){'Passed'}else{'Failed'};Sources=$sources;Artifacts=$artifactHashes;Fixture='NativeSecurity4703Attribution';EventIds=@(4703);RuntimePolicyPhases=@('TokenRightOnly','AuthorizationOnly');OtherAuditMasksPreserved=57;NoSigmaCredit=$true;NoForwardingCredit=$true;HistoricalCandidatesRemainConditional=$true}
 if(-not $complete){throw 'Native attribution fixture cleanup failed.'}
}
$global:LASTEXITCODE=0
