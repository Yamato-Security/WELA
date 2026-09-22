param([switch]$AllowDisposableAuditWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAuditWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable Windows fixture only.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiProbe.ps1')
Initialize-WelaWmiProbeNative
$root=Join-Path $env:RUNNER_TEMP ('wela-token-right-feasibility-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Masks{$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
$guid='0CCE924A-69AE-11D9-BED3-505054503030';$auth='0CCE9231-69AE-11D9-BED3-505054503030'
$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$name='SCENoApplyLegacyAuditPolicy'
$beforeMasks=Get-WelaEffectiveAuditPolicy;$masks=Masks;$beforePrecedence=Get-WelaRegistryState $path $name;$beforeToken=[Wela.WmiProbe.Native]::Snapshot();$failure=$null;$errors=@()
Save 'original.json' @{Masks=$beforeMasks;Precedence=$beforePrecedence;Token=$beforeToken;Head=$env:GITHUB_SHA;Engine=$PSVersionTable.PSVersion.ToString()}
$worker=Join-Path $root 'worker.ps1';$receipt=Join-Path $root 'worker.json'
@'
param($Repo,$Result)
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $Repo 'scripts/WmiProbeNative.cs')
Add-Type -Path (Join-Path $Repo 'scripts/TokenRightProbeNative.cs')
$before=[Wela.WmiProbe.Native]::Snapshot()
$outcome=[Wela.TokenRightProbe.Native]::Run()
$after=[Wela.WmiProbe.Native]::Snapshot()
[pscustomobject]@{ProcessId=$PID;ProcessName=(Get-Process -Id $PID).Path;Before=$before;After=$after;Outcome=$outcome}|ConvertTo-Json -Depth 24|Set-Content -LiteralPath $Result -Encoding UTF8
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
  $engine=(Get-Process -Id $PID).Path
  & $engine -NoLogo -NoProfile -NonInteractive -File $worker $repo $receipt
  if($LASTEXITCODE -ne 0){throw 'Native worker failed.'}
  $result=Get-Content -Raw $receipt|ConvertFrom-Json
  $exactStart=[DateTime]::FromFileTimeUtc($result.Outcome.DisableStartedFileTime);$exactEnd=[DateTime]::FromFileTimeUtc($result.Outcome.RestoreReturnedFileTime)
  $start=$exactStart.AddSeconds(-2);$end=$exactEnd.AddSeconds(2)
  $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4703 and TimeCreated[@SystemTime>='$($start.ToString('o'))' and @SystemTime<='$($end.ToString('o'))']]]"
  $candidates=@{};$queryErrors=@();$attributedEvents=@();$deadline=[DateTime]::UtcNow.AddSeconds(15)
  do{
   $reader=$null
   try{
    $nativeQuery=[System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Security',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$query)
    $reader=[System.Diagnostics.Eventing.Reader.EventLogReader]::new($nativeQuery)
    $count=0
    while($null -ne ($event=$reader.ReadEvent())){
     try{
      $count++;if($count -gt 512){throw 'Diagnostic candidate count exceeded512.'}
      $raw=$event.ToXml();if($raw.Length -gt 65536){throw 'Candidate XML exceeded64Ki characters.'}
      [xml]$xml=$raw;$data=@{};foreach($field in $xml.Event.EventData.Data){$data[[string]$field.Name]=[string]$field.'#text'}
      $time=[DateTime]::Parse([string]$xml.Event.System.TimeCreated.SystemTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
      $identity=$data.ProcessId -and [Convert]::ToInt64($data.ProcessId,16) -eq $result.ProcessId -and $data.ProcessName -ieq $result.ProcessName -and $data.SubjectUserSid -ceq $result.Before.Sid -and $data.TargetUserSid -ceq $result.Before.Sid -and $data.SubjectLogonId -ieq $result.Before.AuthenticationId -and $data.TargetLogonId -ieq $result.Before.AuthenticationId
      $privilege=$data.EnabledPrivilegeList -ceq 'SeDebugPrivilege' -or $data.DisabledPrivilegeList -ceq 'SeDebugPrivilege'
      $exact=$identity -and $privilege -and $time -ge $exactStart -and $time -le $exactEnd
      $candidates[[string]$event.RecordId]=[pscustomobject]@{RecordId=$event.RecordId;Xml=$raw;Data=$data;ExactIdentity=[bool]$identity;ExactInterval=($time -ge $exactStart -and $time -le $exactEnd);Attributed=[bool]$exact}
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
  if((Key (Get-WelaEffectiveAuditPolicy)) -cne (Key $prepared)){throw 'Prepared audit policy drifted during observation.'}
  $summaries+=@([pscustomobject]@{Phase=$phase.Name;CandidateCount=$candidates.Count;AttributedCount=$attributedEvents.Count;ReadComplete=$true;AdjustedAndRestored=($result.Outcome.Status -eq 'Adjusted' -and $result.Outcome.Restored)})
  Save 'summary.json' $summaries
  Write-Host "$($phase.Name): $($attributedEvents.Count) exact native4703 records, $($candidates.Count) bounded diagnostic candidates."
 }
 if(@($summaries|Where-Object{$_.AttributedCount -gt 0}).Count -eq 0){throw 'Neither selected policy phase produced an attributable4703 event.'}
}catch{$failure=$_.ToString();throw}finally{
 foreach($restoreGuid in @($guid,$auth)){try{Set-WelaEffectiveAuditPolicy -Guid $restoreGuid -Mask $beforeMasks[$restoreGuid] -Mode exact}catch{$errors+=$_.ToString()}}
 try{if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $path -Name $name -Value $beforePrecedence.Value -Type $beforePrecedence.Type}else{Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}}catch{$errors+=$_.ToString()}
 $afterToken=[Wela.WmiProbe.Native]::Snapshot();$afterPrecedence=Get-WelaRegistryState $path $name
 $complete=$errors.Count -eq 0 -and (Masks) -ceq $masks -and (Key $afterPrecedence) -ceq (Key $beforePrecedence) -and ((Key $beforeToken) -ceq (Key $afterToken))
 Save 'cleanup.json' @{Complete=$complete;Errors=$errors;Failure=$failure;AfterToken=$afterToken;AfterMasks=Get-WelaEffectiveAuditPolicy;AfterPrecedence=$afterPrecedence}
 if(-not $complete){throw 'Native feasibility fixture cleanup failed.'}
}
$global:LASTEXITCODE=0
