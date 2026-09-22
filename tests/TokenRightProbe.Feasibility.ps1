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
 Set-WelaEffectiveAuditPolicy -Guid $guid -Mask ($beforeMasks[$guid] -bor 1) -Mode exact
 Set-WelaEffectiveAuditPolicy -Guid $auth -Mask 0 -Mode exact
 $engine=(Get-Process -Id $PID).Path
 & $engine -NoLogo -NoProfile -NonInteractive -File $worker $repo $receipt
 if($LASTEXITCODE -ne 0){throw 'Native worker failed.'}
 $result=Get-Content -Raw $receipt|ConvertFrom-Json
 $start=[DateTime]::FromFileTimeUtc($result.Outcome.DisableStartedFileTime).AddSeconds(-1);$end=[DateTime]::FromFileTimeUtc($result.Outcome.RestoreReturnedFileTime).AddSeconds(1)
 $query="*[System[EventID=4703 and TimeCreated[@SystemTime>='$($start.ToString('o'))' and @SystemTime<='$($end.ToString('o'))']]]"
 $matches=@();$deadline=[DateTime]::UtcNow.AddSeconds(15)
 do{
  $events=@(Get-WinEvent -LogName Security -FilterXPath $query -MaxEvents 256 -ErrorAction SilentlyContinue)
  foreach($event in $events){
   $raw=$event.ToXml();[xml]$xml=$raw;$data=@{};foreach($field in $xml.Event.EventData.Data){$data[[string]$field.Name]=[string]$field.'#text'}
   if($data.ProcessId -and [Convert]::ToInt64($data.ProcessId,16) -eq $result.ProcessId -and ($data.EnabledPrivilegeList -match 'SeChangeNotifyPrivilege' -or $data.DisabledPrivilegeList -match 'SeChangeNotifyPrivilege')){$matches+=@([pscustomobject]@{RecordId=$event.RecordId;Xml=$raw;Data=$data})}
   $event.Dispose()
  }
  $matches=@($matches|Sort-Object RecordId -Unique)
  if($matches.Count -ge 2){break};Start-Sleep -Milliseconds 250
 }while([DateTime]::UtcNow -lt $deadline)
 Save 'events.json' $matches
 if($matches.Count -lt 2){throw 'No two attributable actual4703 adjustment events were observed.'}
 Write-Host "Native feasibility observed $($matches.Count) attributable4703 events with Token Right Adjusted success enabled and Authorization Policy Change disabled."
}catch{$failure=$_.ToString();throw}finally{
 foreach($restoreGuid in @($guid,$auth)){try{Set-WelaEffectiveAuditPolicy -Guid $restoreGuid -Mask $beforeMasks[$restoreGuid] -Mode exact}catch{$errors+=$_.ToString()}}
 try{if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $path -Name $name -Value $beforePrecedence.Value -Type $beforePrecedence.Type}else{Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}}catch{$errors+=$_.ToString()}
 $afterToken=[Wela.WmiProbe.Native]::Snapshot();$afterPrecedence=Get-WelaRegistryState $path $name
 $complete=$errors.Count -eq 0 -and (Masks) -ceq $masks -and (Key $afterPrecedence) -ceq (Key $beforePrecedence) -and ((Key $beforeToken) -ceq (Key $afterToken))
 Save 'cleanup.json' @{Complete=$complete;Errors=$errors;Failure=$failure;AfterToken=$afterToken;AfterMasks=Get-WelaEffectiveAuditPolicy;AfterPrecedence=$afterPrecedence}
 if(-not $complete){throw 'Native feasibility fixture cleanup failed.'}
}
$global:LASTEXITCODE=0
