$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WecAuthorization.ps1"
Initialize-WelaWecAuthorizationNative
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern='.'){$m='';try{&$Action|Out-Null}catch{$m=$_.Exception.Message};Assert ($m -match $Pattern) "Expected $Pattern; got $m; value=$bad; action=$Action"}
function Copy-Auth($Value){Get-WelaWecAuthorizationKey $Value|ConvertFrom-Json}
$sidA='S-1-5-21-11-22-33-1001';$sidB='S-1-5-21-11-22-33-1002';$id='WELA Native Security Example'
$authA=Get-WelaWefAuthorization @($sidA);$authB=Get-WelaWefAuthorization @($sidB);$authAB=Get-WelaWefAuthorization @($sidA,$sidB)
$base=[IO.File]::ReadAllText("$repo/config/wef-examples/native-security.xml").Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>').Replace('<AllowedSourceDomainComputers></AllowedSourceDomainComputers>',('<AllowedSourceDomainComputers>'+$authA+'</AllowedSourceDomainComputers>'))
foreach($bad in @('S-1-1-0','S-1-5-20','s-1-5-21-11-22-33-1001','S-1-5-21-011-22-33-1001','S-1-5-21-4294967296-22-33-1001','S-1-5-21-11-22-33','S-1-5-21-11-22-33-1001 ',1,$true,$null)){Reject {Get-WelaWecAuthorizationSids @($bad)}}
Reject {Get-WelaWecAuthorizationSids @()};Reject {Get-WelaWecAuthorizationSids @($sidA,$sidA)} 'Duplicate';Reject {Get-WelaWecAuthorizationSids @($sidA*33)}
Assert ((Get-WelaWecAuthorizationKey @(Get-WelaWecAuthorizationSids @($sidB,$sidA))) -ceq (Get-WelaWecAuthorizationKey @($sidA,$sidB))) 'SID order is canonical'
foreach($good in @($authA,$authAB)){[Wela.WecAuthorization.Edit]::ValidateAuthorization($good);$count++}
foreach($bad in @('',$authA.Replace('GA','GR'),$authA.Replace('NSG:NS','SYG:SY'),($authA+$authA),$authA.Replace('11-22','011-22'),$authA.Replace('11-22','4294967296-22'),$authAB.Replace($sidB,$sidA),('O:NSG:NSD:(A;;GA;;;'+$sidB+')(A;;GA;;;'+$sidA+')'),($authA+'S:(AU;SA;GA;;;WD)'))){Reject {[Wela.WecAuthorization.Edit]::ValidateAuthorization($bad)}}
Assert ([Wela.WecAuthorization.Edit]::SourceSha256 -ceq (Get-WelaArrivalHash ([IO.File]::ReadAllBytes("$repo/scripts/WecAuthorizationNative.cs")))) 'Compiled native helper binds the exact source bytes'
$before=Get-WelaWecAuthorizationDefinition $base;$after=Get-WelaWecAuthorizationDefinition ($base.Replace($authA,$authAB))
Assert ($before.SourceSids.Count -eq 1 -and $after.SourceSids.Count -eq 2 -and $before.PreservedKey -ceq $after.PreservedKey -and $before.WholeKey -cne $after.WholeKey) 'Only the explicit allow list is excluded from preserved XML'
foreach($bad in @($base.Replace('SourceInitiated','CollectorInitiated'),$base.Replace('>false</Enabled>','>true</Enabled>'),$base.Replace($authA,'D:(A;;GA;;;WD)'),$base.Replace($authA,''),$base.Replace($authA,$authAB.Replace($sidB,$sidA)),$base.Replace('Path="Security"','Path="Microsoft-Windows-Sysmon/Operational"'),$base.Replace('</Subscription>','<AllowedSourceDomainComputers>bad</AllowedSourceDomainComputers></Subscription>'))){Reject {Get-WelaWecAuthorizationDefinition $bad}}
$reader=[pscustomobject][ordered]@{ProcessId=10;TokenId='1';ModifiedId='2';UserSid=$sidA;AuthenticationId='3';ElevatedAdministrator=$true;GroupSids=@('S-1-5-32-544')}
$context=[pscustomobject][ordered]@{Host='TEST';Reader=$reader;Services='Running';Destination='unchanged'}
$copy=Copy-Auth $context;$copy.Reader.ProcessId=11;$copy.Reader.TokenId='4';$copy.Reader.ModifiedId='5';Assert ((Get-WelaWecAuthorizationReviewKey $copy) -ceq (Get-WelaWecAuthorizationReviewKey $context)) 'Separate same-logon CLI processes can use a reviewed plan'
$copy.Reader.AuthenticationId='6';Assert ((Get-WelaWecAuthorizationReviewKey $copy) -cne (Get-WelaWecAuthorizationReviewKey $context)) 'Different logon is not accepted'
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-auth-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$script:xml=$base;$script:mode='ok';$script:reads=0;$script:contextReads=0;$script:saves=0;$script:pending=''
function Get-WelaWecAuthorizationContext {$script:contextReads++;$v=Copy-Auth $context;if($script:mode -eq 'token-drift' -and $script:contextReads -gt 1){$v.Reader.ModifiedId='drift'};$v}
function Read-WelaWecAuthorizationDefinition {param($Id);$script:reads++;if($script:mode -eq 'drift' -and $script:reads -eq 2){$script:xml=$script:xml.Replace('MinLatency','Normal')};if($script:mode -eq 'denied'){throw 'Native access denied'};Get-WelaWecAuthorizationDefinition $script:xml}
function Read-WelaWecSubscriptionXml {param($Id);$script:xml}
function New-WelaWecAuthorizationEdit {
 param($Before)
 $edit=[pscustomobject]@{SaveAttempted=$false}
 $edit|Add-Member ScriptMethod Save {param($Authorization)
  Assert (Test-Path $script:pending) 'Pending artifact exists before native call'
  $pending=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText($script:pending));Assert ($pending.Status -ceq 'Pending' -and $pending.DesiredAuthorization -ceq $Authorization) 'Durable intent states exact allow list'
  if($script:mode -eq 'native-refusal'){throw 'Native current view differs'}
  $this.SaveAttempted=$true;$script:saves++
  if($script:mode -eq 'native-error'){throw 'Native save failed'}
  if($script:mode -eq 'false-success'){return}
  $doc=Read-WelaWefXml $script:xml;$doc.Subscription.AllowedSourceDomainComputers=$Authorization
  if($script:mode -eq 'preservation'){$doc.Subscription.ReadExistingEvents='true'}
  if($script:mode -eq 'unexpected-enabled'){$doc.Subscription.Enabled='true'}
  $script:xml=$doc.OuterXml
  if($script:mode -eq 'artifact-drift'){[IO.File]::AppendAllText($script:pending,' ')}
 }
 $edit|Add-Member ScriptMethod Dispose {if($script:mode -eq 'cleanup-error'){throw 'Handle cleanup failed'}}
 $edit
}
try {
 Reject {Invoke-WelaWecAuthorization -Id $id -SourceSids @($sidA) -PlanHash ('a'*64) -OutputPath (Join-Path $root 'bad')} 'Plan requires'
 Reject {Invoke-WelaWecAuthorization Apply -PlanPath missing -PlanHash ('a'*64) -Id '' -OutputPath (Join-Path $root 'bad')} 'only'
 Reject {Invoke-WelaWecAuthorization -Id $id -SourceSids @($sidA) -WhatIf -OutputPath (Join-Path $root 'bad')} 'Unknown'
 foreach($scenario in @('ok','no-op','hash','schema','kind','duplicate-json','context','source','stale','enabled','denied','drift','token-drift','native-refusal','native-error','false-success','preservation','unexpected-enabled','artifact-drift','cleanup-error')){
  $script:mode='ok';$script:xml=$base;$script:reads=0;$script:contextReads=0;$script:saves=0
  $desired=if($scenario -eq 'no-op'){@($sidA)}else{@($sidA,$sidB)}
  $planned=Invoke-WelaWecAuthorization -Id $id -SourceSids $desired -OutputPath (Join-Path $root ($scenario+'-plan'))
  Assert ($planned.Status -ceq 'ReviewRequired' -and $planned.ExitCode -eq 0 -and -not $planned.NativeSaveAttempted -and $script:saves -eq 0) "Plan: $($planned.Diagnostic)"
  $path=Join-Path $planned.OutputPath 'plan.json';$hash=$planned.PlanHash
  if($scenario -eq 'hash'){$hash='f'*64}
  if($scenario -in @('schema','kind','duplicate-json','context','source')){
   $text=[IO.File]::ReadAllText($path)
   switch($scenario){schema{$text=$text -replace '"SchemaVersion"\s*:\s*1','"SchemaVersion":true'}kind{$text=$text -replace '"Kind"\s*:\s*"WelaWecAuthorizationPlan"','"Kind":true'}duplicate-json{$text=$text.Replace('"SchemaVersion":','"SchemaVersion":1,"SchemaVersion":')}context{$text=$text.Replace('TEST','OTHER')}source{$text=$text.Replace('scripts/WecAuthorization.ps1','scripts/other.ps1')}}
   [IO.File]::WriteAllText($path,$text);$hash=(Get-FileHash $path).Hash.ToLowerInvariant()
  }
  if($scenario -eq 'stale'){$script:xml=$base.Replace('MinLatency','Normal')};if($scenario -eq 'enabled'){$script:xml=$base.Replace('>false</Enabled>','>true</Enabled>')}
  $script:mode=$scenario;$script:reads=0;$script:contextReads=0;$out=Join-Path $root ($scenario+'-apply');$script:pending=Join-Path $out 'before-save.json'
  $applied=Invoke-WelaWecAuthorization Apply -PlanPath $path -PlanHash $hash -OutputPath $out
  Assert (($applied.ExitCode -eq 0) -eq ($scenario -in @('ok','no-op'))) "Scenario $scenario : $($applied.Diagnostic)"
  Assert ($applied.ReadyRuleCredit -eq 0 -and (Test-Path (Join-Path $out 'manifest.json'))) 'No readiness credit and final result retained'
  if($scenario -in @('native-error','false-success','preservation','unexpected-enabled','artifact-drift','cleanup-error')){Assert ($applied.NativeSaveAttempted -and $applied.Status -ceq 'SaveAttemptedUnverified') 'Possible persistent change remains unverified'}elseif($scenario -notin @('ok','no-op')){Assert (-not $applied.NativeSaveAttempted -and $script:saves -eq 0 -and $applied.Status -ceq 'Refused') 'Rejected before native save'}
  if($scenario -eq 'no-op'){Assert ($applied.Status -ceq 'AlreadyMatches' -and -not $applied.NativeSaveAttempted -and $script:saves -eq 0) 'No-op never saves'}
  if($scenario -eq 'ok'){
   Assert ($applied.Status -ceq 'AuthorizationChangedAndVerified' -and $applied.NativeSaveAttempted -and $applied.After.PreservedKey -ceq $before.PreservedKey) 'Successful update changes only explicit authorization'
   $again=Invoke-WelaWecAuthorization Apply -PlanPath $path -PlanHash $hash -OutputPath (Join-Path $root 'replay');Assert ($again.Status -ceq 'Refused' -and -not $again.NativeSaveAttempted -and $script:saves -eq 1) 'Changed pre-state refuses stale plan'
  }
  if($scenario -ne 'artifact-drift'){foreach($artifact in $applied.Artifacts){Assert ((Get-FileHash (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Retained artifact hash matches bytes'}}
 }
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count focused WEC authorization assertions; no native delivery proof."
