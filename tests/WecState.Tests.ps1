$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WecState.ps1"
Initialize-WelaWecStateNative
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-wec-state-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$sid='S-1-5-21-11-22-33-1001';$id='WELA Native Security Example'
$base=[IO.File]::ReadAllText("$repo/config/wef-examples/native-security.xml").Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>').Replace('<AllowedSourceDomainComputers></AllowedSourceDomainComputers>',('<AllowedSourceDomainComputers>'+(Get-WelaWefAuthorization @($sid))+'</AllowedSourceDomainComputers>'))
$script:xml=$base;$script:saves=0;$script:reads=0;$script:contextReads=0;$script:mode='ok';$script:journal=''
function Get-WelaWecStateContext {
 $script:contextReads++;$token='11'*56
 if($script:mode -eq 'token-drift' -and $script:contextReads -gt 1){$token='22'*56}
 [pscustomobject][ordered]@{Computer='TEST';HostKey='20348';Reader=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1000';TokenStatistics=$token};Service='Running'}
}
function Read-WelaWecStateDefinition {
 param($Id,$SourceSids)
 $script:reads++
 if($script:mode -eq 'drift' -and $script:reads -eq 2){$script:xml=$script:xml.Replace('MinLatency','Normal')}
 if($script:mode -eq 'denied'){throw 'Native access denied'}
 Get-WelaWecStateDefinition $script:xml $SourceSids
}
function Read-WelaWecStateRuntime {param($Id);[pscustomobject]@{Status='Unknown';Diagnostic='Runtime unavailable';ReadyRuleCredit=0}}
function New-WelaWecStateEdit {
 param($Before)
 $edit=[pscustomobject]@{SaveAttempted=$false}
 $edit|Add-Member ScriptMethod Save {param($Enabled)
  Assert (Test-Path -LiteralPath $script:journal) 'Durable pending record precedes native save'
  $pending=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText($script:journal))
  Assert ($pending.Status -ceq 'Pending' -and $pending.DesiredEnabled -eq $Enabled) 'Pending receipt names exact desired state'
  if($script:mode -eq 'native-refusal'){throw 'Native view changed before save'}
  $this.SaveAttempted=$true;$script:saves++
  if($script:mode -eq 'failure'){throw 'native save failed'}
  if($script:mode -eq 'false-success'){return}
  $doc=Read-WelaWefXml $script:xml;$doc.Subscription.Enabled=$Enabled.ToString().ToLowerInvariant()
  if($script:mode -eq 'preservation'){$doc.Subscription.ReadExistingEvents='true'}
  $script:xml=$doc.OuterXml
  if($script:mode -eq 'evidence-tamper'){[IO.File]::AppendAllText($script:journal,' ')}
 }
 $edit|Add-Member ScriptMethod Dispose {}
 $edit
}
try {
 $before=Get-WelaWecStateDefinition $base @($sid)
 Assert (-not $before.Enabled -and $before.Id -ceq $id) 'Disabled original parsed'
 $enabled=Get-WelaWecStateDefinition ($base.Replace('<Enabled>false','<Enabled>true')) @($sid)
 Assert ($enabled.Enabled -and $enabled.PreservedKey -ceq $before.PreservedKey -and $enabled.WholeKey -cne $before.WholeKey) 'Only Enabled excluded from preservation comparison'
 Reject {Get-WelaWecStateDefinition $base @('S-1-1-0')} 'SID'
 Reject {Get-WelaWecStateDefinition ($base.Replace('Path="Security"','Path="Microsoft-Windows-Sysmon/Operational"')) @($sid)} 'Sysmon'
 Reject {Get-WelaWecStateDefinition ($base.Replace('SourceInitiated','CollectorInitiated')) @($sid)} 'source-initiated'
 Reject {Get-WelaWecStateDefinition ($base.Replace('<Enabled>false</Enabled>','<Enabled>false</Enabled><Enabled>true</Enabled>')) @($sid)} 'duplicate'
 Reject {Invoke-WelaWecState -Id $id -SourceSids @($sid) -OutputPath (Join-Path $root 'invalid')} 'Plan requires'
 Reject {Invoke-WelaWecState -Action Apply -PlanPath missing -PlanHash ('a'*64) -State Enabled -OutputPath (Join-Path $root 'invalid')} 'only'
 foreach($scenario in @('ok','drift','token-drift','failure','false-success','preservation','hash','stale','context','duplicate-key','wrong-type','source-hash','denied','native-refusal','evidence-tamper')){
  $script:xml=$base;$script:mode='ok';$script:reads=0;$script:contextReads=0;$script:saves=0
  $planResult=Invoke-WelaWecState -Id $id -SourceSids @($sid) -State Enabled -OutputPath (Join-Path $root ($scenario+'-plan'))
  Assert ($planResult.ExitCode -eq 0 -and $planResult.Status -eq 'ReviewRequired') "Plan created: $($planResult.Diagnostic)"
  Assert ($script:saves -eq 0 -and -not $planResult.BeforeEnabled -and $planResult.DesiredEnabled) 'Plan is read only and states exact transition'
  $planPath=Join-Path $planResult.OutputPath 'plan.json';$hash=$planResult.PlanHash
  $script:mode=$scenario;$script:reads=0;$script:contextReads=0
  if($scenario -eq 'hash'){$hash='b'*64}
  if($scenario -eq 'stale'){$script:xml=$base.Replace('MinLatency','Normal')}
  if($scenario -in @('context','duplicate-key','wrong-type','source-hash')){
   $text=[IO.File]::ReadAllText($planPath)
   switch($scenario){
    context {$text=$text.Replace('TEST','OTHER')}
    duplicate-key {$text=$text.Replace('"SchemaVersion":','"SchemaVersion": 1, "SchemaVersion":')}
    wrong-type {$text=$text.Replace('"DesiredEnabled": true','"DesiredEnabled": "true"')}
    source-hash {$text=$text.Replace('scripts/WecState.ps1','scripts/Untrusted.ps1')}
   }
   [IO.File]::WriteAllText($planPath,$text);$hash=(Get-FileHash $planPath).Hash.ToLowerInvariant()
  }
  $out=Join-Path $root ($scenario+'-apply');$script:journal=Join-Path $out 'before-save.json'
  $result=Invoke-WelaWecState Apply -PlanPath $planPath -PlanHash $hash -OutputPath $out
  Assert (($result.ExitCode -eq 0) -eq ($scenario -eq 'ok')) "Scenario $scenario : $($result.Diagnostic)"
  Assert ($result.ReadyRuleCredit -eq 0 -and $result.BookmarkContinuity -eq 'Not established') 'No delivery/bookmark/Sigma credit'
  Assert (Test-Path (Join-Path $out 'manifest.json')) 'Result retained'
  if($scenario -in @('drift','token-drift','hash','stale','context','duplicate-key','wrong-type','source-hash','denied','native-refusal')){Assert ($script:saves -eq 0 -and -not $result.NativeSaveAttempted) 'Rejected before native save'}
  if($scenario -in @('failure','false-success','preservation','evidence-tamper')){Assert ($result.Status -eq 'SaveAttemptedUnverified' -and $result.NativeSaveAttempted) 'Partial failure remains explicit'}
  if($scenario -eq 'ok'){
   $after=Get-WelaWecStateDefinition $script:xml @($sid)
   Assert ($after.PreservedKey -ceq $before.PreservedKey -and $after.Enabled -and $result.Status -eq 'StateChangedAndVerified') 'Only Enabled changed'
   Assert ($result.RuntimeAfter.Status -eq 'Unknown') 'Unknown runtime does not become healthy or invalidate observed configuration'
  }
 }
 foreach($desired in @('Enabled','Disabled')){
  $script:mode='ok';$script:xml=if($desired -eq 'Disabled'){$base}else{$base.Replace('<Enabled>false','<Enabled>true')};$script:saves=0
  $planResult=Invoke-WelaWecState -Id $id -SourceSids @($sid) -State $desired -OutputPath (Join-Path $root ($desired+'-same-plan'))
  $result=Invoke-WelaWecState Apply -PlanPath (Join-Path $planResult.OutputPath 'plan.json') -PlanHash $planResult.PlanHash -OutputPath (Join-Path $root ($desired+'-same-apply'))
  Assert ($result.Status -eq 'AlreadyMatches' -and $result.ExitCode -eq 0 -and $script:saves -eq 0) 'Idempotent enabled/disabled state never saves/reactivates'
 }
 $script:xml=$base.Replace('<Enabled>false','<Enabled>true');$script:saves=0
 $planResult=Invoke-WelaWecState -Id $id -SourceSids @($sid) -State Disabled -OutputPath (Join-Path $root 'disable-plan')
 $out=Join-Path $root 'disable-apply';$script:journal=Join-Path $out 'before-save.json'
 $result=Invoke-WelaWecState Apply -PlanPath (Join-Path $planResult.OutputPath 'plan.json') -PlanHash $planResult.PlanHash -OutputPath $out
 Assert ($result.ExitCode -eq 0 -and $result.BeforeEnabled -and -not $result.DesiredEnabled -and (Get-WelaWecStateDefinition $script:xml @($sid)).WholeKey -ceq $before.WholeKey) 'Explicit disable restores exact original XML semantics'
 Reject {Invoke-WelaWecState -Id $id -SourceSids @($sid) -State Disabled -OutputPath $root} 'new directory'
 $one=Get-WelaWecStateContext;$two=Get-WelaWecStateContext;$two.Reader.TokenStatistics=('22'*8)+$two.Reader.TokenStatistics.Substring(16)
 Assert ((Get-WelaWecStateReviewKey $one) -ceq (Get-WelaWecStateReviewKey $two)) 'Different token objects in the same logon can use a reviewed plan'
 $two.Reader.TokenStatistics='22'*56
 Assert ((Get-WelaWecStateReviewKey $one) -cne (Get-WelaWecStateReviewKey $two)) 'Different actual logon cannot reuse a reviewed plan'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "WEC state tests passed: $count assertions."
