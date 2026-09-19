$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
Add-Type -Path "$repo/scripts/WecUpdateNative.cs" -ErrorAction Stop
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-wec-update-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$sid='S-1-5-21-11-22-33-1001';$id='WELA Native Security Example'
$base=[IO.File]::ReadAllText("$repo/config/wef-examples/native-security.xml").Replace('<Enabled>true</Enabled>','<Enabled>false</Enabled>').Replace('<AllowedSourceDomainComputers></AllowedSourceDomainComputers>',('<AllowedSourceDomainComputers>'+(Get-WelaWefAuthorization @($sid))+'</AllowedSourceDomainComputers>'))
$query='<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4625)]]</Select></Query></QueryList>'
$queryPath=Join-Path $root 'query.xml';[IO.File]::WriteAllText($queryPath,$query)
$script:xml=$base;$script:saves=0;$script:reads=0;$script:mode='ok';$script:journal=''
function Get-WelaWecUpdateContext {[pscustomobject][ordered]@{Computer='TEST';HostKey='20348';Reader='S-1-5-21-1-2-3-1000';Service='Running'}}
function Read-WelaWecUpdateDefinition {param($Id,$SourceSids);$script:reads++;if($script:mode -eq 'drift' -and $script:reads -eq 2){$script:xml=$script:xml.Replace('MinLatency','Normal')};Get-WelaWecUpdateDefinition $script:xml $SourceSids}
function New-WelaWecUpdateEdit {
 param($Before)
 $edit=New-Object psobject
 $edit|Add-Member ScriptMethod Save {param($Query,$Description)
  Assert (Test-Path -LiteralPath $script:journal) 'Durable before-save record precedes mutation'
  $script:saves++
  if($script:mode -eq 'failure'){throw 'native save failed'}
  if($script:mode -eq 'false-success'){return}
  $doc=Read-WelaWefXml $script:xml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s',$doc.DocumentElement.NamespaceURI);$doc.SelectSingleNode('/s:Subscription/s:Query',$ns).InnerText=[string]$Query;$doc.SelectSingleNode('/s:Subscription/s:Description',$ns).InnerText=[string]$Description
  if($script:mode -eq 'preservation'){$doc.Subscription.ReadExistingEvents='true'}
  $script:xml=$doc.OuterXml
 }
 $edit|Add-Member ScriptMethod Dispose {}
 $edit
}
try {
 $before=Get-WelaWecUpdateDefinition $base @($sid);Assert ($before.Id -ceq $id) 'Original parsed'
 $formatted=$query.Replace('><',">`r`n  <")
 Assert ((ConvertFrom-WelaWefQuery $formatted).Key -ceq (ConvertFrom-WelaWefQuery $query).Key) 'Formatted native query XML preserves semantic selection'
 Assert ((ConvertFrom-WelaWefQuery $formatted.Replace('4625','4624')).Key -cne (ConvertFrom-WelaWefQuery $query).Key) 'Different event selection changes the semantic key'
 Reject {Get-WelaWecUpdateDefinition ($base.Replace('<Enabled>false','<Enabled>true')) @($sid)} 'disabled'
 Reject {Get-WelaWecUpdateDefinition $base @('S-1-1-0')} 'SID'
 Reject {ConvertFrom-WelaWefQuery ($query.Replace('Security','Microsoft-Windows-Sysmon/Operational'))} 'Sysmon'
 Reject {Invoke-WelaWecUpdate -Action Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -OutputPath (Join-Path $root 'invalid')} 'description'
 Reject {Invoke-WelaWecUpdate -Action Apply -PlanPath missing -PlanHash ('a'*64) -Description accidental -OutputPath (Join-Path $root 'invalid')} 'only'
 foreach($scenario in @('ok','drift','failure','false-success','preservation','hash','stale','context','duplicate-key','enabled')){
  $script:xml=$base;$script:mode='ok';$script:reads=0;$script:saves=0
  $planResult=Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description 'Reviewed change' -OutputPath (Join-Path $root ($scenario+'-plan'))
  Assert ($planResult.ExitCode -eq 0 -and $planResult.Status -eq 'ReviewRequired') "Plan created: $($planResult.Diagnostic)"
  Assert ($script:saves -eq 0) 'Plan never saves'
  $planPath=Join-Path $planResult.OutputPath 'plan.json';$hash=$planResult.PlanHash
  $script:mode=$scenario;$script:reads=0
  if($scenario -eq 'hash'){$hash='b'*64}
  if($scenario -eq 'stale'){$script:xml=$base.Replace('MinLatency','Normal')}
  if($scenario -eq 'enabled'){$script:xml=$base.Replace('<Enabled>false','<Enabled>true')}
  if($scenario -in @('context','duplicate-key')){$text=[IO.File]::ReadAllText($planPath);if($scenario -eq 'context'){$text=$text.Replace('TEST','OTHER')}else{$text=$text.Replace('"SchemaVersion":','"SchemaVersion": 1, "SchemaVersion":')};[IO.File]::WriteAllText($planPath,$text);$hash=(Get-FileHash $planPath).Hash.ToLowerInvariant()}
  $out=Join-Path $root ($scenario+'-apply');$script:journal=Join-Path $out 'before-save.json'
  $result=Invoke-WelaWecUpdate Apply -PlanPath $planPath -PlanHash $hash -OutputPath $out
  Assert (($result.ExitCode -eq 0) -eq ($scenario -eq 'ok')) "Scenario $scenario : $($result.Diagnostic)"
  Assert ($result.ReadyRuleCredit -eq 0) 'No Sigma credit'
  Assert (Test-Path (Join-Path $out 'manifest.json')) 'Result retained'
  if($scenario -in @('drift','hash','stale','context','duplicate-key','enabled')){Assert ($script:saves -eq 0) 'Rejected before save'}
  if($scenario -in @('failure','false-success','preservation')){Assert ($result.Status -eq 'SaveAttemptedUnverified' -and $result.NativeSaveAttempted) 'Partial failure reported honestly'}
  if($scenario -eq 'ok'){$after=Get-WelaWecUpdateDefinition $script:xml @($sid);Assert ($after.PreservedKey -ceq $before.PreservedKey -and $after.Description -ceq 'Reviewed change' -and $after.QueryKey -ceq (ConvertFrom-WelaWefQuery $query).Key) 'Only two properties changed'}
 }
 # Replanning an already matching disabled subscription produces no mutation.
 $script:mode='ok';$script:xml=$base;$script:saves=0;$old=Get-WelaWecUpdateDefinition $base @($sid)
 [IO.File]::WriteAllText($queryPath,$old.QueryXml)
 $planResult=Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description $old.Description -OutputPath (Join-Path $root 'same-plan')
 $result=Invoke-WelaWecUpdate Apply -PlanPath (Join-Path $planResult.OutputPath 'plan.json') -PlanHash $planResult.PlanHash -OutputPath (Join-Path $root 'same-apply')
 Assert ($result.Status -eq 'AlreadyMatches' -and $result.ExitCode -eq 0 -and $script:saves -eq 0) 'Idempotence is read only'
 Reject {Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description '' -OutputPath $root} 'new directory'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "WEC update tests passed: $count assertions."
