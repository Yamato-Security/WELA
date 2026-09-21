$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/WecListener.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern='.'){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected refusal $Pattern, got: $message; input: $bad; action: $Action"}
function Copy-TestListener($Value){Get-WelaListenerKey $Value|ConvertFrom-Json}
$selection=Get-WelaListenerSelection 'test-host' '192.0.2.10'
$xml='<cfg:Listener xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config/listener" xml:lang="en-US"><cfg:Address>IP:192.0.2.10</cfg:Address><cfg:Transport>HTTP</cfg:Transport><cfg:Port>5985</cfg:Port><cfg:Hostname/><cfg:Enabled>true</cfg:Enabled><cfg:URLPrefix>wsman</cfg:URLPrefix><cfg:CertificateThumbprint/><cfg:ListeningOn>192.0.2.10</cfg:ListeningOn></cfg:Listener>'
Assert ($selection.ComputerName -ceq 'TEST-HOST') 'Actual computer selection is canonical.'
foreach($bad in @('*','IP:192.0.2.10','192.0.2.10/32','192.0.2.0/24','192.0.2.01','010.1.2.3','127.0.0.1','0.0.0.0','169.254.1.2','224.0.0.1','255.255.255.255','256.1.2.3','1.2.3','example.test','::1','',' 192.0.2.10')){Reject {Get-WelaListenerSelection 'TEST' $bad}}
foreach($bad in @('','test.example','*','-TEST','TEST HOST','TEST/OTHER')){Reject {Get-WelaListenerSelection $bad '192.0.2.10'}}
Reject {Get-WelaListenerSelection $true '192.0.2.10'};Reject {Get-WelaListenerSelection 'TEST' $true}
$listener=ConvertFrom-WelaListenerXml $xml;Assert-WelaListenerCreated $listener $selection;$count++
Assert ($listener.ListeningOn.Count -eq 1 -and -not $listener.PolicyOwned) 'Actual native shape has exact address and local provenance.'
foreach($bad in @($xml.Replace('<cfg:Port>5985</cfg:Port>',''),$xml.Replace('</cfg:Listener>','<cfg:Enabled>true</cfg:Enabled></cfg:Listener>'),$xml.Replace('cfg:Port','cfg:Unknown'),$xml.Replace('http://schemas.microsoft.com/wbem/wsman/1/config/listener','urn:wrong'),$xml.Replace('<cfg:Hostname/>','<cfg:Hostname unexpected="x"/>'),$xml.Replace('<cfg:Hostname/>','<cfg:Hostname><cfg:Nested/></cfg:Hostname>'),$xml.Replace('<cfg:Hostname/>','<?unexpected data?><cfg:Hostname/>'),$xml.Replace('>true<','>True<'),$xml.Replace('>5985<','>05985<'),$xml.Replace('</cfg:Listener>','<cfg:ListeningOn>192.0.2.10</cfg:ListeningOn></cfg:Listener>'),$xml.Replace('>192.0.2.10<','>not-an-address<'),('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///does-not-exist">]>'+$xml))){Reject {ConvertFrom-WelaListenerXml $bad}}
foreach($name in @('Address','Transport','Port','Hostname','Enabled','URLPrefix','CertificateThumbprint')){$copy=Copy-TestListener $listener;$copy.$name='unexpected';Reject {Assert-WelaListenerCreated $copy $selection} 'differs'}
$copy=Copy-TestListener $listener;$copy.ListeningOn=@('192.0.2.10','192.0.2.11');Reject {Assert-WelaListenerCreated $copy $selection} 'exactly'
$copy=Copy-TestListener $listener;$copy.PolicyOwned=$true;Reject {Assert-WelaListenerCreated $copy $selection} 'local'
$copy=Copy-TestListener $listener;$copy.PolicyOwned='False';Reject {Assert-WelaListenerCreated $copy $selection} 'local'
$owned=ConvertFrom-WelaListenerXml ($xml.Replace('<cfg:Port>','<cfg:Port Source="GPO">'));Assert $owned.PolicyOwned 'Native GPO provenance remains explicit.'
Reject {Assert-WelaListenerAbsent @($listener) $selection} 'Existing'
$copy=Copy-TestListener $listener;$copy.Address='*';$copy.Port='6000';Reject {Assert-WelaListenerAbsent @($copy) $selection} 'Existing'
$copy=Copy-TestListener $listener;$copy.Address='IP:192.0.2.11';Reject {Assert-WelaListenerAbsent @($copy) $selection} 'Existing'
$copy=Copy-TestListener $listener;$copy.Port='6000';Reject {Assert-WelaListenerAbsent @($copy) $selection} 'Existing'
$other=Copy-TestListener $listener;$other.Address='*';$other.Transport='HTTPS';$other.Port='5986';$other.ListeningOn=@('192.0.2.10');Assert-WelaListenerAbsent @($other) $selection;$count++
$reader=[pscustomobject][ordered]@{Computer='TEST-HOST';ProcessId=100;UserSid='S-1-5-21-1-2-3-1001';UserName='TEST-HOST\operator';TokenId='111';ModifiedId='222';AuthenticationId='333';GroupSids=@('S-1-5-32-544');GroupCount=1;PrivilegeCount=20;ElevatedAdministrator=$true;TokenType='Primary';Impersonation='Absent'}
$baseline=[pscustomobject][ordered]@{Local=[pscustomobject][ordered]@{Host=@{Computer='TEST-HOST';Build=26100;UBR=123;ProductType=3;DomainRole=2};MachineGuid='00000000-0000-0000-0000-000000000001';Reader=$reader;Services=@(@{Name='WinRM';State='Running';StartMode='Auto'});Addresses=@(@{IPAddress='192.0.2.10';AddressState='Preferred'});Policy='empty';WinrmXml='<Config/>';Listeners=@($other)};Profiles=@('protected');Rules=@('digest');NativeFirewall='native';NativeReader='native-reader';Adapter=@{Engine='native51';EngineSha256='a'*64;Worker='fixed-worker';WorkerSha256='b'*64};Sources='sources'}
$changed=Copy-TestListener $baseline;$changed.Local.Reader.ProcessId=101;$changed.Local.Reader.TokenId='different';$changed.Local.Reader.ModifiedId='other';Assert ((Get-WelaListenerReviewKey $changed) -ceq (Get-WelaListenerReviewKey $baseline)) 'Plans permit separate processes in the same actual logon.'
$changed.Local.Reader.AuthenticationId='444';Assert ((Get-WelaListenerReviewKey $changed) -cne (Get-WelaListenerReviewKey $baseline)) 'Different logon requires a new plan.'
Assert-WelaListenerSelectedHost $baseline.Local $selection;$count++
$changed=Copy-TestListener $baseline;$changed.Local.Addresses[0].AddressState='Tentative';Reject {Assert-WelaListenerSelectedHost $changed.Local $selection} 'Preferred'
$changed=Copy-TestListener $baseline;$changed.Local.Host.Computer='OTHER';Reject {Assert-WelaListenerSelectedHost $changed.Local $selection} 'actual'
$plan=[pscustomobject]@{SchemaVersion=1;Kind='WelaExactIpListenerPlan';Selection=$selection;StateKey=(Get-WelaListenerReviewKey $baseline);RecordedUtc='2026-09-21T00:00:00Z'};Assert-WelaListenerPlan $plan;$count++
foreach($field in @('SchemaVersion','Kind','StateKey')){$bad=Copy-TestListener $plan;$bad.$field=$true;Reject {Assert-WelaListenerPlan $bad} 'mistyped'}
$bad=Copy-TestListener $plan;$bad.Selection.ComputerName='test-host';Reject {Assert-WelaListenerPlan $bad} 'canonical'
$bad=Copy-TestListener $plan;$bad|Add-Member NoteProperty Extra true;Reject {Assert-WelaListenerPlan $bad}
Initialize-WelaListenerPipe
$textReader=[IO.StringReader]::new('bounded');try{$task=[Wela.ListenerPipe.Bounded]::Read($textReader,7);Assert ($task.GetAwaiter().GetResult() -ceq 'bounded') 'Bounded stream reads complete content.'}finally{$textReader.Dispose()}
$textReader=[IO.StringReader]::new('x'*65536);try{Reject {$task=[Wela.ListenerPipe.Bounded]::Read($textReader,1024);$task.GetAwaiter().GetResult()} 'bound'}finally{$textReader.Dispose()}
foreach($failure in @('kill','wait','dispose')){
 $fake=[pscustomobject]@{HasExited=$false;Mode=$failure}
 $fake|Add-Member ScriptMethod Kill {if($this.Mode -eq 'kill'){throw 'Natural-exit race'}}
 $fake|Add-Member ScriptMethod WaitForExit {param($Timeout);if($this.Mode -eq 'wait'){throw 'Wait failed'};return $true}
 $fake|Add-Member ScriptMethod Dispose {if($this.Mode -eq 'dispose'){throw 'Dispose failed'}}
 $result=[pscustomobject]@{Started=$true;TerminationConfirmed=$false;Diagnostic=''};Close-WelaListenerAdapterProcess $fake $result
 Assert ($result.Started -and $result.Diagnostic) "Possible creation remains recorded after $failure cleanup failure."
 Assert ($result.TerminationConfirmed -eq ($failure -ne 'wait')) 'Termination certainty is separately retained.'
}
$receipt=[pscustomobject]@{SchemaVersion=1;Kind='WelaNative51ListenerCreate';Status='Created';NativeCreateAttempted=$true;ProcessId=123;Engine='native51';EngineVersion='5.1.26100.1';Reader=$reader;Selection=$selection;CreatedXml='<EPR/>';After=@($listener);Diagnostic='';NativeHResult=$null}
Assert-WelaListenerAdapterReceipt $receipt $baseline 123 0;$count++
foreach($field in @('Kind','Engine','EngineVersion','Status','ProcessId','SchemaVersion')){$bad=Copy-TestListener $receipt;$bad.$field=$true;Reject {Assert-WelaListenerAdapterReceipt $bad $baseline 123 0} 'identity|status'}
$bad=Copy-TestListener $receipt;$bad.Reader.AuthenticationId='OTHER';Reject {Assert-WelaListenerAdapterReceipt $bad $baseline 123 0} 'logon'
Reject {Assert-WelaListenerAdapterReceipt $receipt $baseline 124 0} 'identity'
Reject {Assert-WelaListenerAdapterReceipt $receipt $baseline 123 1} 'success'
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-listener-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$script:mode='ok';$script:reads=0;$script:starts=0;$script:created=$false
function Get-WelaListenerState {
 $script:reads++;$state=Copy-TestListener $baseline
 if($script:created){$state.Local.Listeners=@((Copy-TestListener $other),(Copy-TestListener $listener))}
 if($script:mode -eq 'race' -and $script:reads -eq 2){$state.Local.WinrmXml='<Changed/>'}
 if($script:created -and $script:mode -eq 'firewall-drift'){$state.Rules=@('changed')}
 if($script:created -and $script:mode -eq 'token-drift'){$state.Local.Reader.ModifiedId='changed'}
 if($script:created -and $script:mode -eq 'broader'){$state.Local.Listeners[1].ListeningOn=@('192.0.2.10','192.0.2.11')}
 $state
}
function Start-WelaListenerAdapter {
 param($State,$RequestPath,$RequestHash)
 $script:starts++;$dir=Split-Path $RequestPath -Parent
 $intent=Get-Content (Join-Path $dir 'before-create.json') -Raw|ConvertFrom-Json
 Assert ($intent.Status -ceq 'Pending' -and (Read-WelaWecUpdateFile $RequestPath).Hash -ceq $RequestHash -and (Get-Content (Join-Path $dir 'native-payload.xml') -Raw) -ceq (New-WelaListenerPayload)) 'Durable intent and fixed payload precede adapter startup.'
 if($script:mode -eq 'timeout'){return [pscustomobject]@{Started=$true;Receipt=$null;Diagnostic='timeout';TerminationConfirmed=$false}}
 $reply=Copy-TestListener $receipt
 if($script:mode -eq 'refused'){$reply.Status='Refused';$reply.NativeCreateAttempted=$false;$reply.Diagnostic='fresh worker context differs'}else{$script:created=$true}
 if($script:mode -eq 'native-error'){$reply.Status='CreateAttemptedUnverified';$reply.Diagnostic='native failed'}
 [pscustomobject]@{Started=$true;Receipt=$reply;Diagnostic=$(if($script:mode -eq 'cleanup-error'){'cleanup failed'}else{''});TerminationConfirmed=$true}
}
try {
 foreach($scenario in @('ok','hash','schema','duplicate-json','context','race','refused','timeout','native-error','firewall-drift','token-drift','broader','cleanup-error','replay')){
  $script:mode='ok';$script:reads=0;$script:starts=0;$script:created=$false
  $planned=Invoke-WelaWecListener -ComputerName 'TEST-HOST' -LocalAddress '192.0.2.10' -OutputPath (Join-Path $root ($scenario+'-plan'))
  Assert ($planned.Status -ceq 'ReviewRequired' -and $planned.ExitCode -eq 0 -and $script:starts -eq 0) "Plan reads only: $($planned.Diagnostic)"
  $path=Join-Path $planned.OutputPath 'plan.json';$hash=$planned.PlanHash
  if($scenario -eq 'hash'){$hash='f'*64}
  if($scenario -in @('schema','duplicate-json','context')){
   $text=[IO.File]::ReadAllText($path)
   if($scenario -eq 'schema'){$text=$text.Replace('"SchemaVersion": 1','"SchemaVersion": true')}
   if($scenario -eq 'duplicate-json'){$text=$text.Replace('"SchemaVersion":','"SchemaVersion":1,"SchemaVersion":')}
   if($scenario -eq 'context'){$text=$text.Replace('TEST-HOST','OTHER-HOST')}
   [IO.File]::WriteAllText($path,$text);$hash=(Get-FileHash $path).Hash.ToLowerInvariant()
  }
  $script:mode=$scenario;$script:reads=0;$applied=Invoke-WelaWecListener Apply -PlanPath $path -PlanHash $hash -OutputPath (Join-Path $root ($scenario+'-apply'))
  Assert (($applied.ExitCode -eq 0) -eq ($scenario -in @('ok','replay'))) "Outcome $scenario : $($applied.Diagnostic)"
  Assert ($applied.ReadyRuleCredit -eq 0 -and $applied.ServiceChanges -eq 0 -and $applied.FirewallChanges -eq 0 -and (Test-Path (Join-Path $applied.OutputPath 'manifest.json'))) 'No unrelated changes or detection credit; final receipt retained.'
  foreach($artifact in $applied.Artifacts){Assert ((Get-FileHash (Join-Path $applied.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Receipt artifact hash matches actual bytes.'}
  if($scenario -in @('hash','schema','duplicate-json','context','race')){Assert ($script:starts -eq 0 -and $applied.Status -ceq 'Refused') 'Refusal precedes any adapter start.'}
  if($scenario -in @('timeout','native-error','firewall-drift','token-drift','broader','cleanup-error')){Assert ($applied.AdapterStarted -and $applied.Status -ceq 'CreateAttemptedUnverified') 'Possible native creation is never mislabeled Refused.'}
  if($scenario -eq 'refused'){Assert ($applied.Status -ceq 'Refused' -and $applied.NativeCreateAttempted -eq $false) 'Authenticated native refusal before create stays distinct.'}
  if($scenario -eq 'replay'){$again=Invoke-WelaWecListener Apply -PlanPath $path -PlanHash $hash -OutputPath (Join-Path $root 'replay-again');Assert ($again.Status -ceq 'Refused' -and $script:starts -eq 1) 'Applied plan cannot be replayed.'}
 }
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count focused WEC listener assertions. No native listener proof is claimed."
