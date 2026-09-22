$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $script:ScriptRoot 'modules/WefSubscriptions.psm1') -Force
foreach($name in @('WefArrival','WecUpdate','ChannelRead','WefQuery')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
$script:count=0
function Assert($value,[string]$message){if(-not $value){throw $message};$script:count++}
function Reject([scriptblock]$code,[string]$message){$caught=$false;try{& $code|Out-Null}catch{$caught=$true};Assert $caught $message}
function Clone($value){ConvertFrom-WelaArrivalJson (Get-WelaWefQueryKey $value)}
Initialize-WelaWefQueryNative
$nativeToken=[Wela.WefQueryToken.Token]::new();$nativeToken.Sid='S-1-5-21-1-2-3-1000';$nativeToken.Name='Host\reader';$nativeToken.AuthenticationId='0x123';$nativeToken.AuthenticationType='NTLM';$nativeToken.ImpersonationLevel='None';$nativeToken.TokenSource='Process'
$nativeGroup=[Wela.WefQueryToken.Group]::new();$nativeGroup.Sid='S-1-5-32-545';$nativeGroup.Attributes=[uint32]::MaxValue;$nativeToken.Groups=@($nativeGroup);$nativeToken.Privileges=@()
$observedToken=ConvertTo-WelaWefQueryTokenObservation $nativeToken
Assert ($observedToken -is [pscustomobject] -and $observedToken.Groups -is [array] -and $observedToken.Groups.Count -eq 1 -and $observedToken.Privileges -is [array] -and $observedToken.Privileges.Count -eq 0) 'Actual native DTO normalizes singleton groups and empty privileges for strict receipt validation.'
Assert ($observedToken.Groups[0].Attributes -eq [uint32]::MaxValue -and (Get-WelaWefQueryTokenKey $observedToken) -ceq (Get-WelaWefQueryTokenKey (Clone $nativeToken))) 'Native token normalization preserves every unsigned attribute and token comparison.'
$nativePrivilege=[Wela.WefQueryToken.Privilege]::new();$nativePrivilege.Luid='0x14';$nativePrivilege.Attributes=2;$nativeToken.Privileges=@($nativePrivilege)
Assert ((ConvertTo-WelaWefQueryTokenObservation $nativeToken).Privileges[0].Attributes -eq 2) 'Native privilege DTO normalizes without losing enabled attributes.'
$nativeToken.Sid='invalid';Reject {ConvertTo-WelaWefQueryTokenObservation $nativeToken} 'Invalid native token remains unverified.'
Reject {ConvertTo-WelaWefQueryTokenObservation $observedToken} 'Native boundary rejects a substituted arbitrary object.'
$buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal(128)
try{
 function Reset-Buffer([int]$type,[int]$count){for($i=0;$i -lt 128;$i++){[Runtime.InteropServices.Marshal]::WriteByte($buffer,$i,0)};[Runtime.InteropServices.Marshal]::WriteInt32($buffer,12,$type);[Runtime.InteropServices.Marshal]::WriteInt32($buffer,8,$count);[Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,[IntPtr]::Add($buffer,16))}
 Reset-Buffer 136 2;[Runtime.InteropServices.Marshal]::WriteInt32($buffer,16,0);[Runtime.InteropServices.Marshal]::WriteInt32($buffer,20,-1)
 $values=[Wela.WefQuery.Native]::DecodeStatuses($buffer,24);Assert ($values.Count -eq 2 -and $values[1] -eq [uint32]::MaxValue) 'Native EVT UInt32 status preserves unsigned errors.'
 foreach($type in @(2,8,130,129,264)){Reset-Buffer $type 1;Reject {[Wela.WefQuery.Native]::DecodeStatuses($buffer,24)} "Reject wrong status variant $type"}
 Reset-Buffer 136 129;Reject {[Wela.WefQuery.Native]::DecodeStatuses($buffer,128)} 'Status count cap.'
 Reset-Buffer 136 2;Reject {[Wela.WefQuery.Native]::DecodeStatuses($buffer,20)} 'Status pointer cannot exceed used bytes.'
 Reset-Buffer 136 1;[Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,[IntPtr]::Add($buffer,8));Reject {[Wela.WefQuery.Native]::DecodeStatuses($buffer,24)} 'Status pointer cannot overlap header.'
 Reset-Buffer 129 1;[Runtime.InteropServices.Marshal]::WriteIntPtr($buffer,16,[IntPtr]::Add($buffer,32));$text=[Text.Encoding]::Unicode.GetBytes('System'+[char]0);[Runtime.InteropServices.Marshal]::Copy($text,0,[IntPtr]::Add($buffer,32),$text.Length)
 Assert ([Wela.WefQuery.Native]::DecodeNames($buffer,46)[0] -ceq 'System') 'Native string-array pointer and UTF16.'
 Reject {[Wela.WefQuery.Native]::DecodeNames($buffer,44)} 'Unterminated names refuse.'
 [Runtime.InteropServices.Marshal]::WriteInt16($buffer,32,[int16]-10240);Reject {[Wela.WefQuery.Native]::DecodeNames($buffer,46)} 'Unpaired Unicode surrogate refuses.'
 foreach($used in @(0,15,1048577)){Reject {[Wela.WefQuery.Native]::DecodeNames($buffer,$used)} "Invalid buffer length $used"}
}finally{[Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)}
$result=[pscustomobject]@{Opened=$true;Complete=$true;Capped=$false;CleanupConfirmed=$true;NativeError=$null;Diagnostic='';Channels=@([pscustomobject]@{Channel='System';Error=0});DiagnosticChannels=@();DiagnosticNativeError=$null;Events=@()}
Assert-WelaWefQueryNativeResult $result @('System') 16;Assert $true 'Complete empty strict result valid.'
foreach($field in @('Opened','Complete','Capped','CleanupConfirmed')){$copy=Clone $result;$copy.$field='true';Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} "Typed Boolean $field"}
foreach($field in @('NativeError','DiagnosticNativeError')){$copy=Clone $result;$copy.$field=$true;Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} "Typed native code $field"}
$copy=Clone $result;$copy.Channels=@();Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} 'Missing native per-channel provenance.'
$copy=Clone $result;$copy.Channels[0].Channel='Application';Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} 'Unexpected native channel.'
$copy=Clone $result;$copy.Channels[0].Error=$true;Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} 'Boolean error rejected.'
foreach($field in @('Capped','Diagnostic','NativeError','CleanupConfirmed')){$copy=Clone $result;switch($field){Capped{$copy.Capped=$true};Diagnostic{$copy.Diagnostic='failure'};NativeError{$copy.NativeError=5};CleanupConfirmed{$copy.CleanupConfirmed=$false}};Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} "Completeness cannot coexist with $field"}
$failure=Clone $result;$failure.Opened=$false;$failure.Complete=$false;$failure.NativeError=15001;$failure.Channels=@();$failure.DiagnosticChannels=@([pscustomobject]@{Channel='System';Error=15001})
Assert-WelaWefQueryNativeResult $failure @('System') 16;Assert $true 'Failed strict query retains separate diagnostic errors.'
$failure.Events=@('<Event/>');Reject {Assert-WelaWefQueryNativeResult $failure @('System') 16} 'Diagnostic records cannot become matches.'
$copy=Clone $result;$copy.Events=@($true);Reject {Assert-WelaWefQueryNativeResult $copy @('System') 16} 'Typed XML required.'
$copy=Clone $result;$copy.Events=@('x','y');Reject {Assert-WelaWefQueryNativeResult $copy @('System') 1} 'Event bound enforced.'
$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Native"/><EventID>1</EventID><EventRecordID>42</EventRecordID><Channel>System</Channel><Computer>Host.example.test</Computer><TimeCreated SystemTime="2026-01-01T00:00:00.1234567Z"/></System><EventData><Data>日本語 Ω &amp; value</Data></EventData></Event>'
$hostContext=[pscustomobject]@{Computer='Host';DnsHostName='Host';DnsSuffix='example.test'}
$event=Read-WelaWefQueryEvent $xml @('System') $hostContext;Assert ($event.RecordId -eq 42 -and $event.Channel -ceq 'System') 'Native event selected channel/local host provenance.'
foreach($bad in @($xml.Replace('<Channel>System','<Channel>Application'),$xml.Replace('Host.example.test','Other.example.test'),$xml.Replace('Host.example.test','Host.unrelated.test'),$xml.Replace('<EventRecordID>42</EventRecordID>',''),$xml.Replace('<EventID>1</EventID>','<EventID>1</EventID><EventID>2</EventID>'),$xml.Replace('2026-01-01T00:00:00.1234567Z','not-utc'))){Reject {Read-WelaWefQueryEvent $bad @('System') $hostContext} 'Native event malformed or mismatched provenance.'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-query-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
 Copy-Item (Join-Path $script:ScriptRoot 'config/wef-examples/*') $temp
 $path=Join-Path $temp 'source.json';$subscription=Join-Path $temp 'native-security.xml';$original=[IO.File]::ReadAllText($path)
 $selected=Import-WelaWefQuerySelection $path 'WELA Native Security Example'
 Assert ($selected.Id -ceq 'WELA Native Security Example' -and $selected.Files.Count -eq 2 -and $selected.Channels -contains 'Security') 'Existing source config/parser used with exact bounded inputs.'
 Assert ($selected.QuerySha256 -ceq (Get-WelaArrivalHash ([Text.Encoding]::UTF8.GetBytes($selected.Query)))) 'Exact extracted QueryList hashed.'
 Assert-WelaWefQueryInputs $selected;Assert $true 'Unchanged original input hashes valid.'
 Reject {Import-WelaWefQuerySelection $path 'wela Native Security Example'} 'Selected ID case exact.'
 [IO.File]::WriteAllText($path,$original.Replace('"SchemaVersion": 1','"SchemaVersion": 1, "SchemaVersion": 1'))
 Reject {Import-WelaWefQuerySelection $path 'WELA Native Security Example'} 'Duplicate config properties refused.'
 [IO.File]::WriteAllText($path,$original.Replace('"SchemaVersion": 1','"SchemaVersion": true'))
 Reject {Import-WelaWefQuerySelection $path 'WELA Native Security Example'} 'Boolean schema rejected.'
 foreach($field in @('Role','Hardening','CollectorFqdn','CollectorUri','Authentication')){$config=ConvertFrom-WelaArrivalJson $original;$config.$field=$true;[IO.File]::WriteAllText($path,(Get-WelaWefQueryKey $config));Reject {Import-WelaWefQuerySelection $path 'WELA Native Security Example'} "Boolean text cannot pass source config $field"}
 foreach($field in @('SourceSids','SubscriptionFiles')){$config=ConvertFrom-WelaArrivalJson $original;$config.$field=@($true);[IO.File]::WriteAllText($path,(Get-WelaWefQueryKey $config));Reject {Import-WelaWefQuerySelection $path 'WELA Native Security Example'} "Typed source array $field"}
 [IO.File]::WriteAllText($path,$original)
 [IO.File]::AppendAllText($subscription,' ');Reject {Assert-WelaWefQueryInputs $selected} 'Original subscription byte drift invalidates evidence.'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$stream=[IO.StringReader]::new('abcdef');try{Reject {[Wela.WefQuery.Native]::ReadPipe($stream,5).GetAwaiter().GetResult()} 'Bounded pipe rejects excess before growing without limit.'}finally{$stream.Dispose()}
# Exercise complete command outcomes and changed evidence through real local artifacts.
$script:lifecycle=@{Case='';HostReads=0;ChannelReads=0;Config='';Xml=$xml}
function Get-WelaWefQueryHost {$script:lifecycle.HostReads++;[pscustomobject]@{Computer=$(if($script:lifecycle.Case -eq 'HostDrift' -and $script:lifecycle.HostReads -gt 1){'Other'}else{'Host'});DnsHostName='Host';DnsSuffix='example.test'}}
function Get-WelaWefQueryEngine {[pscustomobject]@{Path='fixture-engine';Sha256=('a'*64);Version='7.0';ModulePath='fixture-modules'}}
function Get-WelaWefQueryToken {[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='Host\Reader';AuthenticationId='0x123';AuthenticationType='Fixture';ImpersonationLevel='None';TokenSource='Process';Groups=@([pscustomobject]@{Sid='S-1-5-32-545';Attributes=7});Privileges=@()}}
function Get-WelaWefQueryChannelState {param($Channels) $script:lifecycle.ChannelReads++;[pscustomobject]@{Name='System';State=$(if($script:lifecycle.Case -eq 'ChannelDrift' -and $script:lifecycle.ChannelReads -gt 1){'Disabled'}else{'Enabled'})}}
function Start-WelaWefQueryWorker {
 param($Engine,$RequestPath,$RequestHash)
 $request=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText($RequestPath));$result=[pscustomobject]@{Opened=$true;Complete=$true;Capped=$false;CleanupConfirmed=$true;NativeError=$null;Diagnostic='';Channels=@([pscustomobject]@{Channel='System';Error=0});DiagnosticChannels=@();DiagnosticNativeError=$null;Events=@($script:lifecycle.Xml)}
 if($script:lifecycle.Case -eq 'Empty'){$result.Events=@()}
 if($script:lifecycle.Case -eq 'Partial'){$result.Complete=$false;$result.Capped=$true}
 if($script:lifecycle.Case -eq 'MissingStatus'){$result.Channels=@()}
 if($script:lifecycle.Case -eq 'DuplicateEvents'){$result.Events=@($script:lifecycle.Xml,$script:lifecycle.Xml)}
 if($script:lifecycle.Case -eq 'FailedQuery'){$result.Opened=$false;$result.Complete=$false;$result.NativeError=5;$result.Channels=@();$result.Events=@()}
 $receipt=[pscustomobject]@{SchemaVersion=1;Kind='WelaWefQueryWorker';Nonce=$request.Nonce;ProcessId=4242;Engine=$Engine;ModulePath=$Engine.ModulePath;StartedUtc='2026-01-01T00:00:00Z';CompletedUtc='2026-01-01T00:00:01Z';ReaderBefore=(Get-WelaWefQueryToken);ReaderAfter=(Get-WelaWefQueryToken);Host=$request.Host;Sources=$request.Sources;QuerySha256=$request.QuerySha256;Result=$result}
 if($script:lifecycle.Case -eq 'DateTimeReceipt'){$receipt.StartedUtc=[DateTime]::SpecifyKind([datetime]'2026-01-01T00:00:00',[DateTimeKind]::Utc);$receipt.CompletedUtc=$receipt.StartedUtc.AddSeconds(1)}
 if($script:lifecycle.Case -eq 'InvalidTimeReceipt'){$receipt.StartedUtc=$true}
 if($script:lifecycle.Case -eq 'TokenDrift'){$receipt.ReaderAfter.AuthenticationId='0x999'}
 if($script:lifecycle.Case -eq 'ReceiptBoolean'){$receipt.Kind=$true}
 if($script:lifecycle.Case -eq 'InputDrift'){[IO.File]::AppendAllText($script:lifecycle.Config,' ')}
 if($script:lifecycle.Case -eq 'ArtifactDrift'){[IO.File]::AppendAllText((Join-Path (Split-Path $RequestPath -Parent) 'query.xml'),' ')}
 [pscustomobject]@{Started=$true;ProcessId=4242;ExitCode=0;TimedOut=$false;TerminationConfirmed=($script:lifecycle.Case -ne 'Termination');Receipt=$receipt;Diagnostic=''}
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-query-lifecycle-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
 Copy-Item (Join-Path $script:ScriptRoot 'config/wef-examples/*') $temp
 $script:lifecycle.Config=Join-Path $temp 'source.json';$originalConfig=[IO.File]::ReadAllText($script:lifecycle.Config)
 $subscription=Join-Path $temp 'native-security.xml';$doc=Read-WelaWefXml ([IO.File]::ReadAllText($subscription));$doc.DocumentElement.SelectSingleNode('*[local-name()="Query"]').InnerText='<QueryList><Query Id="0" Path="System"><Select>*</Select></Query></QueryList>';[IO.File]::WriteAllText($subscription,$doc.OuterXml)
 foreach($case in @('Match','DateTimeReceipt','InvalidTimeReceipt','Empty','Partial','FailedQuery','MissingStatus','DuplicateEvents','TokenDrift','ReceiptBoolean','InputDrift','ArtifactDrift','Termination','HostDrift','ChannelDrift')){
  $script:lifecycle.Case=$case;$script:lifecycle.HostReads=0;$script:lifecycle.ChannelReads=0;[IO.File]::WriteAllText($script:lifecycle.Config,$originalConfig)
  $report=Invoke-WelaWefQuery $script:lifecycle.Config 'WELA Native Security Example' (Join-Path $temp $case)
  $expected=switch($case){Match{'MatchesObserved'};DateTimeReceipt{'MatchesObserved'};Empty{'ReadAllowedEmpty'};Partial{'Partial'};FailedQuery{'QueryFailed'};default{'Unverified'}}
  Assert ($report.Status -ceq $expected) ("Public lifecycle $case expected $expected : "+$report.Diagnostic)
  Assert ($report.ExitCode -eq $(if($case -in @('Match','DateTimeReceipt','Empty')){0}else{1}) -and $report.ReadyRuleCredit -eq 0 -and $report.ConfigurationChanges -eq 0) "Public lifecycle $case exit/credit boundaries."
  Assert (Test-Path -LiteralPath (Join-Path (Join-Path $temp $case) 'manifest.json')) "Failure/complete manifest retained for $case."
 }
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Host "WefQuery.Tests: $script:count focused assertions passed."
$global:LASTEXITCODE=0
