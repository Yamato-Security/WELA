$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ScriptRoot 'modules/AuditProfiles.psm1') -Force
foreach($name in @('WefArrival','AuditRecovery','ChannelRead','DnsClientProbe')){. (Join-Path $ScriptRoot ('scripts/'+$name+'.ps1'))}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Throws($Code,$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
Add-Type -Path (Join-Path $ScriptRoot 'scripts/DnsClientProbeNative.cs')
foreach($resolver in @('127.0.0.1','192.0.2.53','10.0.0.53')){Assert-WelaDnsClientResolver $resolver;Assert ([Wela.DnsClientProbe.Native]::ValidateResolver($resolver) -ceq $resolver) 'Explicit canonical IPv4 accepted.'}
foreach($resolver in @('','localhost','127.1','127.0.0.01','127.0.0.1:53','127.0.0.1"','0.0.0.0','224.0.0.1','255.255.255.255','192.0.2.999','::1')){Throws {Assert-WelaDnsClientResolver $resolver} 'IPv4';Throws {[Wela.DnsClientProbe.Native]::ValidateResolver($resolver)} 'resolver|IPv4'}
Throws {[Wela.DnsClientProbe.Native]::Query('arbitrary.example.','127.0.0.1')} 'fixed random'
Assert ([Wela.DnsClientProbe.Native].GetField('SourceSha256').IsLiteral) 'Compiled source fingerprint cannot be reassigned.'
Assert ([Wela.DnsClientProbe.Native]::Options -eq 2103790) 'Fixed documented DNS flags retained.'
$fields=@(foreach($name in @('QueryName','QueryType','QueryOptions','QueryStatus','QueryResults')){[pscustomobject]@{Name=$name;InType=$(if($name -in @('QueryName','QueryResults')){'win:UnicodeString'}elseif($name -eq 'QueryOptions'){'win:UInt64'}else{'win:UInt32'})}})
$state=[pscustomobject]@{Computer='host';Host=[pscustomobject]@{DomainJoined=$false;Domain='WORKGROUP'};Service='Running';Channel=[pscustomobject]@{State='Enabled';Name='Microsoft-Windows-DNS-Client/Operational';SecurityDescriptor='O:SYG:SYD:(A;;0x1;;;SY)';MetadataErrors=@{};Error=$null;IsEnabled=$true;MaximumSizeInBytes=1048576;LogMode='Circular'};Schema=[pscustomobject]@{State='Observed';Provider='Microsoft-Windows-DNS-Client';ProviderGuid='1c95126e-7eea-49a9-a3fe-a378b03ddb4d';ChannelType='Operational';Events=@([pscustomobject]@{Id=3008;Version=0;Channel='Microsoft-Windows-DNS-Client/Operational';Fields=$fields})}}
Assert ((Get-WelaDnsClientProbeStateKey $state).Length -gt 0) 'Exact schema prerequisite accepted.'
$state.Channel.MetadataErrors['LogMode']='denied';Throws {Get-WelaDnsClientProbeStateKey $state} 'fully observed';$state.Channel.MetadataErrors=@{}
$state.Schema.Events[0].Fields[0].InType='win:UInt32';Throws {Get-WelaDnsClientProbeStateKey $state} 'field/type';$state.Schema.Events[0].Fields[0].InType='win:UnicodeString'
$state.Schema.Events[0].Version=1;Throws {Get-WelaDnsClientProbeStateKey $state} 'version/channel';$state.Schema.Events[0].Version=0
$operation=[pscustomobject]@{Query=[pscustomobject]@{QueryName='wela-0123456789abcdef0123456789abcdef.wela.test.';Status=0;Options=2103790};StartedUtc='2026-01-01T00:00:00.0000000Z';CompletedUtc='2026-01-01T00:00:01.0000000Z';RecordIdBefore=9}
$xml=@'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-DNS-Client" Guid="{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"/><EventID>3008</EventID><Version>0</Version><EventRecordID>10</EventRecordID><Channel>Microsoft-Windows-DNS-Client/Operational</Channel><Computer>host</Computer><TimeCreated SystemTime="2026-01-01T00:00:00.5000000Z"/><Execution ProcessID="123"/></System><EventData><Data Name="QueryName">wela-0123456789abcdef0123456789abcdef.wela.test.</Data><Data Name="QueryType">1</Data><Data Name="QueryOptions">0x2019ee</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">192.0.2.1;</Data></EventData></Event>
'@
Assert (Test-WelaDnsClientProbeEvent $xml $operation $state) 'Exact synthetic native3008 shape matches.'
$mutations=@(
 @('>3008<','>3006<'),@('<Version>0','<Version>1'),@('>10<','>9<'),@('>host<','>other<'),@('DNS-Client/Operational','DNS Client Events/Operational'),@('1c95126e','2c95126e'),@('Microsoft-Windows-DNS-Client"','Other-Provider"'),@('00:00:00.5000000Z','00:00:01.5000000Z'),@('ProcessID="123"','ProcessID="0"'),@('Name="QueryType">1','Name="QueryType">28'),@('Name="QueryStatus">0','Name="QueryStatus">9003'),@('0x2019ee','0x2019ec'),@('0123456789abcdef0123456789abcdef','ffffffffffffffffffffffffffffffff'),@('</EventData>','<Data Name="QueryName">duplicate</Data></EventData>'),@('</EventData>','<Data Name="Unknown">extra</Data></EventData>'),@('192.0.2.1;','<Nested/>'),@('<Event xmlns=','<!DOCTYPE Event [<!ENTITY x "no">]><Event xmlns='))
foreach($mutation in $mutations){Assert (-not(Test-WelaDnsClientProbeEvent ($xml.Replace($mutation[0],$mutation[1])) $operation $state)) "Reject mismatched native XML: $($mutation[0])"}
Assert (Test-WelaDnsClientProbeEvent ($xml.Replace('ProcessID="123"','ProcessID="456"')) $operation $state) 'Emitter broker PID remains recorded without invented caller attribution.'
$operation.Query.Status=9003;Assert (Test-WelaDnsClientProbeEvent ($xml.Replace('Name="QueryStatus">0','Name="QueryStatus">9003')) $operation $state) 'Typed NXDOMAIN completion differs from successful resolution.'
$operation.Query.Status=0
# Exercise report/cap/drift behavior; only native boundaries are mocked.
function Clone($Value){ConvertFrom-WelaRecoveryJson ($Value|ConvertTo-Json -Depth 20 -Compress)}
$token=[pscustomobject]@{Computer='host';ProcessId=123;UserSid='S-1-5-21-1-2-3-1001';UserName='HOST\Reader';TokenId='100';AuthenticationId='99';ModifiedId='200';GroupSids=@('S-1-1-0');GroupCount=1;PrivilegeCount=1;ElevatedAdministrator=$false;TokenType='Primary';Impersonation='Absent'}
$state|Add-Member NoteProperty Reader (Clone $token);$operation|Add-Member NoteProperty CallerBefore (Clone $token)
$script:mode='Success';$script:reads=0;$script:workerCalls=0
function Get-WelaDnsClientProbeState {$script:reads++;$copy=Clone $state;$copy.Reader.ModifiedId=[string](200+$script:reads);if($script:mode -eq 'Drift' -and $script:reads -gt 1){$copy.Computer='changed'};if($script:mode -eq 'Blocked'){$copy.Service='Stopped'};$copy}
function Start-WelaDnsClientProbeQuery {param($State,$Resolver,$QueryName);$script:workerCalls++;$operation}
function Read-WelaDnsClientProbeEvents {param($Operation);if($script:mode -eq 'ReadError'){throw 'native query denied'};[pscustomobject]@{Xml=$(if($script:mode -eq 'Missing'){@()}else{@($xml)});Capped=($script:mode -eq 'Cap');Query='synthetic bounded query';LogStatus=@([pscustomobject]@{LogName='Microsoft-Windows-DNS-Client/Operational';StatusCode=$(if($script:mode -eq 'DeniedStatus'){[int]5}else{[int]0})})}}
function Get-WelaChannelReader {$copy=Clone $token;if($script:mode -eq 'TokenDrift'){$copy.ModifiedId='changed'};$copy}
function Get-WelaDnsClientProbeWatermark {if($script:mode -eq 'Clear'){8}else{10}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-dns-fixtures-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
 $plan=Invoke-WelaDnsClientProbe -Resolver '127.0.0.1'
 Assert ($plan.Status -ceq 'PrerequisitesObserved' -and $script:workerCalls -eq 0 -and -not $plan.OutputPath) 'Default Plan never runs a DNS query or writes evidence.'
 foreach($mode in @('Success','Blocked','Cap','ReadError','Drift','Clear','Missing','DeniedStatus','TokenDrift')){
  $script:mode=$mode;$script:reads=0;$script:workerCalls=0;$directory=Join-Path $temp $mode
  $result=Invoke-WelaDnsClientProbe -Action Run -Resolver '127.0.0.1' -OutputPath $directory -TimeoutSeconds 1
  $manifest=ConvertFrom-WelaRecoveryJson ([IO.File]::ReadAllText((Join-Path $directory 'manifest.json')))
  Assert ($manifest.ReadyRuleCredit -eq 0 -and $manifest.ConfigurationChanges -eq 0 -and $manifest.RuleChannelMismatch -match 'DNS Client Events/Operational') 'Success and failure retain original channel mismatch and zero configuration/Sigma credit.'
  Assert ($null -ne $manifest.After) 'Final observations survive failures.'
  foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $directory $artifact.Name)).Hash.ToLowerInvariant()) 'Manifest hashes match written bytes.'}
  if($mode -eq 'Success'){Assert ($result.Status -ceq 'NativeDnsLookupObserved' -and $result.Matches -eq 1 -and $result.ExitCode -eq 0) 'Exact synthetic event yields the bounded observation.';Assert ([IO.File]::ReadAllText((Join-Path $directory 'event-1.xml')) -ceq $xml) 'Original XML retained unchanged.'}
  else{Assert ($result.Status -ceq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) "Failure $mode remains unverified."}
  if($mode -eq 'Blocked'){Assert ($script:workerCalls -eq 0) 'Missing prerequisites prevent the native operation.'}
 }
 Throws {Invoke-WelaDnsClientProbe -Action Run -Resolver '127.0.0.1' -OutputPath (Join-Path $temp 'Success')} 'new directory'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Host "PASS: $script:count DNS Client validator/report/refusal assertions; native boundaries were mocked."
