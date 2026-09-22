$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('WefArrival','FileAccessProbe','RegistryValueProbe')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action){$threw=$false;try{& $Action|Out-Null}catch{$threw=$true};Assert $threw 'Expected evidence refusal.'}
function Copy-Value($Value){ConvertFrom-WelaArrivalJson (Get-WelaFileProbeKey $Value)}
function Fixture {
 $script:token=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='FIXTURE\Reader';AuthenticationId='0x1234';AuthenticationType='Negotiate';ImpersonationLevel='None';TokenSource='Process';Groups=@([pscustomobject]@{Sid='S-1-1-0';Attributes=7});Privileges=@([pscustomobject]@{Luid='0x8';Attributes=0})}
 $script:state=[pscustomobject]@{Computer='FIXTURE';Host=[pscustomobject]@{ProductType=3;Build=20348;DomainRole=2;DomainJoined=$false;Domain='WORKGROUP'};Services=@([pscustomobject]@{Name='EventLog';Status='Running'},[pscustomobject]@{Name='RpcSs';Status='Running'},[pscustomobject]@{Name='Winmgmt';Status='Running'});Reader=[pscustomobject]@{UserSid=$script:token.Sid;ElevatedAdministrator=$true;TokenType='Primary';Impersonation='Absent'};Token=Copy-Value $script:token;Registry=[pscustomobject]@{Path=('HKEY_USERS\'+$script:token.Sid+'\Software\WELA\AuditProbe');Kind='Registry';IsDirectory=$false;Identity='fixed:123';DescriptorBase64='AA==';SecurityInformation=511;Values=@();Aces=@([pscustomobject]@{Ordinary=$true;Type=2;Flags=64;Mask=2;Sid='S-1-1-0';Binary='AA=='})};AuditPolicies=[pscustomobject]@{'0CCE921E-69AE-11D9-BED3-505054503030'=1};Precedence=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1};Channel=[pscustomobject]@{Name='Security';Enabled=$true;SecurityDescriptor='O:SYG:SYD:'};Engine='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';EngineHash=('b'*64);Sources=[pscustomobject]@{Source=('c'*64)}}
 $n='d'*32;$script:operation=[pscustomobject]@{Kind='WelaOwnedRegistryValueModification';Nonce=$n;ProcessId=1234;Executable=$script:state.Engine;RecordIdBefore=10;BeforeToken=Copy-Value $script:token;AfterToken=Copy-Value $script:token;LaunchedUtc='2026-09-21T00:00:00.0000000Z';ObservedUtc='2026-09-21T00:00:01.0000000Z';Native=[pscustomobject]@{Succeeded=$true;CleanupComplete=$true;Nonce=$n;Name=('WELA_Probe_'+$n);BeforeValue=('WELA_BEFORE_'+$n);AfterValue=('WELA_AFTER_'+$n);HandleId='0x888';Before=Copy-Value $script:state.Registry;After=Copy-Value $script:state.Registry;StartedUtc='2026-09-21T00:00:00.0001000Z';WriteReturnedUtc='2026-09-21T00:00:00.0001600Z';CompletedUtc='2026-09-21T00:00:00.0002000Z';Diagnostic=''}}
 $script:stateReads=0;$script:attempts=0;$script:batchMode='match';$script:failArtifact=$null;$script:afterDrift=$false
}
function Xml {
 @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4657</EventID><Version>0</Version><Level>0</Level><Task>12801</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-21T00:00:00.0001500Z"/><EventRecordID>11</EventRecordID><Channel>Security</Channel><Computer>FIXTURE</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectUserName">Reader</Data><Data Name="SubjectDomainName">FIXTURE</Data><Data Name="SubjectLogonId">0x1234</Data><Data Name="ObjectName">\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\WELA\AuditProbe</Data><Data Name="ObjectValueName">$($script:operation.Native.Name)</Data><Data Name="HandleId">0x888</Data><Data Name="OperationType">%%1905</Data><Data Name="OldValueType">%%1873</Data><Data Name="OldValue">$($script:operation.Native.BeforeValue)</Data><Data Name="NewValueType">%%1873</Data><Data Name="NewValue">$($script:operation.Native.AfterValue)</Data><Data Name="ProcessId">0x4d2</Data><Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data></EventData></Event>
"@
}
# The live CIM schema uses UInt16; JSON fixtures normalize numbers to Int32.
foreach($role in @([uint16]2,[int]2)) {Assert-WelaRegistryValueProbeComputerRole ([pscustomobject]@{DomainRole=$role;PartOfDomain=$false});Assert $true 'Native UInt16 and normalized Int32 roles are accepted.'}
foreach($role in @($null,$true,'2',2.5,6,-1)) {Reject {Assert-WelaRegistryValueProbeComputerRole ([pscustomobject]@{DomainRole=$role;PartOfDomain=$false})}}
Reject {Assert-WelaRegistryValueProbeComputerRole ([pscustomobject]@{DomainRole=[uint16]2;PartOfDomain='false'})}
Fixture;$null=Get-WelaRegistryValueProbeStateKey $script:state;Assert-WelaRegistryValueProbeOperation $script:operation $script:state;Assert $true 'Complete fixed-key operation with cleanup is accepted.'
foreach($bad in @('path','mask','precedence','channel','role','group','inherit-only','failure','callback','right','descriptor','sources','token')){
 Fixture
 switch($bad){'path'{$script:state.Registry.Path='HKEY_LOCAL_MACHINE\Software\WELA\AuditProbe'};'mask'{$script:state.AuditPolicies.'0CCE921E-69AE-11D9-BED3-505054503030'=0};'precedence'{$script:state.Precedence.Value=$true};'channel'{$script:state.Channel.Enabled='true'};'role'{$script:state.Host.ProductType=$true};'group'{$script:state.Token.Groups[0].Attributes=16};'inherit-only'{$script:state.Registry.Aces[0].Flags=72};'failure'{$script:state.Registry.Aces[0].Flags=128};'callback'{$script:state.Registry.Aces[0].Ordinary=$false};'right'{$script:state.Registry.Aces[0].Mask=1};'descriptor'{$script:state.Registry.DescriptorBase64=$null};'sources'{$script:state.Sources.Source='bad'};'token'{$script:state.Token.TokenSource='Thread'}}
 Reject {Get-WelaRegistryValueProbeStateKey $script:state}
}
foreach($badRole in @($null,$true,0,4)) {Fixture;$script:state.Host.DomainRole=$badRole;Reject {Get-WelaRegistryValueProbeStateKey $script:state}}
Fixture;$script:state.Host.DomainJoined=$true;Reject {Get-WelaRegistryValueProbeStateKey $script:state}
Fixture;$script:state.Host.Build=22631;Reject {Get-WelaRegistryValueProbeStateKey $script:state}
foreach($bad in @('nonce','success','cleanup','key','values','before','after','reverse','handle','token')){
 Fixture
 switch($bad){'nonce'{$script:operation.Nonce='invalid'};'success'{$script:operation.Native.Succeeded='true'};'cleanup'{$script:operation.Native.CleanupComplete=$false};'key'{$script:operation.Native.After.Path='wrong'};'values'{$script:operation.Native.After.Values=@('new')};'before'{$script:operation.Native.StartedUtc='2026-09-20T00:00:00Z'};'after'{$script:operation.Native.CompletedUtc='2026-09-22T00:00:00Z'};'reverse'{$script:operation.Native.WriteReturnedUtc='2026-09-21T00:00:00Z'};'handle'{$script:operation.Native.HandleId='0x0'};'token'{$script:operation.AfterToken.Privileges[0].Attributes=2}}
 Reject {Assert-WelaRegistryValueProbeOperation $script:operation $script:state}
}
Fixture;$xml=Xml;Assert (Test-WelaRegistryValueProbeEvent $xml $script:operation $script:state) 'Exact native-schema4657 is attributed.'
foreach($change in @(@('4657','4663'),@('<Version>0','<Version>1'),@('<Task>12801','<Task>12800'),@('0x8020000000000000','0x8010000000000000'),@('>FIXTURE</Computer>','>OTHER</Computer>'),@('>0x888</Data>','>0x889</Data>'),@('>0x4d2</Data>','>0x4d3</Data>'),@('>0x1234</Data>','>0x1235</Data>'),@('AuditProbe','OtherKey'),@('%%1905','%%1904'),@('%%1873','%%1874'),@('WELA_BEFORE_','DIFFERENT_'),@('WELA_AFTER_','DIFFERENT_'),@('WELA_Probe_','DIFFERENT_'),@('0001500Z','0000999Z'),@('0001500Z','0002001Z'),@('<EventRecordID>11','<EventRecordID>10'),@('1001</Data>','1002</Data>'),@('v1.0\powershell.exe','v1.0\other.exe'))){Assert (-not(Test-WelaRegistryValueProbeEvent $xml.Replace($change[0],$change[1]) $script:operation $script:state)) 'Mismatched provider/event/key/value/process/token/time is refused.'}
foreach($badXml in @($xml.Replace('</EventData>','<Data Name="OldValue">duplicate</Data></EventData>'),('<!DOCTYPE Event [<!ENTITY x "x">]>'+$xml),('<wrapper>'+$xml+'</wrapper>'))){Assert (-not(Test-WelaRegistryValueProbeEvent $badXml $script:operation $script:state)) 'Ambiguous or unsafe XML is refused.'}
# Compile exact source without invoking native API.
function Initialize-WelaWmiProbeNative {}
Initialize-WelaRegistryValueProbe
Assert ([Wela.RegistryValueProbe.Descriptor]::SourceSha256 -ceq (Get-FileHash (Join-Path $script:ScriptRoot 'scripts/RegistryValueProbeNative.cs')).Hash.ToLowerInvariant()) 'Exact native source hash is bound.'
# The temporary value must fit the same inventory bounds used for final readback.
$small=[Wela.RegistryValueProbe.Value]::new();$small.Name='small';$small.Type=3;$small.DataBase64='AA=='
[Wela.RegistryValueProbe.Descriptor]::AssertProbeCapacity([Wela.RegistryValueProbe.Value[]]@((1..127|ForEach-Object{$small})))
Assert $true '127 original values leave room for exactly one owned marker.'
Reject {[Wela.RegistryValueProbe.Descriptor]::AssertProbeCapacity([Wela.RegistryValueProbe.Value[]]@((1..128|ForEach-Object{$small})))}
$large=[Wela.RegistryValueProbe.Value]::new();$large.Type=3;$large.DataBase64=[Convert]::ToBase64String([byte[]]::new(65536))
Reject {[Wela.RegistryValueProbe.Descriptor]::AssertProbeCapacity([Wela.RegistryValueProbe.Value[]]@((1..16|ForEach-Object{$large})))}
$reserved=[Text.Encoding]::Unicode.GetByteCount('WELA_BEFORE_'+('0'*32)+[char]0)
$tail=[Wela.RegistryValueProbe.Value]::new();$tail.Type=3;$tail.DataBase64=[Convert]::ToBase64String([byte[]]::new(65536-$reserved))
[Wela.RegistryValueProbe.Descriptor]::AssertProbeCapacity([Wela.RegistryValueProbe.Value[]](@((1..15|ForEach-Object{$large}))+@($tail)))
Assert $true 'Exactly reserved byte capacity is accepted.'
$writer=(Get-Command Write-WelaFileProbeArtifact).ScriptBlock
function Get-WelaFileProbeOutputKey {param($Path) 'private-fixture'}
function Write-WelaFileProbeArtifact {param($Root,$OutputKey,$Name,$Text) if($Name -eq $script:failArtifact){throw 'Injected artifact failure'};& $script:writer $Root $OutputKey $Name $Text}
function Get-WelaRegistryValueProbeState {$script:stateReads++;Copy-Value $script:state}
function Invoke-WelaRegistryValueProbeOperation {param($State,$Nonce) $script:attempts++;$script:operation.Nonce=$Nonce;$script:operation.Native.Nonce=$Nonce;$script:operation.Native.Name='WELA_Probe_'+$Nonce;$script:operation.Native.BeforeValue='WELA_BEFORE_'+$Nonce;$script:operation.Native.AfterValue='WELA_AFTER_'+$Nonce;if($script:afterDrift){$script:state.Sources.Source='f'*64};Copy-Value $script:operation}
function Read-WelaRegistryValueProbeEvents {param($Operation) $xml=Xml;$items=if($script:batchMode -eq 'empty'){@()}elseif($script:batchMode -eq 'duplicate'){@($xml,$xml)}else{@($xml)};[pscustomobject]@{Xml=$items;Capped=($script:batchMode -eq 'capped');Query='fixture'}}
function Get-WelaFileProbeWatermark {11}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-reg-probe-test-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
try{
 Fixture;$r=Invoke-WelaRegistryValueProbe;Assert ($r.ExitCode -eq 0 -and $r.Status -ceq 'PrerequisitesObserved' -and $script:attempts -eq 0) 'Plan never attempts a value write.'
 Fixture;$r=Invoke-WelaRegistryValueProbe -Action Run -OutputPath (Join-Path $root 'pass');Assert ($r.ExitCode -eq 0 -and $r.Status -ceq 'RegistryValueModificationObserved' -and $r.Matches -eq 1 -and $r.SigmaEvtxCredit -eq 0) 'Exact4657 with cleanup is component evidence only.'
 foreach($mode in @('capped','duplicate','empty')){Fixture;$script:batchMode=$mode;$r=Invoke-WelaRegistryValueProbe -Action Run -OutputPath (Join-Path $root $mode) -TimeoutSeconds 1;Assert ($r.ExitCode -eq 1) 'Incomplete/duplicate/absent event evidence fails.'}
 Fixture;$script:failArtifact='intent.json';$r=Invoke-WelaRegistryValueProbe -Action Run -OutputPath (Join-Path $root 'intent');Assert ($r.ExitCode -eq 1 -and $script:attempts -eq 0) 'Intent failure prevents value mutation.'
 Fixture;$script:afterDrift=$true;$r=Invoke-WelaRegistryValueProbe -Action Run -OutputPath (Join-Path $root 'drift');Assert ($r.ExitCode -eq 1) 'Final drift prevents observed-event credit.'
 Fixture;$script:operation.Native.CleanupComplete=$false;$r=Invoke-WelaRegistryValueProbe -Action Run -OutputPath (Join-Path $root 'cleanup');Assert ($r.ExitCode -eq 1 -and (Test-Path (Join-Path $root 'cleanup/operation.json'))) 'Failed cleanup receipt is retained and never credited.'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count registry value probe assertions."
