$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('WefArrival','FileAccessProbe')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{& $Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'"}
function Copy-Value($Value){(ConvertFrom-WelaArrivalJson (Get-WelaFileProbeKey ([pscustomobject]@{Data=$Value}))).Data}
function New-Fixture {
    $script:token=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='FIXTURE\Reader';AuthenticationId='0x1234';AuthenticationType='Negotiate';ImpersonationLevel='None';TokenSource='Process';Groups=@([pscustomobject]@{Sid='S-1-1-0';Attributes=7});Privileges=@([pscustomobject]@{Luid='0x8';Attributes=0})}
    $script:reader=[pscustomobject]@{Computer='FIXTURE';ProcessId=1234;UserSid=$script:token.Sid;UserName=$script:token.Name;TokenId='1';AuthenticationId='4660';ModifiedId='2';GroupSids=@('S-1-1-0');GroupCount=1;PrivilegeCount=1;ElevatedAdministrator=$true;TokenType='Primary';Impersonation='Absent'}
    $script:state=[pscustomobject]@{Computer='FIXTURE';Host=[pscustomobject]@{ProductType=3;Build=20348;DomainJoined=$false;Domain='WORKGROUP'};MachineGuid='01234567-89ab-cdef-0123-456789abcdef';Services=@([pscustomobject]@{Name='EventLog';Status='Running'},[pscustomobject]@{Name='RpcSs';Status='Running'},[pscustomobject]@{Name='Winmgmt';Status='Running'});Reader=($script:reader|Select-Object UserSid,UserName,AuthenticationId,GroupSids,GroupCount,PrivilegeCount,ElevatedAdministrator,TokenType,Impersonation);Token=(Copy-Value $script:token);File=[pscustomobject]@{Path='C:\Fixture\ReadCase.TxT';NativePath='\Device\HarddiskVolume5\Fixture\ReadCase.TxT';Identity='1:2:3:1339999';Size=32;LastWriteUtc='2026-09-20T00:00:00.0000000Z';DescriptorBase64='AA==';StateKey=('a'*64);Attributes=32;Links=1;SecurityInformation=511;Aces=@([pscustomobject]@{Type=2;Flags=64;Mask=1;Sid='S-1-1-0';Ordinary=$true;Binary='AA=='})};AuditPolicies=[pscustomobject]@{'0CCE921D-69AE-11D9-BED3-505054503030'=1};Precedence=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=1;Type='DWord'};Channel=[pscustomobject]@{Name='Security';Enabled=$true;SecurityDescriptor='O:SYG:SYD:'};Engine='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';EngineHash=('b'*64);Sources=[pscustomobject]@{Source=('c'*64)}}
    $script:nonce='d'*32
    $script:operation=[pscustomobject]@{Kind='WelaOneByteFileRead';Nonce=$script:nonce;ProcessId=1234;Executable=$script:state.Engine;FilePath=$script:state.File.Path;BeforeReader=(Copy-Value $script:reader);AfterReader=(Copy-Value $script:reader);BeforeToken=(Copy-Value $script:token);AfterToken=(Copy-Value $script:token);Read=[pscustomobject]@{Clock='GetSystemTimePreciseAsFileTime';Succeeded=$true;ReadCalls=1;BytesRead=1;HandleId='0x888';BeforeKey=('a'*64);AfterKey=('a'*64);StartedUtc='2026-09-21T00:00:00.0001000Z';CompletedUtc='2026-09-21T00:00:00.0002000Z'};RecordIdBefore=10}
    $script:reads=0;$script:batchMode='match';$script:afterDrift=$false;$script:workerFailure=$false;$script:failArtifact=$null
}
function Native-Xml {
    @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4663</EventID><Version>1</Version><Level>0</Level><Task>12800</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-21T00:00:00.0001500Z"/><EventRecordID>11</EventRecordID><Channel>Security</Channel><Computer>FIXTURE</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectUserName">Reader</Data><Data Name="SubjectDomainName">FIXTURE</Data><Data Name="SubjectLogonId">0x1234</Data><Data Name="ObjectServer">Security</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\Fixture\ReadCase.TxT</Data><Data Name="HandleId">0x888</Data><Data Name="AccessList">%%4416</Data><Data Name="AccessMask">0x1</Data><Data Name="ProcessId">0x4d2</Data><Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="ResourceAttributes">-</Data></EventData></Event>
"@
}
New-Fixture
$null=Get-WelaFileProbeStateKey $script:state;Assert $true 'complete native prerequisites are accepted'
Assert-WelaFileProbeOperation $script:operation $script:state $script:nonce 1234 ([datetimeoffset]'2026-09-21T00:00:00Z') ([datetimeoffset]'2026-09-21T00:00:01Z');Assert $true 'one precise same-token byte read is accepted'
foreach($path in @('','relative.txt','\\host\share\file','C:\a:stream','C:\a\..\file','C:\a\file.','C:\a\file ','C:\a\file*','C:\a\','C:\a\\file','C:/file',('C:\'+('a'*240)))){Reject {Assert-WelaFileProbePath $path} 'exact ordinary'}
foreach($name in @('computer','machine','host-build','host-product','joined','service','token-source','token-sid','token-group','token-privilege','file-path','native-path','file-key','descriptor','size','links','sections','ace-ordinary','ace-type','ace-mask','ace-sid','channel-name','channel-enabled','precedence-type','precedence-value','mask','reader-type','reader-impersonation','engine','source')){
    New-Fixture
    switch($name){
        'computer' {$script:state.Computer=$true};'machine' {$script:state.MachineGuid=$true};'host-build' {$script:state.Host.Build=$true};'host-product' {$script:state.Host.ProductType=$true};'joined' {$script:state.Host.DomainJoined='false'}
        'service' {$script:state.Services[0].Status=$true};'token-source' {$script:state.Token.TokenSource=$true};'token-sid' {$script:state.Token.Sid=$true};'token-group' {$script:state.Token.Groups[0].Attributes=$true};'token-privilege' {$script:state.Token.Privileges[0].Attributes=$true}
        'file-path' {$script:state.File.Path=$true};'native-path' {$script:state.File.NativePath=$true};'file-key' {$script:state.File.StateKey=$true};'descriptor' {$script:state.File.DescriptorBase64=$true};'size' {$script:state.File.Size=$true};'links' {$script:state.File.Links=$true};'sections' {$script:state.File.SecurityInformation=$true}
        'ace-ordinary' {$script:state.File.Aces[0].Ordinary='true'};'ace-type' {$script:state.File.Aces[0].Type=$true};'ace-mask' {$script:state.File.Aces[0].Mask=$true};'ace-sid' {$script:state.File.Aces[0].Sid=$true}
        'channel-name' {$script:state.Channel.Name=$true};'channel-enabled' {$script:state.Channel.Enabled='true'};'precedence-type' {$script:state.Precedence.Type=$true};'precedence-value' {$script:state.Precedence.Value=$true};'mask' {$script:state.AuditPolicies.'0CCE921D-69AE-11D9-BED3-505054503030'=$true}
        'reader-type' {$script:state.Reader.TokenType=$true};'reader-impersonation' {$script:state.Reader.Impersonation=$true};'engine' {$script:state.Engine=$true};'source' {$script:state.Sources.Source=$true}
    }
    Reject {Get-WelaFileProbeStateKey $script:state} 'required|Incomplete|complete|ordinary|Unknown|Missing|Malformed|must already'
}
foreach($name in @('deny-only','disabled-group','inherit-only','failure-ace','callback','wrong-right','wrong-sid')){
    New-Fixture
    switch($name){'deny-only' {$script:state.Token.Groups[0].Attributes=16};'disabled-group' {$script:state.Token.Groups[0].Attributes=0};'inherit-only' {$script:state.File.Aces[0].Flags=72};'failure-ace' {$script:state.File.Aces[0].Flags=128};'callback' {$script:state.File.Aces[0].Ordinary=$false};'wrong-right' {$script:state.File.Aces[0].Mask=2};'wrong-sid' {$script:state.File.Aces[0].Sid='S-1-5-18'}}
    Reject {Get-WelaFileProbeStateKey $script:state} 'No existing ordinary success ReadData'
}
foreach($name in @('kind','nonce','pid','executable','path','clock','success','calls','bytes','handle','before','after','token-drift','reader-drift','pre-launch','post-observed','reverse')){
    New-Fixture
    switch($name){'kind' {$script:operation.Kind=$true};'nonce' {$script:operation.Nonce=$true};'pid' {$script:operation.ProcessId=$true};'executable' {$script:operation.Executable=$true};'path' {$script:operation.FilePath=$true};'clock' {$script:operation.Read.Clock=$true};'success' {$script:operation.Read.Succeeded='true'};'calls' {$script:operation.Read.ReadCalls=$true};'bytes' {$script:operation.Read.BytesRead=$true};'handle' {$script:operation.Read.HandleId='0x0'};'before' {$script:operation.Read.BeforeKey=$true};'after' {$script:operation.Read.AfterKey='e'*64};'token-drift' {$script:operation.AfterToken.Privileges[0].Attributes=2};'reader-drift' {$script:operation.AfterReader.ModifiedId='999'};'pre-launch' {$script:operation.Read.StartedUtc='2026-09-20T23:59:59Z'};'post-observed' {$script:operation.Read.CompletedUtc='2026-09-21T00:00:02Z'};'reverse' {$script:operation.Read.CompletedUtc='2026-09-21T00:00:00Z'}}
    Reject {Assert-WelaFileProbeOperation $script:operation $script:state $script:nonce 1234 ([datetimeoffset]'2026-09-21T00:00:00Z') ([datetimeoffset]'2026-09-21T00:00:01Z')} 'authority|identity|receipt|Expected|token|interval'
}
New-Fixture;$xml=Native-Xml
Assert (Test-WelaFileProbeEvent $xml $script:operation $script:state) 'actual-schema source fixture matches all attribution fields'
foreach($change in @(@('4663','4662'),@('<Version>1','<Version>0'),@('0x8020000000000000','0x8010000000000000'),@('<Task>12800','<Task>1'),@('>FIXTURE</Computer>','>OTHER</Computer>'),@('>0x1</Data>','>0x2</Data>'),@('>0x888</Data>','>0x889</Data>'),@('>0x4d2</Data>','>0x4d3</Data>'),@('>0x1234</Data>','>0x1235</Data>'),@('>File</Data>','>Key</Data>'),@('ReadCase.TxT','Other.txt'),@('>%%4416</Data>','>%%4417</Data>'),@('0001500Z','0000999Z'),@('0001500Z','0002001Z'),@('<EventRecordID>11','<EventRecordID>10'),@('1001</Data>','1002</Data>'),@('v1.0\powershell.exe','v1.0\other.exe'))){Assert (-not(Test-WelaFileProbeEvent $xml.Replace($change[0],$change[1]) $script:operation $script:state)) "mismatched event $($change[0]) is refused"}
Assert (Test-WelaFileProbeEvent $xml.Replace('ReadCase.TxT','readcase.txt').Replace('System32','SYSTEM32').Replace('%%4416','  %%4416  ') $script:operation $script:state) 'Windows path casing and native access-list whitespace do not change identity/right'
Assert (Test-WelaFileProbeEvent $xml.Replace($script:state.File.Path,$script:state.File.NativePath.ToLowerInvariant()) $script:operation $script:state) 'the exact same-handle observed NT path is accepted case-insensitively'
foreach($wrong in @('\Device\HarddiskVolume6\Fixture\ReadCase.TxT','\Device\HarddiskVolume5\Elsewhere\ReadCase.TxT','\Device\HarddiskVolume5\Fixture\Other.TxT')){Assert (-not(Test-WelaFileProbeEvent $xml.Replace($script:state.File.Path,$wrong) $script:operation $script:state)) 'other NT volumes and paths remain rejected'}
foreach($time in @('0001000Z','0002000Z')){Assert (Test-WelaFileProbeEvent $xml.Replace('0001500Z',$time) $script:operation $script:state) 'exact precise interval boundaries are inclusive'}
Assert (-not(Test-WelaFileProbeEvent $xml.Replace('</EventData>','<Data Name="AccessMask">0x1</Data></EventData>') $script:operation $script:state)) 'duplicate XML authority is refused'
Assert (-not(Test-WelaFileProbeEvent ('<!DOCTYPE Event [<!ENTITY x "x">]>'+$xml) $script:operation $script:state)) 'DTD evidence is refused'
Assert (-not(Test-WelaFileProbeEvent ('<wrapper>'+$xml+'</wrapper>') $script:operation $script:state)) 'wrapped event is refused'
$script:state.File.LastWriteUtc=[datetime]::SpecifyKind([datetime]'2026-09-20T00:00:00',[DateTimeKind]::Utc);$null=Get-WelaFileProbeStateKey $script:state
$script:operation.Read.StartedUtc=[datetime]::SpecifyKind([datetime]'2026-09-21T00:00:00.0001000',[DateTimeKind]::Utc)
Assert-WelaFileProbeOperation $script:operation $script:state $script:nonce 1234 ([datetimeoffset]'2026-09-21T00:00:00Z') ([datetimeoffset]'2026-09-21T00:00:01Z');Assert $true 'older PowerShell UTC DateTime observations remain valid'
# Compile the exact retained bytes even on portable hosts; invoke no native API.
function Initialize-WelaWmiProbeNative {}
Initialize-WelaFileProbeNative
Assert ([Wela.FileAccessProbe.FileHandle]::SourceSha256 -ceq (Get-FileHash (Join-Path $script:ScriptRoot 'scripts/FileAccessProbeNative.cs')).Hash.ToLowerInvariant()) 'compiled helper carries the SHA256 of the exact decoded source bytes'
Initialize-WelaFileProbeNative;Assert $true 'identical compiled helper binding is reusable'
Remove-Item Function:Initialize-WelaWmiProbeNative
$sources=Get-WelaFileProbeSources
foreach($name in @('scripts/CustomAuditProfiles.ps1','scripts/ChannelReadNative.cs','scripts/Configuration.ps1','scripts/IpsecPrerequisites.ps1','modules/AuditProfiles.psm1','config/audit_profiles.json')){Assert ($sources.$name -ceq (Get-FileHash (Join-Path $script:ScriptRoot $name)).Hash.ToLowerInvariant()) 'actual transitive dependency fingerprint is included'}

$script:writer=(Get-Command Write-WelaFileProbeArtifact).ScriptBlock
function Get-WelaFileProbeOutputKey {param($Path) 'fixture-private-output'}
function Write-WelaFileProbeArtifact {param($Root,$OutputKey,$Name,$Text) if($Name -eq $script:failArtifact){throw 'injected durable artifact failure'};& $script:writer $Root $OutputKey $Name $Text}
function Get-WelaFileProbeState {param($Path) Copy-Value $script:state}
function Start-WelaFileProbeRead {param($State,$RequestPath,$Nonce) $script:reads++;Assert (Test-Path (Join-Path (Split-Path $RequestPath) 'intent.json')) 'durable intent precedes each worker attempt';if($script:workerFailure){throw 'worker failed after a possible attempt'};$operation=Copy-Value $script:operation;$operation.Nonce=$Nonce;if($script:afterDrift){$script:state.Sources.Source='f'*64};$operation}
function Read-WelaFileProbeEvents {param($Operation) $xml=Native-Xml;$items=if($script:batchMode -eq 'empty'){@()}elseif($script:batchMode -eq 'duplicate'){@($xml,$xml)}else{@($xml)};[pscustomobject]@{Xml=$items;Capped=($script:batchMode -eq 'capped');Query='fixture'}}
function Get-WelaFileProbeWatermark {11}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-file-probe-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
try {
    New-Fixture;$report=Invoke-WelaFileAccessProbe -FilePath $script:state.File.Path
    Assert ($report.Status -ceq 'PrerequisitesObserved' -and $script:reads -eq 0 -and -not $report.OutputPath) 'Plan observes prerequisites without files or byte reads'
    New-Fixture;$report=Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root 'success')
    Assert ($report.Status -ceq 'FileReadObserved' -and $script:reads -eq 1 -and $report.Matches -eq 1 -and $report.Artifacts.Count -eq 5 -and $report.RetainedContentBytes -eq 0 -and $report.SigmaEvtxCredit -eq 0) 'successful report retains five hashed metadata/XML artifacts and no byte content'
    foreach($mode in @('capped','duplicate','empty')){New-Fixture;$script:batchMode=$mode;$report=Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root $mode) -TimeoutSeconds 1;Assert ($report.Status -ceq 'Unverified' -and $report.ExitCode -eq 1) 'capped, duplicated or absent source evidence remains unverified'}
    New-Fixture;$script:afterDrift=$true;$report=Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root 'drift')
    Assert ($report.Status -ceq 'Unverified' -and $report.Diagnostic -match 'changed during the probe') 'late implementation drift prevents event readiness even after a matched record'
    New-Fixture;$script:workerFailure=$true;$report=Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root 'worker-failure')
    Assert ($report.Status -ceq 'Unverified' -and (Test-Path (Join-Path $root 'worker-failure/intent.json')) -and -not(Test-Path (Join-Path $root 'worker-failure/operation.json'))) 'uncertain worker attempt retains intent without fabricating completion'
    New-Fixture;$script:failArtifact='intent.json';$report=Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root 'intent-failure')
    Assert ($report.ExitCode -eq 1 -and $script:reads -eq 0) 'failed durable intent prevents worker launch'
    New-Fixture;$script:failArtifact='manifest.json'
    Reject {Invoke-WelaFileAccessProbe -Action Run -FilePath $script:state.File.Path -OutputPath (Join-Path $root 'manifest-failure')} 'durable artifact failure'
    Assert ((Test-Path (Join-Path $root 'manifest-failure/operation.json')) -and (Test-Path (Join-Path $root 'manifest-failure/event.xml'))) 'manifest persistence failure fails outward while completed evidence remains'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "Passed $script:checks file-access probe assertions; no Windows settings or file data changed."
