$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WmiProbe.ps1"
. "$repo/scripts/Capi2Probe.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,$Message){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Assert $failed $Message}
function Clone($Value){ConvertFrom-WelaArrivalJson ($Value|ConvertTo-Json -Depth 24)}
$nonce='0123456789abcdef0123456789abcdef';$now=[DateTime]::UtcNow
$token=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='HOST\user';AuthenticationId='0x1234';AuthenticationType='NTLM';Groups=@([pscustomobject]@{Sid='S-1-5-32-545';Attributes=7});Privileges=@()}
$state=[pscustomobject]@{Computer='HOST';Host=[pscustomobject]@{Computer='HOST';Build=20348;UBR=1;ProductType=3;DomainJoined=$false;Domain='WORKGROUP'};Token=$token;Channel=[pscustomobject]@{Name='Microsoft-Windows-CAPI2/Operational';Enabled=$true;SecurityDescriptor='O:SYG:SYD:(A;;1;;;SY)';Type='Operational';Provider='Microsoft-Windows-CAPI2'};Provider=[pscustomobject]@{Name='Microsoft-Windows-CAPI2';Guid='5bbca4a8-b209-48dc-a8c7-b23d3e5216fb';Event11Versions=@(0);LogNames=@('Microsoft-Windows-CAPI2/Operational')}}
$rsa=[Security.Cryptography.RSA]::Create();$rsa.KeySize=2048;$cert=$null
try{
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(('CN=WelaCapi2Probe_'+$nonce),$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $cert=$request.CreateSelfSigned(([DateTimeOffset]$now).AddMinutes(-5),([DateTimeOffset]$now).AddMinutes(5))
 $operation=[pscustomobject]@{Nonce=$nonce;CertificateDerBase64=[Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert));Subject=$cert.Subject;Thumbprint=$cert.Thumbprint;KeyEphemeral=$true;ProcessId=5678;ProcessName='pwsh.exe';StartedUtc=$now.AddSeconds(-1).ToString('o');CompletedUtc=$now.AddSeconds(1).ToString('o');Clock='GetSystemTimePreciseAsFileTime';RecordIdBefore=10;BeforeToken=$token;AfterToken=$token;Chain=[pscustomobject]@{Flags=2147492100;ErrorStatus=32;Chains=1;Elements=1}}
 $der=Assert-WelaCapi2ProbeCertificate $operation $nonce;Assert ($der.Length -gt 128) 'Generated test DER is validated.'
}finally{if($cert){$cert.Dispose()};$rsa.Dispose()}
foreach($field in @('Nonce','Subject','Thumbprint','CertificateDerBase64')){$bad=Clone $operation;$bad.$field='wrong';Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} "Reject certificate $field mismatch"}
foreach($value in @($false,'true',$null)){$bad=Clone $operation;$bad.KeyEphemeral=$value;Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} 'Ephemeral key evidence must be true Boolean.'}
foreach($field in @('Flags','ErrorStatus','Chains','Elements')){$bad=Clone $operation;$bad.Chain.$field=0;Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} "Reject unexpected native chain $field"}
$bad=Clone $operation;$bad.CompletedUtc=$now.AddMinutes(20).ToString('o');Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} 'Certificate must cover operation.'
Assert ([bool](Get-WelaCapi2ProbeStateKey $state)) 'Exact observed prerequisites accepted.'
foreach($edit in @({param($s)$s.Host.Build=19045},{param($s)$s.Host.UBR=$null},{param($s)$s.Host.ProductType=1},{param($s)$s.Host.Computer='OTHER'},{param($s)$s.Channel.Enabled=$false},{param($s)$s.Channel.Enabled='true'},{param($s)$s.Channel.Type='Analytical'},{param($s)$s.Channel.Provider='Other'},{param($s)$s.Channel.SecurityDescriptor=$null},{param($s)$s.Provider.Guid=[guid]::Empty.ToString()},{param($s)$s.Provider.Event11Versions=@(1)},{param($s)$s.Provider.Event11Versions=@(0,0)},{param($s)$s.Provider.LogNames=@('Security')})){$bad=Clone $state;&$edit $bad;Reject {Get-WelaCapi2ProbeStateKey $bad} 'Reject incomplete or unsupported prerequisites.'}
$xml=@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CAPI2" Guid="{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}"/><EventID>11</EventID><Version>0</Version><Level>2</Level><Task>11</Task><Opcode>2</Opcode><Keywords>0x4000000000000003</Keywords><TimeCreated SystemTime="$($now.ToString('o'))"/><EventRecordID>11</EventRecordID><Execution ProcessID="5678" ThreadID="1"/><Channel>Microsoft-Windows-CAPI2/Operational</Channel><Computer>HOST</Computer><Security UserID="$($token.Sid)"/></System><UserData><CertGetCertificateChain><Certificate fileRef="$($operation.Thumbprint).cer" subjectName="WelaCapi2Probe_$nonce"/><Flags value="80002104"/><ChainEngineInfo context="user"/><CertificateChain><TrustStatus><ErrorStatus value="20"/></TrustStatus><ChainElement><Certificate fileRef="$($operation.Thumbprint).cer" subjectName="WelaCapi2Probe_$nonce"/><TrustStatus><ErrorStatus value="20"/></TrustStatus></ChainElement></CertificateChain><EventAuxInfo ProcessName="pwsh.exe"/><Result value="800B0109"/></CertGetCertificateChain></UserData></Event>
"@
Assert (Test-WelaCapi2ProbeEvent $xml $operation $state) 'Exact source/certificate/PID/token/time/chain fixture matches.'
$changes=@(
 @('Name="Microsoft-Windows-CAPI2"','Name="Other"'),@('5bbca4a8-b209-48dc-a8c7-b23d3e5216fb','00000000-0000-0000-0000-000000000000'),@('<EventID>11</EventID>','<EventID>70</EventID>'),@('<Version>0</Version>','<Version>1</Version>'),@('<Level>2</Level>','<Level>4</Level>'),@('<Task>11</Task>','<Task>10</Task>'),@('<Opcode>2</Opcode>','<Opcode>1</Opcode>'),@('0x4000000000000003','0x4000000000000001'),@('<EventRecordID>11</EventRecordID>','<EventRecordID>10</EventRecordID>'),@('<EventRecordID>11</EventRecordID>','<EventRecordID>x</EventRecordID>'),@('ProcessID="5678"','ProcessID="5679"'),@( ('UserID="'+$token.Sid+'"'), 'UserID="S-1-5-18"'),@('<Computer>HOST</Computer>','<Computer>OTHER</Computer>'),@('80002104','80000104'),@('800B0109','0'),@('value="20"','value="0"'),@('context="user"','context="machine"'),@('ProcessName="pwsh.exe"','ProcessName="other.exe"'),@($operation.Thumbprint,('0'*40)),@($nonce,('f'*32)),@('<UserData>','<UserData><Other/>'),@('<CertGetCertificateChain>','<CertGetCertificateChain xmlns="urn:other">'),@('<Version>0</Version>','<Version>0</Version><Version>0</Version>'),@('<Flags value="80002104"/>','<Flags value="80002104"/><Flags value="80002104"/>'),@('</UserData>','</UserData><EventData/>'),@('<Event xmlns=','<!DOCTYPE Event [<!ENTITY test "x">]><Event xmlns=')
)
foreach($pair in $changes){Assert (-not(Test-WelaCapi2ProbeEvent ($xml.Replace($pair[0],$pair[1])) $operation $state)) ('Reject altered XML '+$pair[0])}
foreach($time in @($now.AddSeconds(-2).ToString('o'),$now.AddSeconds(2).ToString('o'),$now.ToString('yyyy-MM-ddTHH:mm:ss'),$now.ToString('yyyy-MM-ddTHH:mm:ss')+'+00:00')){Assert (-not(Test-WelaCapi2ProbeEvent ($xml.Replace($now.ToString('o'),$time)) $operation $state)) 'Reject outside or ambiguous UTC.'}
foreach($time in @($operation.StartedUtc,$operation.CompletedUtc)){Assert (Test-WelaCapi2ProbeEvent ($xml.Replace($now.ToString('o'),$time)) $operation $state) 'Accept exact inclusive operation boundary.'}
$null=Assert-WelaWmiProbeInterval $operation ([DateTimeOffset]$now.AddSeconds(-2)) ([DateTimeOffset]$now.AddSeconds(2));$count++
$bad=Clone $operation;$bad.Clock='UtcNow';Reject {Assert-WelaWmiProbeInterval $bad ([DateTimeOffset]$now.AddSeconds(-2)) ([DateTimeOffset]$now.AddSeconds(2))} 'Require precise native clock.'
Reject {Invoke-WelaCapi2Probe -Action Run} 'Run requires a new private output path.'
Reject {Invoke-WelaCapi2Probe -Action Plan -OutputPath unused} 'Plan creates no files.'
Write-Host "PASS: $count portable CAPI2 assertions. No native event proof is claimed."
$global:LASTEXITCODE=0
