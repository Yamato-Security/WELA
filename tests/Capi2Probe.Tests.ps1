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
$state=[pscustomobject]@{Computer='HOST';Services=@([pscustomobject]@{Name='CryptSvc';Status='Running'},[pscustomobject]@{Name='EventLog';Status='Running'},[pscustomobject]@{Name='Winmgmt';Status='Running'});Host=[pscustomobject]@{Computer='HOST';Build=20348;UBR=1;ProductType=3;DomainJoined=$false;Domain='WORKGROUP'};Token=$token;Channel=[pscustomobject]@{Name='Microsoft-Windows-CAPI2/Operational';Enabled=$true;SecurityDescriptor='O:SYG:SYD:(A;;1;;;SY)';Type='Operational';Provider='Microsoft-Windows-CAPI2'};Provider=[pscustomobject]@{Name='Microsoft-Windows-CAPI2';Guid='5bbca4a8-b209-48dc-a8c7-b23d3e5216fb';Event11Versions=@(0);LogNames=@('Microsoft-Windows-CAPI2/Operational')}}
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){$rsa=[Security.Cryptography.RSACng]::new(2048)}else{$rsa=[Security.Cryptography.RSA]::Create();$rsa.KeySize=2048};$cert=$null
try{
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(('CN=WelaCapi2Probe_'+$nonce),$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $cert=$request.CreateSelfSigned(([DateTimeOffset]$now).AddMinutes(-5),([DateTimeOffset]$now).AddMinutes(5))
 $operation=[pscustomobject]@{Nonce=$nonce;CertificateDerBase64=[Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert));Subject=$cert.Subject;Thumbprint=$cert.Thumbprint;KeyEphemeral=$true;ProcessId=5678;ProcessName='pwsh.exe';StartedUtc=$now.AddSeconds(-1).ToString('o');CompletedUtc=$now.AddSeconds(1).ToString('o');Clock='GetSystemTimePreciseAsFileTime';RecordIdBefore=10;BeforeToken=$token;AfterToken=$token;Chain=[pscustomobject]@{Flags=2147492100;ErrorStatus=32;Chains=1;Elements=1}}
 $der=Assert-WelaCapi2ProbeCertificate $operation $nonce;Assert ($der.Length -gt 128) 'Generated test DER is validated.'
}finally{if($cert){$cert.Dispose()};$rsa.Dispose()}
$bad=Clone $operation;$bad.CertificateDerBase64=[Convert]::ToBase64String(([byte[]]([Convert]::FromBase64String($operation.CertificateDerBase64)+[byte[]]@(0))));Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} 'Reject trailing data after the actual certificate DER.'
foreach($field in @('Nonce','Subject','Thumbprint','CertificateDerBase64')){$bad=Clone $operation;$bad.$field='wrong';Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} "Reject certificate $field mismatch"}
foreach($value in @($false,'true',$null)){$bad=Clone $operation;$bad.KeyEphemeral=$value;Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} 'Ephemeral key evidence must be true Boolean.'}
foreach($field in @('Flags','ErrorStatus','Chains','Elements')){$bad=Clone $operation;$bad.Chain.$field=0;Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} "Reject unexpected native chain $field"}
$bad=Clone $operation;$bad.CompletedUtc=$now.AddMinutes(20).ToString('o');Reject {Assert-WelaCapi2ProbeCertificate $bad $nonce} 'Certificate must cover operation.'
Assert ([bool](Get-WelaCapi2ProbeStateKey $state)) 'Exact observed prerequisites accepted.'
foreach($edit in @({param($s)$s.Services[0].Status='Stopped'},{param($s)$s.Services=@()},{param($s)$s.Host.Build=19045},{param($s)$s.Host.UBR=$null},{param($s)$s.Host.ProductType=1},{param($s)$s.Host.Computer='OTHER'},{param($s)$s.Channel.Enabled=$false},{param($s)$s.Channel.Enabled='true'},{param($s)$s.Channel.Type='Analytical'},{param($s)$s.Channel.Provider='Other'},{param($s)$s.Channel.SecurityDescriptor=$null},{param($s)$s.Provider.Guid=[guid]::Empty.ToString()},{param($s)$s.Provider.Event11Versions=@(1)},{param($s)$s.Provider.Event11Versions=@(0,0)},{param($s)$s.Provider.LogNames=@('Security')})){$bad=Clone $state;&$edit $bad;Reject {Get-WelaCapi2ProbeStateKey $bad} 'Reject incomplete or unsupported prerequisites.'}
$xml=@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CAPI2" Guid="{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}"/><EventID>11</EventID><Version>0</Version><Level>2</Level><Task>11</Task><Opcode>2</Opcode><Keywords>0x4000000000000003</Keywords><TimeCreated SystemTime="$($now.ToString('o'))"/><EventRecordID>11</EventRecordID><Execution ProcessID="5678" ThreadID="1"/><Channel>Microsoft-Windows-CAPI2/Operational</Channel><Computer>HOST</Computer><Security UserID="$($token.Sid)"/></System><UserData><CertGetCertificateChain><Certificate fileRef="$($operation.Thumbprint).cer" subjectName="WelaCapi2Probe_$nonce"/><ExtendedKeyUsage/><URLRetrievalTimeout>PT1S</URLRetrievalTimeout><Flags value="80002104" CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL="true" CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY="true" CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE="true" CERT_CHAIN_DISABLE_AIA="true"/><ChainEngineInfo context="user"/><CertificateChain><TrustStatus><ErrorStatus value="20"/></TrustStatus><ChainElement><Certificate fileRef="$($operation.Thumbprint).cer" subjectName="WelaCapi2Probe_$nonce"/><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256" publicKeyName="RSA"/><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyLength="2048"/><TrustStatus><ErrorStatus value="20"/></TrustStatus><ApplicationUsage any="true"/><IssuanceUsage any="true"/></ChainElement></CertificateChain><EventAuxInfo ProcessName="pwsh.exe"/><CorrelationAuxInfo TaskId="{00000000-0000-0000-0000-000000000001}" SeqNumber="3"/><Result value="800B0109"/></CertGetCertificateChain></UserData></Event>
"@
Assert (Test-WelaCapi2ProbeEvent $xml $operation $state) 'Exact source/certificate/PID/token/time/chain fixture matches.'
$changes=@(
 @('Name="Microsoft-Windows-CAPI2"','Name="Other"'),@('5bbca4a8-b209-48dc-a8c7-b23d3e5216fb','00000000-0000-0000-0000-000000000000'),@('<EventID>11</EventID>','<EventID>70</EventID>'),@('<Version>0</Version>','<Version>1</Version>'),@('<Level>2</Level>','<Level>4</Level>'),@('<Task>11</Task>','<Task>10</Task>'),@('<Opcode>2</Opcode>','<Opcode>1</Opcode>'),@('0x4000000000000003','0x4000000000000001'),@('<EventRecordID>11</EventRecordID>','<EventRecordID>10</EventRecordID>'),@('<EventRecordID>11</EventRecordID>','<EventRecordID>x</EventRecordID>'),@('ProcessID="5678"','ProcessID="5679"'),@( ('UserID="'+$token.Sid+'"'), 'UserID="S-1-5-18"'),@('<Computer>HOST</Computer>','<Computer>OTHER</Computer>'),@('80002104','80000104'),@('800B0109','0'),@('value="20"','value="0"'),@('context="user"','context="machine"'),@('ProcessName="pwsh.exe"','ProcessName="other.exe"'),@($operation.Thumbprint,('0'*40)),@($nonce,('f'*32)),@('<UserData>','<UserData><Other/>'),@('<CertGetCertificateChain>','<CertGetCertificateChain xmlns="urn:other">'),@('<Version>0</Version>','<Version>0</Version><Version>0</Version>'),@('<ExtendedKeyUsage/>','<ExtendedKeyUsage/><ExtendedKeyUsage/>'),@('PT1S','PT2S'),@('CERT_CHAIN_DISABLE_AIA="true"','CERT_CHAIN_DISABLE_AIA="false"'),@('<ChainEngineInfo','<AdditionalStore/><ChainEngineInfo'),@('publicKeyLength="2048"','publicKeyLength="1024"'),@('hashName="SHA256"','hashName="SHA1"'),@('<ApplicationUsage','<RevocationInfo/><ApplicationUsage'),@('</UserData>','</UserData><EventData/>'),@('<Event xmlns=','<!DOCTYPE Event [<!ENTITY test "x">]><Event xmlns=')
)
foreach($pair in $changes){Assert (-not(Test-WelaCapi2ProbeEvent ($xml.Replace($pair[0],$pair[1])) $operation $state)) ('Reject altered XML '+$pair[0])}
foreach($time in @($now.AddSeconds(-2).ToString('o'),$now.AddSeconds(2).ToString('o'),$now.ToString('yyyy-MM-ddTHH:mm:ss'),$now.ToString('yyyy-MM-ddTHH:mm:ss')+'+00:00')){Assert (-not(Test-WelaCapi2ProbeEvent ($xml.Replace($now.ToString('o'),$time)) $operation $state)) 'Reject outside or ambiguous UTC.'}
foreach($time in @($operation.StartedUtc,$operation.CompletedUtc)){Assert (Test-WelaCapi2ProbeEvent ($xml.Replace($now.ToString('o'),$time)) $operation $state) 'Accept exact inclusive operation boundary.'}
$null=Assert-WelaWmiProbeInterval $operation ([DateTimeOffset]$now.AddSeconds(-2)) ([DateTimeOffset]$now.AddSeconds(2));$count++
$bad=Clone $operation;$bad.Clock='UtcNow';Reject {Assert-WelaWmiProbeInterval $bad ([DateTimeOffset]$now.AddSeconds(-2)) ([DateTimeOffset]$now.AddSeconds(2))} 'Require precise native clock.'
Reject {Invoke-WelaCapi2Probe -Action Run} 'Run requires a new private output path.'
Reject {Invoke-WelaCapi2Probe -Action Plan -OutputPath unused} 'Plan creates no files.'
# Lifecycle fixtures test failure receipts and no-operation planning independently of Windows telemetry.
$script:FixtureState=$state;$script:FixtureOperation=$operation;$script:FixtureXml=$xml;$script:FixtureMode='success';$script:FixtureStateReads=0;$script:FixtureActions=0
function Get-WelaCapi2ProbeState {$script:FixtureStateReads++;$value=Clone $script:FixtureState;if($script:FixtureMode -eq 'drift' -and $script:FixtureStateReads -gt 1){$value.Host.UBR++};$value}
function Get-WelaCapi2ProbeWatermark {if($script:FixtureMode -eq 'denied'){throw 'Reader denied.'};if($script:FixtureMode -eq 'rollback' -and $script:FixtureActions){return [long]0};[long]11}
function Start-WelaCapi2ProbeBuild {param($State);$script:FixtureActions++;if($script:FixtureMode -eq 'worker'){throw 'Bounded worker failed.'};Clone $script:FixtureOperation}
function Read-WelaCapi2ProbeEvents {param($Operation);$items=@($script:FixtureXml);if($script:FixtureMode -eq 'none'){$items=@($script:FixtureXml.Replace('800B0109','0'))};if($script:FixtureMode -eq 'duplicate'){$items=@($script:FixtureXml,$script:FixtureXml)};[pscustomobject]@{Xml=$items;Capped=($script:FixtureMode -eq 'cap');Query='fixed-fixture';MaximumEvents=64}}
$planned=Invoke-WelaCapi2Probe
Assert ($planned.Status -eq 'PrerequisitesObserved' -and $script:FixtureActions -eq 0 -and -not $planned.OutputPath) 'Plan observes prerequisites without operation or files.'
$private=Join-Path ([IO.Path]::GetTempPath()) ('wela-capi2-fixture-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $private
try{
 foreach($mode in @('success','none','duplicate','cap','drift','rollback','worker','denied')){
  $script:FixtureMode=$mode;$script:FixtureStateReads=0;$script:FixtureActions=0
  $out=Join-Path $private $mode;$result=Invoke-WelaCapi2Probe -Action Run -OutputPath $out -TimeoutSeconds 1
  if($mode -eq 'success'){Assert ($result.Status -eq 'LocalChainEventObserved' -and $result.ExitCode -eq 0 -and (Test-Path "$out/event.xml")) 'Success retains one exact matched event.'}
  else{Assert ($result.Status -eq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) ('Failure remains explicit: '+$mode)}
  Assert (Test-Path "$out/manifest.json") 'Every started bundle retains its manifest.'
  Assert ($script:FixtureActions -le 1 -and $result.ChannelChanges -eq 0 -and $result.StoreChanges -eq 0 -and $result.TrustPolicyChanges -eq 0 -and $result.ReadyRuleCredit -eq 0) 'No operation retry or configuration/coverage credit.'
  foreach($artifact in $result.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant()) 'Lifecycle artifact hash matches.'}
 }
 Reject {Invoke-WelaCapi2Probe -Action Run -OutputPath (Join-Path $private 'success')} 'Existing evidence cannot be overwritten.'
}finally{Remove-Item -LiteralPath $private -Recurse -Force}
Write-Host "PASS: $count portable CAPI2 assertions. No native event proof is claimed."
$global:LASTEXITCODE=0
