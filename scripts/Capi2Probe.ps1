# Explicit fixed local CAPI2 source measurement. No channel, key-store or trust-policy writes.
function Initialize-WelaCapi2ProbeNative {
 Initialize-WelaWmiProbeNative
 $source=Join-Path $PSScriptRoot 'Capi2ProbeNative.cs';$hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
 if(-not ('Wela.Capi2Probe.Native' -as [type])){Add-Type -Path $source -ErrorAction Stop;$script:WelaCapi2ProbeNativeHash=$hash}
 if($script:WelaCapi2ProbeNativeHash -cne $hash){throw 'Loaded CAPI2 helper differs from its source; start a fresh session.'}
}
function Get-WelaCapi2ProbeSources {
 $sources=[ordered]@{}
 foreach($name in @('WELA.ps1','scripts/Capi2Probe.ps1','scripts/Capi2ProbeWorker.ps1','scripts/Capi2ProbeNative.cs','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/ChannelRead.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$name)) -Algorithm SHA256).Hash.ToLowerInvariant()}
 $sources|ConvertTo-Json -Compress
}
function Get-WelaCapi2ProbeChannel {
 $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-CAPI2/Operational')
 try{[pscustomobject][ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode;Type=[string]$channel.LogType;Provider=$channel.OwningProviderName}}finally{$channel.Dispose()}
}
function Get-WelaCapi2ProbeState {
 Initialize-WelaCapi2ProbeNative
 $services=@(Get-Service -Name Winmgmt,CryptSvc,EventLog -ErrorAction Stop|Sort-Object Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status}})
 if($services.Count -ne 3 -or @($services|Where-Object Status -ne 'Running').Count){throw 'Winmgmt, CryptSvc and EventLog must already be running; the probe starts no service.'}
 $token=[Wela.WmiProbe.Native]::Snapshot();$hostState=Get-WelaChannelReadHost
 $provider=[Diagnostics.Eventing.Reader.ProviderMetadata]::new('Microsoft-Windows-CAPI2')
 try{$event=@($provider.Events|Where-Object Id -eq 11);$metadata=[pscustomobject]@{Name=$provider.Name;Guid=$provider.Id.ToString();Event11Versions=@($event|ForEach-Object Version);LogNames=@($provider.LogLinks|ForEach-Object LogName|Sort-Object)}}finally{$provider.Dispose()}
 $engine=(Get-Process -Id $PID).Path
 $state=[pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostState;Services=$services;Token=$token;Channel=(Get-WelaCapi2ProbeChannel);Provider=$metadata;Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant();Sources=(Get-WelaCapi2ProbeSources)}
 if((Get-WelaWmiProbeTokenKey $token) -cne (Get-WelaWmiProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot()))){throw 'Token changed during CAPI2 prerequisite observation.'}
 $state
}
function Get-WelaCapi2ProbeStateKey {
 param($State)
 if(@($State.Services).Count -ne 3 -or (@($State.Services.Name|Sort-Object) -join ',') -cne 'CryptSvc,EventLog,Winmgmt' -or @($State.Services|Where-Object Status -cne 'Running').Count){throw 'Required native services must already be running.'}
 if($State.Host.Build -notin @(20348,26100) -or $State.Host.ProductType -notin @(2,3) -or -not $State.Host.UBR -or $State.Host.Computer -cne $State.Computer){throw 'CAPI2 probe requires an observed Server 2022/2025 build and patch context.'}
 if($State.Channel.Enabled -isnot [bool] -or -not $State.Channel.Enabled -or $State.Channel.Name -cne 'Microsoft-Windows-CAPI2/Operational' -or $State.Channel.Type -cne 'Operational' -or $State.Channel.Provider -cne 'Microsoft-Windows-CAPI2' -or -not $State.Channel.SecurityDescriptor){throw 'CAPI2 Operational must already be enabled with an observed descriptor.'}
 if($State.Provider.Name -cne 'Microsoft-Windows-CAPI2' -or $State.Provider.Guid -ine '5bbca4a8-b209-48dc-a8c7-b23d3e5216fb' -or @($State.Provider.Event11Versions).Count -ne 1 -or $State.Provider.Event11Versions[0] -ne 0 -or $State.Channel.Name -cnotin $State.Provider.LogNames){throw 'Unreviewed CAPI2 provider or event11 schema version.'}
 $null=Get-WelaWmiProbeTokenKey $State.Token
 $State|ConvertTo-Json -Depth 16 -Compress
}
function Get-WelaCapi2ProbeWatermark {
 $latest=Read-WelaChannelLatest 'Microsoft-Windows-CAPI2/Operational'
 if($latest.Status -eq 'ReadAllowedEmpty'){return [long]0}
 if($latest.Status -ne 'EventObserved'){throw ('CAPI2 is not readable: '+$latest.Status+' '+$latest.Diagnostic)}
 [long]$latest.Event.RecordId
}
function Assert-WelaCapi2ProbeCertificate {
 param($Operation,[string]$Nonce)
 if($Nonce -cnotmatch '^[a-f0-9]{32}$' -or $Operation.Nonce -cne $Nonce -or $Operation.KeyEphemeral -isnot [bool] -or -not $Operation.KeyEphemeral -or $Operation.CertificateDerBase64 -isnot [string] -or $Operation.CertificateDerBase64.Length -gt 12000){throw 'Unexpected generated certificate identity.'}
 $der=[Convert]::FromBase64String($Operation.CertificateDerBase64)
 if($der.Length -lt 128 -or $der.Length -gt 8192){throw 'Certificate DER exceeds its evidence bound.'}
 $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
 try{
  if($certificate.Subject -cne ('CN=WelaCapi2Probe_'+$Nonce) -or $certificate.Issuer -cne $certificate.Subject -or $Operation.Subject -cne $certificate.Subject -or $Operation.Thumbprint -cne $certificate.Thumbprint -or $certificate.Extensions.Count -ne 0 -or $certificate.HasPrivateKey -or $certificate.SignatureAlgorithm.Value -cne '1.2.840.113549.1.1.11' -or $certificate.PublicKey.Oid.Value -cne '1.2.840.113549.1.1.1'){throw 'Certificate DER does not describe the fixed ephemeral self-signed probe.'}
  $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
  try{if($rsa.get_KeySize() -ne 2048){throw 'Unexpected probe RSA key size.'}}finally{$rsa.Dispose()}
  $start=ConvertTo-WelaArrivalUtc $Operation.StartedUtc;$end=ConvertTo-WelaArrivalUtc $Operation.CompletedUtc
  if($certificate.NotBefore.ToUniversalTime() -gt $start.UtcDateTime -or $certificate.NotAfter.ToUniversalTime() -lt $end.UtcDateTime -or ($certificate.NotAfter-$certificate.NotBefore).TotalMinutes -gt 11){throw 'Certificate validity does not cover the bounded operation.'}
  if($Operation.Chain.Flags -ne 2147492100 -or $Operation.Chain.ErrorStatus -ne 32 -or $Operation.Chain.Chains -ne 1 -or $Operation.Chain.Elements -ne 1){throw 'Expected one offline untrusted self-signed native chain.'}
 }finally{$certificate.Dispose()}
 ,$der
}
function Start-WelaCapi2ProbeBuild {
 param($State)
 if((Get-WelaCapi2ProbeStateKey (Get-WelaCapi2ProbeState)) -cne (Get-WelaCapi2ProbeStateKey $State)){throw 'CAPI2 prerequisites changed before the operation.'}
 $watermark=Get-WelaCapi2ProbeWatermark;$nonce=[guid]::NewGuid().ToString('N')
 $worker=Join-Path $PSScriptRoot 'Capi2ProbeWorker.ps1'
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Engine;$info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Nonce '+$nonce
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=$info.StandardOutputEncoding
 $process=$null
 try{
  $launch=[DateTimeOffset][Wela.WmiProbe.Native]::UtcNow();$process=[Diagnostics.Process]::Start($info);$output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(20000)){$process.Kill();$null=$process.WaitForExit(1000);throw 'Fixed CAPI2 worker exceeded twenty seconds.'}
  if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($output,$errors),1000)){throw 'Fixed worker output did not complete.'}
  if($output.Result.Length -gt 262144 -or $errors.Result.Length -gt 65536){throw 'Worker output exceeded its evidence bound.'}
  if($process.ExitCode -ne 0 -or $errors.Result){throw ('Fixed CAPI2 worker failed: '+$errors.Result)}
  $operation=ConvertFrom-WelaArrivalJson $output.Result
  if($operation.ProcessId -ne $process.Id -or $operation.ProcessName -ine [IO.Path]::GetFileName($State.Engine)){throw 'Worker process identity differs.'}
  $interval=Assert-WelaWmiProbeInterval $operation $launch ([DateTimeOffset][Wela.WmiProbe.Native]::UtcNow())
  $operation.StartedUtc=$interval.Start.UtcDateTime.ToString('o');$operation.CompletedUtc=$interval.End.UtcDateTime.ToString('o')
  $der=Assert-WelaCapi2ProbeCertificate $operation $nonce
  if((Get-WelaWmiProbeTokenKey $operation.BeforeToken) -cne (Get-WelaWmiProbeTokenKey $operation.AfterToken) -or (Get-WelaWmiProbeTokenKey $operation.BeforeToken -AuthorizationOnly) -cne (Get-WelaWmiProbeTokenKey $State.Token -AuthorizationOnly)){throw 'Worker token differs from caller or changed during operation.'}
  $operation|Add-Member NoteProperty RecordIdBefore $watermark
  $operation|Add-Member NoteProperty CertificateSha256 (Get-WelaArrivalHash $der)
  $operation
 }finally{if($process){try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(1000)}}finally{$process.Dispose()}}}
}
function Read-WelaCapi2ProbeEvents {
 param($Operation)
 $query="*[System[Provider[@Name='Microsoft-Windows-CAPI2'] and EventID=11 and EventRecordID>$($Operation.RecordIdBefore) and Execution[@ProcessID='$($Operation.ProcessId)'] and TimeCreated[@SystemTime>='$($Operation.StartedUtc)' and @SystemTime<='$($Operation.CompletedUtc)']]]"
 $records=@();$xml=@()
 try{try{$records=@(Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -FilterXPath $query -MaxEvents 64 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
  foreach($record in $records){$text=[string]$record.ToXml();if($text.Length -gt 131072){throw 'CAPI2 event exceeds 128 KiB characters.'};$xml+=$text}
  [pscustomobject]@{Xml=$xml;Capped=($records.Count -ge 64);Query=$query;MaximumEvents=64}
 }finally{foreach($record in $records){$record.Dispose()}}
}
function Test-WelaCapi2XmlChildren {
 param($Node,[string[]]$Names)
 $children=@($Node.ChildNodes|Where-Object NodeType -eq Element)
 if($children.Count -ne $Names.Count -or @($Node.ChildNodes|Where-Object {$_.NodeType -notin @('Element','Whitespace')}).Count){return $false}
 foreach($name in $Names){if(@($children|Where-Object {$_.LocalName -ceq $name -and $_.NamespaceURI -ceq 'http://schemas.microsoft.com/win/2004/08/events/event'}).Count -ne 1){return $false}}
 $true
}
function Test-WelaCapi2ProbeEvent {
 param([string]$Xml,$Operation,$State)
 $reader=$null
 try{
  if($Xml.Length -gt 131072){return $false}
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
  $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
  $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
  if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count){return $false}
  $system=@{};foreach($name in @('Provider','EventID','Version','Level','Task','Opcode','Keywords','EventRecordID','Channel','Computer','TimeCreated','Execution','Security')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
  if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-CAPI2' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '5bbca4a8-b209-48dc-a8c7-b23d3e5216fb' -or $system.EventID.InnerText -cne '11' -or $system.Version.InnerText -cne '0' -or $system.Level.InnerText -cne '2' -or $system.Task.InnerText -cne '11' -or $system.Opcode.InnerText -cne '2' -or $system.Keywords.InnerText -ine '0x4000000000000003' -or $system.Channel.InnerText -cne 'Microsoft-Windows-CAPI2/Operational' -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.RecordIdBefore){return $false}
  $computers=@($State.Computer);if($State.Host.DomainJoined){$computers+=$State.Computer+'.'+$State.Host.Domain}
  if($system.Computer.InnerText -notin $computers -or $system.Execution.GetAttribute('ProcessID') -cne [string]$Operation.ProcessId -or $system.Security.GetAttribute('UserID') -cne $Operation.BeforeToken.Sid){return $false}
  $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime');if($time -lt (ConvertTo-WelaArrivalUtc $Operation.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.CompletedUtc)){return $false}
  $data=$doc.SelectSingleNode('/e:Event/e:UserData',$ns)
  # Namespace and exact paths are pinned to native event11, never a recursive name search.
  if(@($data.ChildNodes|Where-Object NodeType -eq Element).Count -ne 1){return $false}
  $chain=$data.SelectNodes('e:CertGetCertificateChain',$ns);if($chain.Count -ne 1){return $false};$chain=$chain[0]
  $names=@('Certificate','ExtendedKeyUsage','URLRetrievalTimeout','Flags','ChainEngineInfo','CertificateChain','EventAuxInfo','CorrelationAuxInfo','Result')
  if(-not(Test-WelaCapi2XmlChildren $chain $names)){return $false}
  $fields=@{};foreach($name in $names){$nodes=$chain.SelectNodes("e:$name",$ns);if($nodes.Count -ne 1){return $false};$fields[$name]=$nodes[0]}
  if($fields.ExtendedKeyUsage.HasChildNodes -or $fields.URLRetrievalTimeout.InnerText -cne 'PT1S' -or -not(Test-WelaCapi2XmlChildren $fields.CertificateChain @('TrustStatus','ChainElement'))){return $false}
  foreach($flag in @('CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL','CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY','CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE','CERT_CHAIN_DISABLE_AIA')){if($fields.Flags.GetAttribute($flag) -cne 'true'){return $false}}
  if($fields.EventAuxInfo.HasAttribute('impersonateToken') -and $fields.EventAuxInfo.GetAttribute('impersonateToken') -cne $Operation.BeforeToken.Sid){return $false}
  $cert=$fields.Certificate
  if($cert.GetAttribute('fileRef') -cne ($Operation.Thumbprint+'.cer') -or $cert.GetAttribute('subjectName') -cne ('WelaCapi2Probe_'+$Operation.Nonce) -or $fields.Flags.GetAttribute('value') -ine '80002104' -or $fields.ChainEngineInfo.GetAttribute('context') -cne 'user' -or $fields.EventAuxInfo.GetAttribute('ProcessName') -ine $Operation.ProcessName -or $fields.Result.GetAttribute('value') -ine '800B0109'){return $false}
  $error=$fields.CertificateChain.SelectNodes('e:TrustStatus/e:ErrorStatus',$ns);$elements=$fields.CertificateChain.SelectNodes('e:ChainElement',$ns)
  if($error.Count -ne 1 -or $error[0].GetAttribute('value') -cne '20' -or $elements.Count -ne 1){return $false}
  $elementCert=$elements[0].SelectNodes('e:Certificate',$ns);$elementError=$elements[0].SelectNodes('e:TrustStatus/e:ErrorStatus',$ns)
  if($elementCert.Count -ne 1 -or $elementCert[0].GetAttribute('fileRef') -cne $cert.GetAttribute('fileRef') -or $elementCert[0].GetAttribute('subjectName') -cne $cert.GetAttribute('subjectName') -or $elementError.Count -ne 1 -or $elementError[0].GetAttribute('value') -cne '20'){return $false}
  if(-not(Test-WelaCapi2XmlChildren $elements[0] @('Certificate','SignatureAlgorithm','PublicKeyAlgorithm','TrustStatus','ApplicationUsage','IssuanceUsage'))){return $false}
  $signature=$elements[0].SelectSingleNode('e:SignatureAlgorithm',$ns);$publicKey=$elements[0].SelectSingleNode('e:PublicKeyAlgorithm',$ns)
  if($signature.GetAttribute('oid') -cne '1.2.840.113549.1.1.11' -or $signature.GetAttribute('hashName') -cne 'SHA256' -or $signature.GetAttribute('publicKeyName') -cne 'RSA' -or $publicKey.GetAttribute('oid') -cne '1.2.840.113549.1.1.1' -or $publicKey.GetAttribute('publicKeyLength') -cne '2048'){return $false}
  return $true
 }catch{return $false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaCapi2Probe {
 param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
 if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new Capi2ProbeOutputPath; Plan creates no files.'}
 $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaOfflineCapi2ChainProbe';Action=$Action;Status='Unverified';ExitCode=1;Before=$null;After=$null;Operation=$null;Query=$null;Candidates=0;Matches=0;Artifacts=@();Diagnostic='';OutputPath=$null;ChannelChanges=0;StoreChanges=0;TrustPolicyChanges=0;ReadyRuleCredit=0;Scope='One fixed local ephemeral certificate-chain build and matching CAPI2 event11 only. Untrusted self-signed outcome expected; no TLS, revocation, remote, forwarding, catalog event70 or Sigma/backend validation. Sysmon excluded.'}
 if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $PSScriptRoot}
 try{
  $before=Get-WelaCapi2ProbeState;$report.Before=$before;$key=Get-WelaCapi2ProbeStateKey $before;$null=Get-WelaCapi2ProbeWatermark
  if($Action -eq 'Plan'){$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
  $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 20)
  $operation=Start-WelaCapi2ProbeBuild $before;$report.Operation=$operation
  $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'operation.json' ($operation|ConvertTo-Json -Depth 16)
  $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'certificate.pem' ("-----BEGIN CERTIFICATE-----`n"+$operation.CertificateDerBase64+"`n-----END CERTIFICATE-----`n")
  $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
  do{$batch=Read-WelaCapi2ProbeEvents $operation;$report.Query=$batch.Query;$report.Candidates=@($batch.Xml).Count
   if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'The 64-event query cap was reached or completeness is unknown.'}
   $matches=@($batch.Xml|Where-Object {Test-WelaCapi2ProbeEvent $_ $operation $before});if($matches.Count){break};Start-Sleep -Milliseconds 250
  }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
  $report.Matches=$matches.Count
  if($matches.Count -ne 1){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('candidate-'+$i+'.xml') $xml};throw 'Expected exactly one matching CAPI2 event11 in the fixed operation interval.'}
  $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'event.xml' $matches[0]
  if((Get-WelaCapi2ProbeWatermark) -lt $operation.RecordIdBefore){throw 'CAPI2 record boundary moved backwards; continuity is unknown.'}
  $after=Get-WelaCapi2ProbeState;$report.After=$after;if((Get-WelaCapi2ProbeStateKey $after) -cne $key){throw 'Host, token, provider, channel or implementation changed during collection.'}
  $report.Status='LocalChainEventObserved';$report.ExitCode=0
 }catch{$report.Diagnostic=$_.Exception.Message}
 finally{if($report.Before -and -not $report.After){try{$report.After=Get-WelaCapi2ProbeState}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}};if($report.OutputPath -and $report.After){$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'after.json' ($report.After|ConvertTo-Json -Depth 20)}}
 if($report.OutputPath){$null=Write-WelaArrivalArtifact $report.OutputPath 'manifest.json' ($report|ConvertTo-Json -Depth 24)}
 $report
}
