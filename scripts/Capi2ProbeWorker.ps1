# Fixed local operation. The parent bounds this process to twenty seconds.
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'WmiProbe.ps1')
. (Join-Path $PSScriptRoot 'Capi2Probe.ps1')
Initialize-WelaCapi2ProbeNative
$before=[Wela.WmiProbe.Native]::Snapshot()
$key=$null;$rsa=$null;$certificate=$null
try {
 $key=[Wela.Capi2Probe.Native]::CreateEphemeralRsa()
 if(-not $key.IsEphemeral -or $key.KeyName){throw 'The generated CNG key is not ephemeral.'}
 $rsa=[Security.Cryptography.RSACng]::new($key)
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(('CN=WelaCapi2Probe_'+$Nonce),$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $now=[DateTimeOffset][Wela.WmiProbe.Native]::UtcNow()
 $generator=[Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($rsa,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $certificate=$request.Create($request.SubjectName,$generator,$now.AddMinutes(-5),$now.AddMinutes(5),[guid]::NewGuid().ToByteArray())
 if($certificate.HasPrivateKey){throw 'Only a public certificate is expected.'}
 $der=$certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
 $started=[Wela.WmiProbe.Native]::UtcNow()
 $chain=[Wela.Capi2Probe.Native]::Build($der)
 $completed=[Wela.WmiProbe.Native]::UtcNow()
 $after=[Wela.WmiProbe.Native]::Snapshot()
 if((Get-WelaWmiProbeTokenKey $before) -cne (Get-WelaWmiProbeTokenKey $after)){throw 'Worker token changed during the chain build.'}
 [pscustomobject]@{Nonce=$Nonce;CertificateDerBase64=[Convert]::ToBase64String($der);Thumbprint=$certificate.Thumbprint;Subject=$certificate.Subject;KeyEphemeral=$key.IsEphemeral;ProcessId=$PID;ProcessName=[IO.Path]::GetFileName((Get-Process -Id $PID).Path);StartedUtc=$started.ToString('o');CompletedUtc=$completed.ToString('o');Clock='GetSystemTimePreciseAsFileTime';BeforeToken=$before;AfterToken=$after;Chain=$chain}|ConvertTo-Json -Depth 12 -Compress
}finally{if($certificate){$certificate.Dispose()};if($rsa){$rsa.Dispose()};if($key){$key.Dispose()}}
