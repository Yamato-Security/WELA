# Genuine public fixed probe. Only the disposable fixture may toggle the channel.
param([switch]$AllowDisposableChannelWrite,[ValidateRange(1,3)][int]$ProbeRuns=3)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableChannelWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable GitHub-hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/WmiProbe.ps1"
. "$repo/scripts/Capi2Probe.ps1"
$hostState=Get-WelaChannelReadHost
if($hostState.ProductType -ne 3 -or $hostState.DomainRole -ne 2 -or $hostState.DomainJoined -or $hostState.Build -notin @(20348,26100)){throw 'A disposable standalone Server 2022/2025 is required.'}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function Read-Stores {
 $result=[ordered]@{}
 foreach($location in @('CurrentUser','LocalMachine')){foreach($name in @('My','Root','CertificateAuthority')){
  $store=[Security.Cryptography.X509Certificates.X509Store]::new([Security.Cryptography.X509Certificates.StoreName]$name,[Security.Cryptography.X509Certificates.StoreLocation]$location)
  try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly);$certificates=$store.Certificates;try{$result[$location+'/'+$name]=@($certificates|ForEach-Object Thumbprint|Sort-Object)}finally{foreach($c in $certificates){$c.Dispose()}}}finally{$store.Dispose()}
 }}
 [pscustomobject]$result
}
$engine=(Get-Process -Id $PID).Path;$original=Get-WelaCapi2ProbeChannel;$originalStores=Read-Stores
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-capi2-native-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
$null=Write-WelaArrivalArtifact $root 'channel-original.json' ($original|ConvertTo-Json)
$null=Write-WelaArrivalArtifact $root 'stores-original.json' ($originalStores|ConvertTo-Json -Depth 8)
$failure=$null;$cleanupErrors=@();$nonces=@();$thumbprints=@();$changed=$false
try{
 $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($original.Name)
 try{if(-not $channel.IsEnabled){$changed=$true;$channel.IsEnabled=$true;$channel.SaveChanges()}}finally{$channel.Dispose()}
 $enabled=Get-WelaCapi2ProbeChannel
 $expected=$original|ConvertTo-Json|ConvertFrom-Json;$expected.Enabled=$true
 Assert ((Key $enabled) -ceq (Key $expected)) 'Fixture changed only channel Enabled.'
 for($trial=1;$trial -le $ProbeRuns;$trial++){
  $out=Join-Path $root ('probe-'+$trial)
  $old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$cli=&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" capi2-probe -Capi2ProbeAction Run -Capi2ProbeOutputPath $out -Capi2ProbeTimeoutSeconds 15 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
  if(-not(Test-Path "$out/manifest.json")){throw ('Public probe did not retain a manifest: '+$cli)}
  $manifest=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText("$out/manifest.json"))
  Write-Host ($manifest|ConvertTo-Json -Depth 24)
  foreach($file in @(Get-ChildItem -LiteralPath $out -Filter '*.xml')){Write-Host ([IO.File]::ReadAllText($file.FullName))}
  Assert ($code -eq 0 -and $manifest.Status -eq 'LocalChainEventObserved' -and $manifest.ExitCode -eq 0) ('Actual CAPI2 probe failed: '+$manifest.Diagnostic+' '+$cli)
  Assert ($manifest.Matches -eq 1 -and $manifest.ChannelChanges -eq 0 -and $manifest.StoreChanges -eq 0 -and $manifest.TrustPolicyChanges -eq 0 -and $manifest.ReadyRuleCredit -eq 0) 'Bounded event evidence grants no configuration or Sigma claim.'
  Assert ($manifest.Operation.Nonce -notin $nonces -and $manifest.Operation.Thumbprint -notin $thumbprints) 'Independent public invocation generated a fresh nonce and certificate.'
  $nonces+=$manifest.Operation.Nonce;$thumbprints+=$manifest.Operation.Thumbprint
  $der=Assert-WelaCapi2ProbeCertificate $manifest.Operation $manifest.Operation.Nonce
  Assert ((Get-WelaArrivalHash $der) -ceq $manifest.Operation.CertificateSha256) 'Actual DER matches retained SHA256.'
  Assert (Test-WelaCapi2ProbeEvent ([IO.File]::ReadAllText("$out/event.xml")) $manifest.Operation $manifest.Before) 'Actual event11 matches certificate, nonce, PID, SID, UTC, offline flags and expected chain outcome.'
  foreach($artifact in $manifest.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant()) 'Artifact hash verifies.'}
  Assert ((Key (Get-WelaCapi2ProbeChannel)) -ceq (Key $enabled)) 'Public probe preserved channel configuration.'
  Assert ((Key (Read-Stores)) -ceq (Key $originalStores)) 'CurrentUser and LocalMachine My/Root/CA certificate inventories preserved.'
  Assert ((Get-Acl -LiteralPath $out).AreAccessRulesProtected) 'Private evidence blocks inherited broad access.'
 }
}catch{$failure=$_}
finally{
 try{$channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($original.Name);try{if($channel.IsEnabled -ne $original.Enabled){$channel.IsEnabled=$original.Enabled;$channel.SaveChanges()}}finally{$channel.Dispose()};$restored=Get-WelaCapi2ProbeChannel;$null=Write-WelaArrivalArtifact $root 'channel-restored.json' ($restored|ConvertTo-Json);if((Key $restored) -cne (Key $original)){throw 'Original channel configuration was not restored.'}}catch{$cleanupErrors+='Channel restoration: '+$_.Exception.Message}
 try{$storesAfter=Read-Stores;$null=Write-WelaArrivalArtifact $root 'stores-after.json' ($storesAfter|ConvertTo-Json -Depth 8);if((Key $storesAfter) -cne (Key $originalStores)){throw 'Certificate store inventory changed.'}}catch{$cleanupErrors+='Store observation: '+$_.Exception.Message}
 $null=Write-WelaArrivalArtifact $root 'cleanup.json' ([pscustomobject]@{ChangedEnabled=$changed;Failure=$(if($failure){$failure.Exception.Message}else{$null});CleanupErrors=$cleanupErrors;ChannelRestored=($cleanupErrors.Count -eq 0);Complete=($null -eq $failure -and $cleanupErrors.Count -eq 0);Evidence=$root}|ConvertTo-Json)
}
if($failure){throw $failure};if($cleanupErrors.Count){throw ($cleanupErrors -join '; ')}
Write-Host "PASS: $script:count actual CAPI2 assertions across $ProbeRuns independent public runs; original channel restored and selected certificate inventories preserved."
$global:LASTEXITCODE=0
