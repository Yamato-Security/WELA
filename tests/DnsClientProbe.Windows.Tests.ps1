param([switch]$AllowDisposableDns,[ValidateSet('powershell','pwsh')][string]$TestEngine='powershell')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableDns -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit DNS mutation opt-in on a disposable GitHub-hosted Windows runner is required.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $ScriptRoot 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $ScriptRoot 'modules/NativeProviders.psm1') -Force
foreach($name in @('Configuration','ControlApplicability','NativeProviderPacks','AuditRecovery','WefArrival','ChannelRead','DnsClientProbe')){. (Join-Path $ScriptRoot ('scripts/'+$name+'.ps1'))}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
$os=Get-CimInstance Win32_OperatingSystem;$computer=Get-CimInstance Win32_ComputerSystem
if($os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100) -or $computer.PartOfDomain -or $computer.DomainRole -ne 2 -or (Get-WindowsFeature DNS).Installed){throw 'This fixture requires an unjoined Server2022/2025 with no existing DNS role.'}
$engine=(Get-Command $TestEngine -ErrorAction Stop).Source
$private=New-WelaArrivalOutput (Join-Path $env:TEMP ('wela-dns-client-native-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
$channel='Microsoft-Windows-DNS-Client/Operational';$zone='wela.test';$zoneFile='wela-native-'+[guid]::NewGuid().ToString('N')+'.dns';$zoneFilePath=$null;$zoneFileCreated=$false
$beforeFeatures=@(Get-WindowsFeature|Where-Object Installed|ForEach-Object Name);$policies=Get-WelaEffectiveAuditPolicy;$original=Get-WelaNativeChannel $channel
if($original.State -notin @('Enabled','Disabled') -or $original.MetadataErrors.Count -or $original.Error){throw 'Complete original DNS Client channel state is required before fixture mutation.'}
$null=Write-WelaArrivalArtifact $private 'original-channel.json' ($original|ConvertTo-Json -Depth 10)
$installed=$false;$zoneCreated=$false;$channelChanged=$false;$passed=$false
function Invoke-Cli {
 param([string[]]$Arguments,[int]$Expected=0)
 $ErrorActionPreference='Continue'
 try{$text=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $ScriptRoot 'WELA.ps1') @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
 $text|ForEach-Object{Write-Host $_};$global:LASTEXITCODE=0
 Assert ($code -eq $Expected) "Public DNS Client CLI exit $code, expected $Expected."
}
function Set-ChannelEnabled([bool]$Enabled){$out=& "$env:SystemRoot\System32\wevtutil.exe" sl $channel ('/e:'+([string]$Enabled).ToLowerInvariant()) 2>&1;if($LASTEXITCODE -ne 0){throw "Fixture channel update failed: $out"};$global:LASTEXITCODE=0}
try {
 $installed=$true;$feature=Install-WindowsFeature DNS -IncludeManagementTools -ErrorAction Stop
 if(-not $feature.Success -or [string]$feature.RestartNeeded -ne 'No'){throw 'DNS role install failed or requires restart; no native acceptance claim.'}
 Start-Service DNS -ErrorAction Stop
 $ready=[Diagnostics.Stopwatch]::StartNew();do{try{$null=Get-DnsServerZone -ErrorAction Stop;break}catch{if($ready.Elapsed.TotalSeconds -gt 30){throw};Start-Sleep -Milliseconds 500}}while($true)
 if(Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue){throw 'Fixture zone already exists; no replacement is permitted.'}
 $zoneFilePath=Join-Path $env:SystemRoot ('System32\dns\'+$zoneFile)
 if(Test-Path -LiteralPath $zoneFilePath){throw 'Fixture zone file already exists.'}
 # Avoid relying on generated SOA/NS names on an unjoined, suffix-free runner.
 $zoneText=@'
$ORIGIN wela.test.
$TTL 0
@ IN SOA ns.wela.test. hostmaster.wela.test. ( 1 3600 600 86400 0 )
@ IN NS ns.wela.test.
ns IN A 127.0.0.1
* IN A 192.0.2.1
'@
 $stream=[IO.File]::Open($zoneFilePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$zoneFileCreated=$true;$bytes=[Text.Encoding]::ASCII.GetBytes(($zoneText -replace "\r?\n","`r`n")+"`r`n");$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
 Write-Host "Creating owned authoritative zone $zone from new file $zoneFile"
 Add-DnsServerPrimaryZone -Name $zone -ZoneFile $zoneFile -DynamicUpdate None -LoadExisting -ErrorAction Stop;$zoneCreated=$true
 $record=@(Get-DnsServerResourceRecord -ZoneName $zone -RRType A -ErrorAction Stop|Where-Object HostName -ceq '*')
 Assert (@($record).Count -eq 1 -and $record.RecordData.IPv4Address.IPAddressToString -ceq '192.0.2.1') 'Loaded owned wildcard A record is exact.'
 # The zone is authoritative and the native request has recursion disabled. No external resolver or answer connection is used.
 if(-not $original.IsEnabled){$channelChanged=$true;Set-ChannelEnabled $true}
 $configured=Get-WelaNativeChannel $channel
 $catalog=Get-WelaProviderPackCatalog;$pack=@($catalog.packs|Where-Object id -ceq 'dns-client')[0]
 Write-Host ((Get-WelaProviderPackSchema $pack)|ConvertTo-Json -Depth 12)
 Invoke-Cli @('dns-client-probe','-DnsClientProbeResolver','127.0.0.1')
 $output=Join-Path $private 'evidence'
 Invoke-Cli @('dns-client-probe','-DnsClientProbeAction','Run','-DnsClientProbeResolver','127.0.0.1','-DnsClientProbeOutputPath',$output)
 $report=ConvertFrom-WelaRecoveryJson ([IO.File]::ReadAllText((Join-Path $output 'manifest.json')))
 Assert ($report.Status -ceq 'NativeDnsLookupObserved' -and $report.ExitCode -eq 0 -and $report.Matches -ge 1 -and $report.ReadyRuleCredit -eq 0 -and $report.ConfigurationChanges -eq 0) 'Actual native3008 correlation is observed without configuration/Sigma credit.'
 Assert ($report.Operation.Query.QueryName -cmatch '^wela-[a-f0-9]{32}\.wela\.test\.$' -and $report.Operation.Query.Status -eq 0 -and $report.Operation.Query.ResultStatus -eq 0 -and @($report.Operation.Query.Answers).Count -eq 1 -and $report.Operation.Query.Answers[0].Address -ceq '192.0.2.1') 'Owned authoritative loopback resolver returns the exact fixed A answer.'
 foreach($artifact in $report.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Evidence bytes match recorded SHA256.'}
 foreach($file in Get-ChildItem -LiteralPath $output -Filter 'event-*.xml'){$xml=[IO.File]::ReadAllText($file.FullName);Assert (Test-WelaDnsClientProbeEvent $xml $report.Operation $report.Before) 'Actual persisted3008 XML matches the production validator.';Write-Host $xml}
 Assert ((Get-WelaChannelReadKey (Get-WelaNativeChannel $channel)) -ceq (Get-WelaChannelReadKey $configured)) 'Product preserves the exact configured channel metadata.'
 Assert ($report.RuleChannelMismatch -match 'DNS Client Events/Operational') 'Original rule-channel mismatch remains explicit.'
 $passed=$true;Write-Host "PASS: $script:count native DNS Client checks through $TestEngine."
}catch{
 Write-Host ('Native DNS Client failure: '+($_|Out-String));Write-Host $_.ScriptStackTrace
 # Small owned diagnostics only; avoid dumping unrelated channel payloads.
 if(Test-Path (Join-Path $private 'evidence')){Get-ChildItem (Join-Path $private 'evidence') -File|Where-Object {$_.Name -in @('manifest.json','operation.json') -or $_.Name -like 'candidate-*.xml'}|ForEach-Object{Write-Host $_.Name;Write-Host ([IO.File]::ReadAllText($_.FullName))}}
 throw
}finally{
 $errors=@()
 try{if($channelChanged){Set-ChannelEnabled ([bool]$original.IsEnabled)};if((Get-WelaChannelReadKey (Get-WelaNativeChannel $channel)) -cne (Get-WelaChannelReadKey $original)){throw 'DNS Client channel configuration restoration differs.'}}catch{$errors+=$_.Exception.Message}
 if($zoneCreated){try{$owned=Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue;if($owned){if($owned.IsDsIntegrated -or $owned.ZoneType -ne 'Primary'){throw 'Owned DNS zone identity changed; cleanup refused.'};Remove-DnsServerZone -Name $zone -Force -ErrorAction Stop};if(Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue){throw 'Owned zone remains.'}}catch{$errors+=$_.Exception.Message}}
 if($zoneFileCreated){try{if(Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue){throw 'Refuse deleting a zone file still loaded by DNS.'};if(Test-Path -LiteralPath $zoneFilePath){Remove-Item -LiteralPath $zoneFilePath -ErrorAction Stop}}catch{$errors+=$_.Exception.Message}}
 try{$afterPolicies=Get-WelaEffectiveAuditPolicy;foreach($guid in $policies.Keys){if($afterPolicies[$guid] -ne $policies[$guid]){throw 'Native audit policy changed.'}}}catch{$errors+=$_.Exception.Message}
 $removal=[pscustomobject]@{ChannelAndZoneRestored=($errors.Count -eq 0);Attempted=$false;Features=@();Success=$null;RestartNeeded=$null;Boundary='Owned feature removal can require disposal of this GitHub-hosted VM; no restart or complete live feature-restoration claim.'}
 if($installed -and -not $errors.Count){try{$added=@(Get-WindowsFeature|Where-Object {$_.Installed -and $_.Name -notin $beforeFeatures -and $_.Name -in @('DNS','RSAT-DNS-Server')}|ForEach-Object Name);if($added.Count){$removal.Attempted=$true;$removal.Features=$added;$removed=Uninstall-WindowsFeature -Name $added -ErrorAction Stop;$removal.Success=[bool]$removed.Success;$removal.RestartNeeded=[string]$removed.RestartNeeded;if(-not $removed.Success -or $removal.RestartNeeded -notin @('No','Yes')){throw 'DNS feature removal failed or restart state is unknown.'}}}catch{$errors+=$_.Exception.Message}}
 $null=Write-WelaArrivalArtifact $private 'cleanup.json' ($removal|ConvertTo-Json -Depth 6);$removal|ConvertTo-Json -Depth 6|Write-Host
 if($errors.Count){throw "Disposable DNS cleanup failed; evidence retained at $private : $($errors -join '; ')"}
 if($passed){Remove-Item -LiteralPath $private -Recurse -Force}
}
$global:LASTEXITCODE=0
