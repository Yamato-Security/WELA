param([switch]$AllowDisposableSubscription)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableSubscription -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows subscription opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/ChannelRead.ps1"
$count=0;$engine=(Get-Process -Id $PID).Path
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Services {@(Get-CimInstance Win32_Service -Filter "Name='Wecsvc' OR Name='Winmgmt' OR Name='EventLog' OR Name='WinRM'"|Sort-Object Name|Select-Object Name,State,StartMode)}
function Channel {$c=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents');try{[pscustomobject]@{Name=$c.LogName;Enabled=$c.IsEnabled;Mode=[string]$c.LogMode;MaximumBytes=$c.MaximumSizeInBytes;Path=$c.LogFilePath;SecurityDescriptor=$c.SecurityDescriptor}}finally{$c.Dispose()}}
function Inventory {$ids=@(Get-WelaWecSubscriptionIds);if($ids.Count -gt 64){throw 'Disposable fixture inventory exceeds 64 entries.'};@($ids|ForEach-Object {[pscustomobject]@{Id=$_;Xml=Read-WelaWecSubscriptionXml $_}})}
$hostState=Get-WelaChannelReadHost
Assert ($hostState.Build -in @(20348,26100) -and $hostState.UBR -gt 0 -and $hostState.ProductType -eq 3 -and $hostState.DomainRole -eq 2 -and -not $hostState.DomainJoined) 'Actual patched standalone Server2022/2025 fixture; no invented domain identity'
$nonce=[guid]::NewGuid().ToString('N');$id='WELA-Observe-'+$nonce;$unicode=([string][char]0x65e5)+([string][char]0x672c)
$description='Owned observation '+$nonce+' '+$unicode;$sid='S-1-5-21-111111111-222222222-333333333-1234'
$root=Join-Path $env:RUNNER_TEMP ('wela-wec-observation-'+$nonce);$null=New-Item -ItemType Directory $root
function Save($Name,$Value){$text=ConvertTo-Json -InputObject $Value -Depth 30;[IO.File]::WriteAllText((Join-Path $root $Name),$text,[Text.UTF8Encoding]::new($false))}
$beforeServices=Services;$beforeChannel=Channel;$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc';$beforeDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
$original=$null;$created=$false;$failure=$null;$errors=@();$inventoryOk=$false;$servicesOk=$false;$channelOk=$false;$reports=@();$afterServices=$null;$afterChannel=$null;$afterDelayed=$null
$sources=[ordered]@{};foreach($p in @('WELA.ps1','scripts/WefDeployment.ps1','modules/WefSubscriptions.psm1','modules/WecSubscriptionInventory.cs','modules/WecSubscriptionXml.cs')){$sources[$p]=(Get-FileHash (Join-Path $repo $p)).Hash.ToLowerInvariant()}
Save 'before-fixture.json' @{Host=$hostState;Services=$beforeServices;Channel=$beforeChannel;DelayedAutoStart=$beforeDelayed;Sources=$sources}
$config=Get-Content "$repo/config/wef-examples/collector.json" -Raw|ConvertFrom-Json
# Existing Audit/Plan deliberately remain incomplete on this real standalone runner.
# The example collector identity is never resolved, contacted or asserted as local.
$config.SourceSids=@($sid);$config.SubscriptionFiles=@('requested.xml');$config.IngressRuleName='WELA-Absent-'+$nonce
$path=Join-Path $root 'requested.xml';$configPath=Join-Path $root 'collector.json';Save 'collector.json' $config
$query='<QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[(EventID=1)] and EventData[Data='''+$unicode+''']]</Select></Query></QueryList>'
$xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><SubscriptionId>$id</SubscriptionId><SubscriptionType>SourceInitiated</SubscriptionType><Description>$description</Description><Enabled>false</Enabled><Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri><ConfigurationMode>Normal</ConfigurationMode><Query><![CDATA[$query]]></Query><ReadExistingEvents>false</ReadExistingEvents><TransportName>HTTP</TransportName><ContentFormat>Events</ContentFormat><Locale Language="en-US"/><LogFile>ForwardedEvents</LogFile><AllowedSourceDomainComputers></AllowedSourceDomainComputers></Subscription>
"@
[IO.File]::WriteAllText($path,$xml,[Text.UTF8Encoding]::new($false))
function Public([string]$Action,[string]$Name){
 $out=Join-Path $root ($Name+'.json');$prior=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" wec-collector -WefAction $Action -WefConfigPath $configPath -ResultsPath $out 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 [IO.File]::WriteAllText((Join-Path $root ($Name+'.log')),($text -join "`n"),[Text.UTF8Encoding]::new($false))
 Assert ($code -eq 1 -and (Test-Path $out)) 'Public collector reports incomplete real standalone prerequisites with exit1'
 $r=Get-Content -LiteralPath $out -Raw -Encoding UTF8|ConvertFrom-Json
 Assert ($r.Action -ceq $Action -and $r.Role -ceq 'Collector' -and $r.LocalConfigurationStatus -ceq 'Incomplete' -and -not $r.HostIdentity.DomainJoined) 'Public report preserves actual role and incomplete domain prerequisites'
 Assert ($r.Subscriptions.Count -eq 1 -and $r.Subscriptions[0].Id -ceq $id -and $r.Subscriptions[0].EventArrival -ceq 'Not tested' -and $r.Subscriptions[0].ForwardedSigmaCoverage -ceq 'Not assessed' -and $r.Subscriptions[0].ChannelObservationLocation -like 'Collector only*') 'No source authentication, remote channel or forwarded coverage claim'
 $script:reports+=($Name+'.json');$r
}
function SubscriptionControl($Report){@($Report.Controls|Where-Object Kind -eq Subscription)[0]}
try {
 $wec=@($beforeServices|Where-Object Name -eq Wecsvc);Assert ($wec.Count -eq 1 -and $wec[0].State -in @('Running','Stopped') -and $wec[0].StartMode -in @('Auto','Manual','Disabled')) 'Stable original collector service state required'
 if($wec[0].StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Manual};if($wec[0].State -eq 'Stopped'){Start-Service Wecsvc}
 $original=@(Inventory);Save 'original-inventory.json' $original;Assert (@(Get-WelaWecSubscriptionIds) -notcontains $id) 'Unique owned subscription initially absent'
 Save 'console-enumeration-before.json' (Invoke-WelaNative 'wecutil.exe' @('es'))
 $duringServices=Services
 $absent=Public Audit 'absent-before'
 Assert ($absent.Subscriptions[0].ObservedSubscription.Exists -eq $false -and $null -eq $absent.Subscriptions[0].ObservedEnabled -and -not $absent.Subscriptions[0].ObservationError -and (SubscriptionControl $absent).Status -ceq 'ChangeRequired') 'Complete native enumeration establishes selected absence'
 $model=Import-WelaWefConfig $configPath Collector;$ownedPath=Join-Path $root 'owned.xml';[IO.File]::WriteAllText($ownedPath,$model.Subscriptions[0].Xml,[Text.UTF8Encoding]::new($false))
 $created=$true;$null=Invoke-WelaNative 'wecutil.exe' @('cs',$ownedPath)
 $before=Read-WelaWecSubscriptionXml $id;[IO.File]::WriteAllText((Join-Path $root 'original-owned.xml'),$before,[Text.UTF8Encoding]::new($false))
 Assert (@(Get-WelaWecSubscriptionIds) -ccontains $id) 'Actual native enumeration returns exact owned ID'
 foreach($action in @('Audit','Plan')){
  $r=Public $action ('present-'+$action.ToLowerInvariant());$o=$r.Subscriptions[0]
  Assert ($o.ObservedSubscription.Exists -and $o.ObservedEnabled -eq $false -and -not $o.ObservationError -and (SubscriptionControl $r).Status -ceq 'RequestedSettingsMatch') 'Existing disabled native definition is observed and matched'
  Assert ($o.ObservedSubscription.Xml -ceq $before -and $o.ObservedSubscription.Definition.Description -ceq $description -and $o.Filters[0].XPath -ceq ('*[System[(EventID=1)] and EventData[Data='''+$unicode+''']]')) 'Public JSON preserves exact Unicode native XML, description and selected XPath'
  Assert ((Read-WelaWecSubscriptionXml $id) -ceq $before) 'Public Audit/Plan does not save or alter existing subscription'
 }
 [IO.File]::WriteAllText($path,$xml.Replace('<Enabled>false</Enabled>','<Enabled>true</Enabled>'),[Text.UTF8Encoding]::new($false))
 $r=Public Plan 'requested-enabled'
 Assert ($r.Subscriptions[0].RequestedEnabled -and $r.Subscriptions[0].ObservedEnabled -eq $false -and (SubscriptionControl $r).Status -ceq 'ManualReview') 'Actual disabled state is not replaced with requested enabled state'
 [IO.File]::WriteAllText($path,$xml,[Text.UTF8Encoding]::new($false))
 try {
  $null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+($description+' drift')))
  $r=Public Audit 'description-drift'
  Assert ((SubscriptionControl $r).Status -ceq 'ManualReview' -and $r.Subscriptions[0].ObservedSubscription.Definition.Description -ceq ($description+' drift')) 'Native Unicode drift is retained and does not become a match'
 }finally{$null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+$description))}
 $config.SourceSids=@($sid.Replace('-1234','-1235'));Save 'collector.json' $config
 $r=Public Audit 'authorization-mismatch'
 Assert ((SubscriptionControl $r).Status -ceq 'Unknown' -and $null -eq $r.Subscriptions[0].ObservedSubscription -and $null -eq $r.Subscriptions[0].ObservedEnabled -and $r.Subscriptions[0].ObservationError) 'Unsupported observed authorization remains unknown, never absent'
 $config.SourceSids=@($sid);Save 'collector.json' $config
 Assert ((Read-WelaWecSubscriptionXml $id) -ceq $before) 'All public observations and fixture drift restoration preserve original raw XML'
 [IO.File]::WriteAllText((Join-Path $root 'restored-owned.xml'),(Read-WelaWecSubscriptionXml $id),[Text.UTF8Encoding]::new($false))
 $null=Invoke-WelaNative 'wecutil.exe' @('ds',$id);$created=$false
 $r=Public Audit 'absent-after';Assert ($r.Subscriptions[0].ObservedSubscription.Exists -eq $false -and -not $r.Subscriptions[0].ObservationError) 'Actual removed owned subscription returns confirmed absence'
 Assert ((Key (Services)) -ceq (Key $duringServices) -and (Key (Channel)) -ceq (Key $beforeChannel)) 'Read-only public commands preserve services and complete destination configuration'
 Write-Host "PASS: $count actual collector observation assertions on $($PSVersionTable.PSVersion). No domain/forwarding proof."
}catch{$failure=$_.ToString();Write-Host $failure}finally{
 try {
  if($created -and @(Get-WelaWecSubscriptionIds) -contains $id){$raw=Read-WelaWecSubscriptionXml $id;$doc=Read-WelaWefXml $raw;if($doc.Subscription.Description -cne $description -and $doc.Subscription.Description -cne ($description+' drift')){throw 'Fixture ownership differs; do not delete subscription.'};$null=Invoke-WelaNative 'wecutil.exe' @('ds',$id)}
  $restored=@(Inventory);Save 'restored-inventory.json' $restored;$inventoryOk=$null -ne $original -and (Key $restored) -ceq (Key $original)
 }catch{$errors+=$_.ToString()}
 try{$afterChannel=Channel;$channelOk=(Key $afterChannel) -ceq (Key $beforeChannel)}catch{$errors+=$_.ToString()}
 try {
  $wec=@($beforeServices|Where-Object Name -eq Wecsvc)[0]
  if($wec.State -eq 'Stopped' -and (Get-Service Wecsvc).Status -ne 'Stopped'){Stop-Service Wecsvc}
  if($wec.StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Disabled}
  if((Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){if($beforeDelayed.ValueExists){$null=New-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $beforeDelayed.Value -PropertyType $beforeDelayed.Type -Force}else{Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop}}
  $afterServices=Services;$afterDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
  $servicesOk=(Key $afterServices) -ceq (Key $beforeServices) -and (Key $afterDelayed) -ceq (Key $beforeDelayed)
 }catch{$errors+=$_.ToString()}
 Save 'after-fixture.json' @{Services=$afterServices;Channel=$afterChannel;DelayedAutoStart=$afterDelayed}
 $artifacts=@(Get-ChildItem $root -File|ForEach-Object {[pscustomobject]@{Name=$_.Name;Bytes=$_.Length;Sha256=(Get-FileHash $_.FullName).Hash.ToLowerInvariant()}})
 Save 'cleanup.json' @{Failure=$failure;CleanupErrors=$errors;SubscriptionsRestored=$inventoryOk;ServicesRestored=$servicesOk;ChannelPreserved=$channelOk;Complete=($inventoryOk -and $servicesOk -and $channelOk -and -not $errors.Count);Assertions=$count;Engine=$PSVersionTable.PSVersion.ToString();Host=$hostState;Sources=$sources;Artifacts=$artifacts;PublicReports=$reports;Scope='Native local collector observation only; real standalone prerequisites remain incomplete.'}
}
if($failure -or -not $inventoryOk -or -not $servicesOk -or -not $channelOk -or $errors.Count){throw "Native observation or fixture cleanup failed; inspect $root"}
exit 0
