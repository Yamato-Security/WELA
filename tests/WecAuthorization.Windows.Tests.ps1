param([switch]$AllowDisposableSubscription)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableSubscription -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows subscription opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/WecAuthorization.ps1"
$count=0;$engine=(Get-Process -Id $PID).Path
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){Get-WelaWecAuthorizationKey $Value}
function Services {@(Get-CimInstance Win32_Service -Filter "Name='Wecsvc' OR Name='Winmgmt' OR Name='EventLog' OR Name='WinRM'"|Sort-Object Name|Select-Object Name,State,StartMode)}
function Channel {$c=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents');try{[pscustomobject]@{Name=$c.LogName;Enabled=$c.IsEnabled;Mode=[string]$c.LogMode;MaximumBytes=$c.MaximumSizeInBytes;Path=$c.LogFilePath;SecurityDescriptor=$c.SecurityDescriptor}}finally{$c.Dispose()}}
function EnableChannel([bool]$Value){$c=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('ForwardedEvents');try{$c.IsEnabled=$Value;$c.SaveChanges()}finally{$c.Dispose()}}
Add-Type -Path (Join-Path $PSScriptRoot 'WecAuthorizationFixtureNative.cs')
function Ids {[Wela.WecAuthorizationFixture.Inventory]::Read()|Sort-Object}
function Inventory {$ids=@(Ids);Save 'last-observed-ids.json' $ids;@($ids|ForEach-Object {[pscustomobject]@{Id=$_;Xml=Read-WelaWecSubscriptionXml $_}})}
$nonce=[guid]::NewGuid().ToString('N');$id='WELA-Authorization-'+$nonce;$description='Owned authorization '+$nonce+' '+[char]0x65e5+[char]0x672c
$sidA='S-1-5-21-111111111-222222222-333333333-1234';$sidB='S-1-5-21-111111111-222222222-333333333-1235'
$root=Join-Path $env:RUNNER_TEMP ('wela-wec-authorization-'+$nonce);$null=New-Item -ItemType Directory $root
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
# Native -File argument binding cannot portably carry a string[] on both engines.
# This fixture wrapper supplies the selected array to the actual public script.
$wrapper=Join-Path $root 'invoke-public.ps1'
@'
param([string]$WelaPath,[string]$Action,[string]$Id,[string]$Sids,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath)
$ErrorActionPreference='Stop'
$p=@{Cmd='wec-authorization';WecAuthorizationAction=$Action;WecAuthorizationOutputPath=$OutputPath}
if($PSBoundParameters.ContainsKey('Id')){$p.WecAuthorizationId=$Id}
if($PSBoundParameters.ContainsKey('Sids')){$p.WecAuthorizationSourceSid=@($Sids.Split(';'))}
if($PSBoundParameters.ContainsKey('PlanPath')){$p.WecAuthorizationPlanPath=$PlanPath}
if($PSBoundParameters.ContainsKey('PlanHash')){$p.WecAuthorizationPlanHash=$PlanHash}
$global:LASTEXITCODE=0
& $WelaPath @p
exit $LASTEXITCODE
'@|Set-Content -LiteralPath $wrapper -Encoding UTF8
function Public([string[]]$Arguments,[string]$Output,[bool]$Success=$true){
 $prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File $wrapper -WelaPath "$repo/WELA.ps1" @Arguments -OutputPath $Output 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 if(($code -eq 0) -ne $Success){Write-Host ($text -join "`n");Get-ChildItem $root -Filter manifest.json -Recurse|ForEach-Object {Write-Host (Get-Content $_.FullName -Raw)};throw "Public command returned $code"};$script:count++
 $result=Get-Content -LiteralPath (Join-Path $Output 'manifest.json') -Raw|ConvertFrom-Json
 foreach($a in $result.Artifacts){Assert ((Get-FileHash (Join-Path $Output $a.Name)).Hash.ToLowerInvariant() -ceq $a.Sha256) 'Public evidence hash matches actual bytes'}
 $result
}
$beforeServices=Services;$beforeChannel=Channel;$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc';$beforeDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
$original=$null;$created=$false;$failure=$null;$cleanupErrors=@();$inventoryOk=$false;$servicesOk=$false;$channelOk=$false;$endServices=$null;$endChannel=$null;$endDelayed=$null
Save 'before-fixture.json' @{Services=$beforeServices;Channel=$beforeChannel;DelayedAutoStart=$beforeDelayed}
try {
 $wec=@($beforeServices|Where-Object Name -eq Wecsvc);Assert ($wec.Count -eq 1 -and $wec[0].State -in @('Running','Stopped') -and $wec[0].StartMode -in @('Auto','Manual','Disabled')) 'Stable original service state required'
 if($wec[0].StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Manual};if($wec[0].State -eq 'Stopped'){Start-Service Wecsvc}
 if(-not $beforeChannel.Enabled){EnableChannel $true}
 Save 'original-console-enumeration.json' (Invoke-WelaNative 'wecutil.exe' @('es'))
 $original=@(Inventory);Save 'original-inventory.json' $original;Assert (@(Ids) -notcontains $id) 'Unique owned subscription is initially absent'
 $query='<QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[(EventID=1)]]</Select></Query></QueryList>'
 $xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><SubscriptionId>$id</SubscriptionId><SubscriptionType>SourceInitiated</SubscriptionType><Description>$description</Description><Enabled>false</Enabled><Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri><ConfigurationMode>Normal</ConfigurationMode><Query><![CDATA[$query]]></Query><ReadExistingEvents>false</ReadExistingEvents><TransportName>HTTP</TransportName><ContentFormat>Events</ContentFormat><Locale Language="en-US"/><LogFile>ForwardedEvents</LogFile><AllowedSourceDomainComputers>$(Get-WelaWefAuthorization @($sidA))</AllowedSourceDomainComputers></Subscription>
"@
 $path=Join-Path $root 'owned.xml';[IO.File]::WriteAllText($path,$xml,[Text.UTF8Encoding]::new($false));$created=$true;$null=Invoke-WelaNative 'wecutil.exe' @('cs',$path)
 $before=Read-WelaWecAuthorizationDefinition $id;[IO.File]::WriteAllText((Join-Path $root 'original.xml'),$before.Xml,[Text.UTF8Encoding]::new($false));$duringServices=Services;$duringChannel=Channel
 Initialize-WelaWecAuthorizationNative
 $missing=$false;try{$e=[Wela.WecAuthorization.Edit]::new($id+'-missing');$e.Dispose()}catch{$missing=$true};Assert ($missing -and @(Ids) -notcontains ($id+'-missing')) 'Native existing-only handle never creates a missing ID'
 $index=0
 foreach($desired in @(@($sidA),@($sidA,$sidB),@($sidA,$sidB),@($sidB),@($sidA))){
  $index++;$prior=Read-WelaWecAuthorizationDefinition $id;$changed=$prior.Authorization -cne (Get-WelaWefAuthorization $desired)
  $plan=Public @('-Action','Plan','-Id',$id,'-Sids',($desired -join ';')) (Join-Path $root "plan-$index")
  Assert ($plan.Status -ceq 'ReviewRequired' -and -not $plan.NativeSaveAttempted -and (Read-WelaWecAuthorizationDefinition $id).WholeKey -ceq $prior.WholeKey) 'Actual public Plan preserved original native definition'
  $planPath=Join-Path $plan.OutputPath 'plan.json'
  if($index -eq 2){$bad=Public @('-Action','Apply','-PlanPath',$planPath,'-PlanHash',('f'*64)) (Join-Path $root 'bad-hash') $false;Assert ($bad.Status -ceq 'Refused' -and -not $bad.NativeSaveAttempted) 'Wrong hash refuses before native save'}
  $apply=Public @('-Action','Apply','-PlanPath',$planPath,'-PlanHash',$plan.PlanHash) (Join-Path $root "apply-$index")
  Assert ($apply.NativeSaveAttempted -eq $changed -and $apply.Status -ceq $(if($changed){'AuthorizationChangedAndVerified'}else{'AlreadyMatches'})) 'Only a changed allow list saves'
  $after=Read-WelaWecAuthorizationDefinition $id
  Assert ($after.Authorization -ceq (Get-WelaWefAuthorization $desired) -and $after.PreservedKey -ceq $before.PreservedKey -and $apply.ReadyRuleCredit -eq 0) 'Actual disabled definition changes only selected authorization; no readiness credit'
  if($index -eq 2){$stale=Public @('-Action','Apply','-PlanPath',$planPath,'-PlanHash',$plan.PlanHash) (Join-Path $root 'stale') $false;Assert ($stale.Status -ceq 'Refused' -and -not $stale.NativeSaveAttempted) 'Stale pre-state plan refuses replay'}
 }
 Assert ((Read-WelaWecAuthorizationDefinition $id).WholeKey -ceq $before.WholeKey) 'Fresh public plan restored complete original subscription'
 # Direct native fresh-handle guard checks a concurrently changed description.
 $edit=New-WelaWecAuthorizationEdit $before
 try{$null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+($description+' drift')));$refused=$false;try{$edit.Save((Get-WelaWefAuthorization @($sidB)))}catch{$refused=$true};Assert ($refused -and -not $edit.SaveAttempted) 'Native guard refuses a changed current definition before save'}finally{$edit.Dispose();$null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+$description))}
 try{
  $null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,'/e:true')
  $enabled=Public @('-Action','Plan','-Id',$id,'-Sids',$sidB) (Join-Path $root 'enabled-refusal') $false
  Assert ($enabled.Status -ceq 'Refused' -and -not $enabled.NativeSaveAttempted) 'Public command refuses actual enabled subscription'
 }finally{$null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,'/e:false')}
 Assert ((Read-WelaWecAuthorizationDefinition $id).WholeKey -ceq $before.WholeKey) 'Fixture drift and enabled-state probes restored full original XML'
 Assert ((Key (Services)) -ceq (Key $duringServices) -and (Key (Channel)) -ceq (Key $duringChannel)) 'Product preserves services and complete channel configuration'
 [IO.File]::WriteAllText((Join-Path $root 'restored-owned.xml'),(Read-WelaWecSubscriptionXml $id),[Text.UTF8Encoding]::new($false))
 Write-Host "PASS: $count actual WEC authorization assertions on $($PSVersionTable.PSVersion). No real source or forwarding proof."
}catch{$failure=$_.ToString();Write-Host $failure}finally{
 try{
  if($created -and @(Ids) -contains $id){$raw=Read-WelaWecSubscriptionXml $id;$doc=Read-WelaWefXml $raw;if($doc.Subscription.Description -cne $description -and $doc.Subscription.Description -cne ($description+' drift')){throw 'Fixture ownership differs; do not delete subscription.'};$null=Invoke-WelaNative 'wecutil.exe' @('ds',$id)}
  $restored=@(Inventory);Save 'restored-inventory.json' $restored;$inventoryOk=$null -ne $original -and (Key $restored) -ceq (Key $original)
 }catch{$cleanupErrors+=$_.ToString()}
 try{if((Channel).Enabled -ne $beforeChannel.Enabled){EnableChannel $beforeChannel.Enabled};$endChannel=Channel;$channelOk=(Key $endChannel) -ceq (Key $beforeChannel)}catch{$cleanupErrors+=$_.ToString()}
 try{
  $wec=@($beforeServices|Where-Object Name -eq Wecsvc)[0]
  if($wec.State -eq 'Stopped' -and (Get-Service Wecsvc).Status -ne 'Stopped'){Stop-Service Wecsvc}
  if($wec.StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Disabled}
  if((Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){if($beforeDelayed.ValueExists){$null=New-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $beforeDelayed.Value -PropertyType $beforeDelayed.Type -Force}else{Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop}}
  $endServices=Services;$endDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart;$servicesOk=(Key $endServices) -ceq (Key $beforeServices) -and (Key $endDelayed) -ceq (Key $beforeDelayed)
 }catch{$cleanupErrors+=$_.ToString()}
 Save 'after-fixture.json' @{Services=$endServices;Channel=$endChannel;DelayedAutoStart=$endDelayed}
 Save 'cleanup.json' @{Failure=$failure;CleanupErrors=$cleanupErrors;SubscriptionsRestored=$inventoryOk;ServicesRestored=$servicesOk;ChannelRestored=$channelOk;Complete=($inventoryOk -and $servicesOk -and $channelOk -and -not $cleanupErrors.Count);Assertions=$count;Computer=[Environment]::MachineName;Engine=$PSVersionTable.PSVersion.ToString();Scope='Owned disabled subscription authorization only; inert SIDs are not resolved or authenticated.'}
}
if($failure -or -not $inventoryOk -or -not $servicesOk -or -not $channelOk -or $cleanupErrors.Count){throw "Native authorization or fixture cleanup failed; inspect $root"}
exit 0
