param([switch]$AllowDisposableSubscription)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $AllowDisposableSubscription -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted Windows subscription opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/WefSubscriptions.psm1" -Force
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/ControlApplicability.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/WecUpdate.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function ServiceState {Get-CimInstance Win32_Service -Filter "Name='Wecsvc'"|Select-Object Name,State,StartMode}
function Subscriptions {@((Invoke-WelaNative 'wecutil.exe' @('es')).Output|ForEach-Object {$_.ToString().Trim()}|Where-Object {$_})}
$beforeService=ServiceState;$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc';$beforeDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
if($beforeService.State -notin @('Running','Stopped') -or $beforeService.StartMode -notin @('Auto','Manual','Disabled')){throw 'Stable Wecsvc state required.'}
$nonce=[guid]::NewGuid().ToString('N');$id='WELA-Update-Test-'+$nonce;$description='Owned original '+$nonce;$changedDescription='Owned reviewed '+$nonce
$sid='S-1-5-21-111111111-222222222-333333333-1234'
$root=Join-Path $env:RUNNER_TEMP ('wela-wec-update-'+$nonce);$null=New-Item -ItemType Directory $root
$created=$false;$beforeIds=$null;$primary=$null
try {
 if($beforeService.StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Manual}
 if($beforeService.State -eq 'Stopped'){Start-Service Wecsvc}
 $beforeIds=@(Subscriptions);if($beforeIds -contains $id){throw 'Unique ID already exists.'}
 $query='<QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[(EventID=1)]]</Select></Query></QueryList>'
 $xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><SubscriptionId>$id</SubscriptionId><SubscriptionType>SourceInitiated</SubscriptionType><Description>$description</Description><Enabled>false</Enabled><Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri><ConfigurationMode>Normal</ConfigurationMode><Query><![CDATA[$query]]></Query><ReadExistingEvents>false</ReadExistingEvents><TransportName>HTTP</TransportName><ContentFormat>Events</ContentFormat><Locale Language="en-US"/><LogFile>ForwardedEvents</LogFile><AllowedSourceDomainComputers>$(Get-WelaWefAuthorization @($sid))</AllowedSourceDomainComputers></Subscription>
"@
 $xmlPath=Join-Path $root 'owned.xml';[IO.File]::WriteAllText($xmlPath,$xml);$created=$true;$null=Invoke-WelaNative 'wecutil.exe' @('cs',$xmlPath)
 $before=Read-WelaWecUpdateDefinition $id @($sid);$duringService=ServiceState
 $queryPath=Join-Path $root 'query.xml';[IO.File]::WriteAllText($queryPath,$query.Replace('EventID=1','EventID=2'))
 $plan=Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description $changedDescription -OutputPath (Join-Path $root 'plan')
 Assert ($plan.ExitCode -eq 0) "Native plan: $($plan.Diagnostic)"
 Assert ((Read-WelaWecUpdateDefinition $id @($sid)).WholeKey -ceq $before.WholeKey) 'Planning is read only'
 $planPath=Join-Path $plan.OutputPath 'plan.json'
 $apply=Invoke-WelaWecUpdate Apply -PlanPath $planPath -PlanHash $plan.PlanHash -OutputPath (Join-Path $root 'apply')
 if($apply.ExitCode){throw ($apply|ConvertTo-Json -Depth 24)}
 Assert ($apply.Status -eq 'UpdatedAndVerified' -and $apply.NativeSaveAttempted) 'Native existing-only save succeeded'
 $after=Read-WelaWecUpdateDefinition $id @($sid)
 Assert ($after.PreservedKey -ceq $before.PreservedKey -and $after.Description -ceq $changedDescription -and $after.QueryKey -ceq (ConvertFrom-WelaWefQuery ([IO.File]::ReadAllText($queryPath))).Key) 'Only query/description changed; complete remaining XML preserved'
 Assert ($apply.ReadyRuleCredit -eq 0) 'No delivery/Sigma credit'
 $stale=Invoke-WelaWecUpdate Apply -PlanPath $planPath -PlanHash $plan.PlanHash -OutputPath (Join-Path $root 'stale')
 Assert ($stale.ExitCode -eq 1 -and -not $stale.NativeSaveAttempted -and $stale.Diagnostic -match 'differs') 'Stale actual definition refuses another native save'
 Assert ((Read-WelaWecUpdateDefinition $id @($sid)).WholeKey -ceq $after.WholeKey) 'Stale refusal preserves native definition'
 $samePlan=Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description $changedDescription -OutputPath (Join-Path $root 'same-plan')
 $same=Invoke-WelaWecUpdate Apply -PlanPath (Join-Path $samePlan.OutputPath 'plan.json') -PlanHash $samePlan.PlanHash -OutputPath (Join-Path $root 'same')
 Assert ($same.ExitCode -eq 0 -and $same.Status -eq 'AlreadyMatches' -and -not $same.NativeSaveAttempted) 'Native idempotence does not save'
 [IO.File]::WriteAllText($queryPath,$before.QueryXml)
 $restorePlan=Invoke-WelaWecUpdate Plan -Id $id -SourceSids @($sid) -QueryPath $queryPath -Description $description -OutputPath (Join-Path $root 'restore-plan')
 $restore=Invoke-WelaWecUpdate Apply -PlanPath (Join-Path $restorePlan.OutputPath 'plan.json') -PlanHash $restorePlan.PlanHash -OutputPath (Join-Path $root 'restore')
 Assert ($restore.ExitCode -eq 0 -and (Read-WelaWecUpdateDefinition $id @($sid)).WholeKey -ceq $before.WholeKey) "Original query/description restored: $($restore.Diagnostic)"
 Assert ((Key (ServiceState)) -ceq (Key $duringService)) 'Production updater did not change Wecsvc'
 Write-Host "Native WEC update passed $count assertions on $([Environment]::OSVersion.Version), PowerShell $($PSVersionTable.PSVersion). Disabled subscription only; no delivery/bookmark claim."
}catch{$primary=$_}
finally {
 $errors=@()
 try {
  if($created -and @(Subscriptions) -contains $id){$raw=[string]::Concat((Invoke-WelaNative 'wecutil.exe' @('gs',$id,'/f:xml')).Diagnostic);$doc=Read-WelaWefXml $raw;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s',$doc.DocumentElement.NamespaceURI);$observed=$doc.SelectSingleNode('/s:Subscription/s:Description',$ns).InnerText;if($observed -cnotin @($description,$changedDescription)){throw 'Fixture ownership changed; refusing deletion.'};$null=Invoke-WelaNative 'wecutil.exe' @('ds',$id)}
  if($null -ne $beforeIds -and (Key @($beforeIds|Sort-Object)) -cne (Key @(Subscriptions|Sort-Object))){throw 'Subscription inventory differs after cleanup.'}
 }catch{$errors+=$_.Exception.Message}
 try {
  if($beforeService.State -eq 'Stopped' -and (Get-Service Wecsvc).Status -ne 'Stopped'){Stop-Service Wecsvc}
  if($beforeService.StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Disabled}
  if((Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){if($beforeDelayed.ValueExists){$null=New-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $beforeDelayed.Value -PropertyType $beforeDelayed.Type -Force}else{Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop}}
  if((Key (ServiceState)) -cne (Key $beforeService) -or (Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){throw 'Original Wecsvc state/startup differs.'}
 }catch{$errors+=$_.Exception.Message}
 if($errors.Count){throw "Fixture cleanup failed; retained $root : $($errors -join '; '); primary failure: $primary"}
 Write-Host 'Original subscription inventory and Wecsvc state/startup restored.'
}
if($primary){throw $primary}
$global:LASTEXITCODE=0
