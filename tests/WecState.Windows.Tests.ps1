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
. "$repo/scripts/WecRuntime.ps1"
. "$repo/scripts/WecState.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function ServiceState {Get-CimInstance Win32_Service -Filter "Name='Wecsvc'"|Select-Object Name,State,StartMode}
function Subscriptions {@((Invoke-WelaNative 'wecutil.exe' @('es')).Output|ForEach-Object {$_.ToString().Trim()}|Where-Object {$_})}
function Invoke-Cli {
 param([string[]]$Arguments,[string]$Output,[bool]$Success=$true)
 $engine=(Get-Process -Id $PID).Path
 $prior=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$text=@(&$engine -NoLogo -NoProfile -NonInteractive -File "$repo/WELA.ps1" wec-state @Arguments -WecStateOutputPath $Output 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
 Assert (($code -eq 0) -eq $Success) "Public CLI exit $code : $($text -join ' ')"
 $manifest=Join-Path $Output 'manifest.json';Assert (Test-Path $manifest) 'Public command emitted actual durable result'
 Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json
}
$beforeService=ServiceState;$serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc';$beforeDelayed=Get-WelaRegistryState $serviceKey DelayedAutoStart
if($beforeService.State -notin @('Running','Stopped') -or $beforeService.StartMode -notin @('Auto','Manual','Disabled')){throw 'Stable Wecsvc state required.'}
$nonce=[guid]::NewGuid().ToString('N');$id='WELA-State-Test-'+$nonce;$description='Owned state '+([string][char]0x65e5)+([string][char]0x672c)+([string][char]0x8a9e)+' '+$nonce;$changedDescription=$description
$sid='S-1-5-21-111111111-222222222-333333333-1234'
$root=Join-Path $env:RUNNER_TEMP ('wela-wec-state-'+$nonce);$null=New-Item -ItemType Directory $root
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
 $before=Read-WelaWecStateDefinition $id @($sid);$duringService=ServiceState
 Assert (-not $before.Enabled -and $before.Description -ceq $description) 'Real owned disabled subscription preserves Unicode description'
 Initialize-WelaWecStateNative
 $missing=$false;try{$unexpected=[Wela.WecState.Edit]::new($id+'-absent');$unexpected.Dispose()}catch{$missing=$true}
 Assert ($missing -and @(Subscriptions) -notcontains ($id+'-absent')) 'Native existing-only open never creates missing subscription'
 $enablePlan=$null
 foreach($state in @('Disabled','Enabled','Enabled','Disabled','Disabled')){
  $index=$count;$out=Join-Path $root ("plan-$index")
  $prior=Read-WelaWecStateDefinition $id @($sid)
  $plan=Invoke-Cli -Arguments @('-WecStateId',$id,'-WecStateSourceSid',$sid,'-WecStateDesired',$state) -Output $out
  Assert ($plan.Status -eq 'ReviewRequired' -and -not $plan.NativeSaveAttempted) 'Public plan never changes Enabled'
  Assert ((Read-WelaWecStateDefinition $id @($sid)).WholeKey -ceq $prior.WholeKey) 'Plan preserved complete native subscription'
  $planPath=Join-Path $out 'plan.json'
  $apply=Invoke-Cli -Arguments @('-WecStateAction','Apply','-WecStatePlanPath',$planPath,'-WecStatePlanHash',$plan.PlanHash) -Output (Join-Path $root ("apply-$index"))
  $expected=($state -eq 'Enabled');$changed=($prior.Enabled -ne $expected)
  Assert ($apply.NativeSaveAttempted -eq $changed -and $apply.Status -eq $(if($changed){'StateChangedAndVerified'}else{'AlreadyMatches'})) 'Only an actual state transition invokes EcSaveSubscription'
  $after=Read-WelaWecStateDefinition $id @($sid)
  Assert ($after.Enabled -eq $expected -and $after.PreservedKey -ceq $before.PreservedKey) 'Native readback differs only in Enabled'
  Assert ($apply.ReadyRuleCredit -eq 0 -and $apply.BookmarkContinuity -eq 'Not established' -and $null -ne $apply.RuntimeAfter) 'Separate native runtime observation supplies no delivery or bookmark claim'
  foreach($artifact in $apply.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $apply.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Saved native artifacts match hashes'}
  if($changed -and $expected){
   $enablePlan=$plan
   $stale=Invoke-Cli -Arguments @('-WecStateAction','Apply','-WecStatePlanPath',$planPath,'-WecStatePlanHash',$plan.PlanHash) -Output (Join-Path $root 'stale-enabled-plan') -Success $false
   Assert ($stale.Status -eq 'Refused' -and -not $stale.NativeSaveAttempted -and $stale.Diagnostic -match 'differs') 'A completed transition cannot replay its stale pre-state'
   Assert ((Read-WelaWecStateDefinition $id @($sid)).WholeKey -ceq $after.WholeKey) 'Stale plan refusal preserved enabled definition'
  }
 }
 Assert ((Read-WelaWecStateDefinition $id @($sid)).WholeKey -ceq $before.WholeKey) 'Explicit disable restored entire original native definition'
 # A separately opened native handle sees a changed description and refuses save.
 $edit=New-WelaWecStateEdit $before
 try {
  $null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+($description+' drift')))
  $refused=$false;try{$edit.Save($true)}catch{$refused=$true}
  Assert ($refused -and -not $edit.SaveAttempted) 'Fresh native handle guards description drift before saving'
  Assert (-not(Read-WelaWecStateDefinition $id @($sid)).Enabled) 'Native drift refusal did not enable subscription'
 }finally{$edit.Dispose();$null=Invoke-WelaNative 'wecutil.exe' @('ss',$id,('/d:'+$description))}
 Assert ((Read-WelaWecStateDefinition $id @($sid)).WholeKey -ceq $before.WholeKey) 'Native drift fixture restored original description'
 Assert ((Key (ServiceState)) -ceq (Key $duringService)) 'Product command preserved service state/startup'
 Write-Host "Native WEC state passed $count assertions on $([Environment]::OSVersion.Version), PowerShell $($PSVersionTable.PSVersion). No real source, listener or bookmark claim."
}catch{$primary=$_}
finally {
 $errors=@()
 try {
  if($created -and @(Subscriptions) -contains $id){$raw=Read-WelaWecSubscriptionXml $id;$doc=Read-WelaWefXml $raw;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s',$doc.DocumentElement.NamespaceURI);$observed=$doc.SelectSingleNode('/s:Subscription/s:Description',$ns).InnerText;if($observed -cnotin @($description,$changedDescription)){throw 'Fixture ownership changed; refusing deletion.'};$null=Invoke-WelaNative 'wecutil.exe' @('ds',$id)}
  if($null -ne $beforeIds -and (Key @($beforeIds|Sort-Object)) -cne (Key @(Subscriptions|Sort-Object))){throw 'Subscription inventory differs after cleanup.'}
 }catch{$errors+=$_.Exception.Message}
 try {
  if($beforeService.State -eq 'Stopped' -and (Get-Service Wecsvc).Status -ne 'Stopped'){Stop-Service Wecsvc}
  if($beforeService.StartMode -eq 'Disabled'){Set-Service Wecsvc -StartupType Disabled}
  if((Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){if($beforeDelayed.ValueExists){$null=New-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $beforeDelayed.Value -PropertyType $beforeDelayed.Type -Force}else{Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop}}
  if((Key (ServiceState)) -cne (Key $beforeService) -or (Key (Get-WelaRegistryState $serviceKey DelayedAutoStart)) -cne (Key $beforeDelayed)){throw 'Original Wecsvc state/startup differs.'}
 }catch{$errors+=$_.Exception.Message}
 if($errors.Count){throw "Fixture cleanup failed; retained $root : $($errors -join '; '); primary failure: $primary"}
 [pscustomobject]@{Passed=($null -eq $primary);Assertions=$count;OriginalSubscriptionsRestored=$true;OriginalServiceRestored=$true;Computer=[Environment]::MachineName;Engine=$PSVersionTable.PSVersion.ToString();Scope='Owned native Enabled transitions only; no real source, listener, forwarding or bookmark proof'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'acceptance.json') -Encoding UTF8
 Write-Host 'Original subscription inventory and Wecsvc state/startup restored.'
}
if($primary){throw $primary}
$global:LASTEXITCODE=0
