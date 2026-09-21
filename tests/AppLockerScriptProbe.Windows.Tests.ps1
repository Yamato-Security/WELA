param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){Write-Host 'Skipped: Windows required.';exit 0}
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted policy-write opt-in required.'}
function Refresh-DisposableComputerPolicy {
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=Join-Path ([Environment]::SystemDirectory) 'gpupdate.exe';$info.Arguments='/target:computer /force /wait:30';$info.UseShellExecute=$false
 $process=[Diagnostics.Process]::Start($info)
 try {if(-not $process.WaitForExit(60000)){$process.Kill();throw 'Disposable computer policy refresh exceeded 60 seconds.'};if($process.ExitCode -ne 0){throw ('Disposable computer policy refresh failed: '+$process.ExitCode)}} finally {$process.Dispose()}
}
function Stop-DisposablePolicyConverter {
 $task=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop
 if($task.State -in @('Running','Queued')) {Stop-ScheduledTask -InputObject $task -ErrorAction Stop}
 $deadline=[DateTime]::UtcNow.AddSeconds(15)
 do {$task=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop;if($task.State -in @('Ready','Disabled')){return};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $deadline)
 throw 'The verified borrowed PolicyConverter task did not become idle.'
}
function Run-DisposablePolicyConverter {
 # The Task Scheduler CIM provider can retain stale LastRunTime on Server2022.
 # Follow the actual COM Run instance and native completion state instead.
 $scheduler=$null;$folder=$null;$registered=$null;$instance=$null;$running=$null;$definition=$null;$settings=$null
 try {
  $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
  $folder=$scheduler.GetFolder('\Microsoft\Windows\AppID');$registered=$folder.GetTask('PolicyConverter')
  $definition=$registered.Definition;$settings=$definition.Settings
  if(-not $settings.AllowDemandStart){throw 'The verified PolicyConverter task does not allow an on-demand invocation.'}
  $running=$registered.GetInstances(0)
  if($running.Count -ne 0 -or $registered.State -ne 3){throw 'The verified borrowed PolicyConverter task must be idle before invocation.'}
  $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($running);$running=$null
  $instance=$registered.Run($null)
  if($null -eq $instance -or [string]::IsNullOrWhiteSpace($instance.InstanceGuid)){throw 'Native PolicyConverter did not return a task instance identity.'}
  $instanceId=[string]$instance.InstanceGuid;$deadline=[DateTime]::UtcNow.AddSeconds(30)
  do {
   $running=$registered.GetInstances(0)
   try {$idle=$running.Count -eq 0 -and $registered.State -eq 3}finally{$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($running);$running=$null}
   if($idle){if($registered.LastTaskResult -ne 0){throw ('Native policy conversion failed: '+$registered.LastTaskResult)};Write-Host ('Native PolicyConverter instance completed: '+$instanceId);return}
   Start-Sleep -Milliseconds 200
  }while([DateTime]::UtcNow -lt $deadline)
  Stop-DisposablePolicyConverter
  throw 'The owned native PolicyConverter instance did not complete within thirty seconds.'
 }finally{foreach($item in @($running,$instance,$settings,$definition,$registered,$folder,$scheduler)){if($null -ne $item -and [Runtime.InteropServices.Marshal]::IsComObject($item)){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)}}}
}

$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/AppLockerReadiness.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AppLockerScriptProbe.ps1"
$script:ScriptRoot=$repo
$root=Join-Path $env:RUNNER_TEMP ('wela-applocker-script-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
Write-Host ('Native fixture process session: '+[Diagnostics.Process]::GetCurrentProcess().SessionId)
$converter=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop
$converterBefore=Export-ScheduledTask -InputObject $converter -ErrorAction Stop
$converterDisabled=$converter.State -eq 'Disabled';$converterChanged=$false
$actions=@($converter.Actions)
if($converter.State -notin @('Disabled','Ready') -or $actions.Count -ne 1 -or [Environment]::ExpandEnvironmentVariables($actions[0].Execute).Trim('"') -ine (Join-Path ([Environment]::SystemDirectory) 'appidpolicyconverter.exe') -or $actions[0].Arguments){throw ('Only the unchanged native PolicyConverter action is permitted: '+($actions|ConvertTo-Json -Depth 8))}
$before=Get-WelaAppLockerReadiness
if($before.Host.PartOfDomain -or $before.Management.Status -ne 'Observed' -or $before.LocalPolicy.Status -ne 'Observed' -or $before.EffectiveGpPolicy.Status -ne 'Observed' -or $before.LocalPolicy.Policy.TotalRules -ne 0 -or $before.EffectiveGpPolicy.Policy.TotalRules -ne 0 -or $before.LocalPolicy.Policy.HasUnknownPolicyData -or $before.EffectiveGpPolicy.Policy.HasUnknownPolicyData){Write-Host ($before | ConvertTo-Json -Depth 16);throw 'Disposable test requires empty, understood local/effective policies on a non-domain disposable host.'}
$backup=Join-Path $root 'policy-before.xml';[IO.File]::WriteAllText($backup,$before.LocalPolicy.Policy.Xml)
[IO.File]::WriteAllText((Join-Path $root 'prerequisites-before.json'),($before | ConvertTo-Json -Depth 16))
$fixture='<AppLockerPolicy Version="1"><RuleCollection Type="Script" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Disposable Windows path only" Description="Owned native event fixture" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$policyPath=Join-Path $root 'fixture.xml';[IO.File]::WriteAllText($policyPath,$fixture)
$log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/MSI and Script');$enabled=$log.IsEnabled;$touched=$false;$cleanup=@();$primary=$null
try {
 $touched=$true
 # Test-only preparation under explicit disposable-host and empty-GP gates.
 # Hosted images contain enrollment/provider keys: preserve them and CSP Unknown.
 # The production importer must continue to reject those observations.
 $preparedUtc=[DateTime]::UtcNow
 Set-AppLockerPolicy -XmlPolicy $policyPath -ErrorAction Stop
 if($before.Service.StartMode -eq 'Disabled'){throw 'Test will not change protected AppIDSvc startup mode.'}
 if($before.Service.State -ne 'Running'){Start-Service AppIDSvc -ErrorAction Stop}
 $log.IsEnabled=$true;$log.SaveChanges()
 if($converterDisabled){$converterChanged=$true;$null=Enable-ScheduledTask -InputObject $converter -ErrorAction Stop}
 Refresh-DisposableComputerPolicy
 Run-DisposablePolicyConverter
 $applied=$false;$applyDeadline=[DateTime]::UtcNow.AddSeconds(30)
 do {
  $records=@()
  try {try{$records=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL';Id=8001;StartTime=$preparedUtc} -MaxEvents 10 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}};$applied=$records.Count -gt 0} finally {foreach($record in $records){$record.Dispose()}}
  if($applied){break};Start-Sleep -Milliseconds 250
 } while([DateTime]::UtcNow -lt $applyDeadline)
 if(-not $applied){throw 'No native 8001 policy-applied event after disposable GP refresh.'}
 Write-Host 'Native 8001 policy-applied evidence observed after disposable GP refresh.'
 # Wait for actual effective audit-only policy, without treating elapsed time as success.
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do {$state=Get-WelaAppLockerScriptState;$ready=$false;try{$null=Get-WelaAppLockerScriptStateKey $state;$ready=$true}catch{};if($ready){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
 foreach($decision in @('WouldBlock','Allowed')) {
  if($decision -eq 'Allowed'){
   [IO.File]::WriteAllText($policyPath,$fixture.Replace('%WINDIR%\*','*'))
   Set-AppLockerPolicy -XmlPolicy $policyPath -ErrorAction Stop
   Refresh-DisposableComputerPolicy;Run-DisposablePolicyConverter
   $expected=ConvertFrom-WelaAppLockerXml ([IO.File]::ReadAllText($policyPath))
   $actual=Get-WelaAppLockerPolicySnapshot Effective
   if($actual.Status -ne 'Observed' -or (Get-WelaAppLockerXmlKey $actual.Policy.Xml) -cne (Get-WelaAppLockerXmlKey $expected.Xml)){throw 'Actual allowed Script policy differs from the disposable fixture.'}
  }
  $probe=& "$repo/WELA.ps1" applocker-script-probe -AppLockerScriptAction Run -AppLockerScriptOutputPath (Join-Path $root ('evidence-'+$decision)) -AppLockerScriptTimeoutSeconds 30
  $expectedId=if($decision -eq 'Allowed'){8005}else{8006}
  if($probe.ExitCode -or $probe.Status -cne 'NativeScriptEventObserved' -or $probe.EventId -ne $expectedId){throw ($probe|ConvertTo-Json -Depth 32)}
  if($probe.ReadyRuleCredit -ne 0 -or $probe.PolicyChanges -ne 0){throw 'Unsupported policy/credit claim.'}
  foreach($artifact in $probe.Artifacts){if((Get-FileHash (Join-Path $probe.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Artifact hash mismatch'}}
  Write-Host "Native AppLocker $expectedId observed via public CLI under PowerShell $($PSVersionTable.PSVersion), build $($probe.Before.Host.Build). Zero Sigma credit."
 }

} catch {
 $primary=$_;Write-Host $_
 Get-ChildItem -LiteralPath $root -Recurse -Filter 'candidate-*.xml'|ForEach-Object {Write-Host ([IO.File]::ReadAllText($_.FullName))}
 # Read-only diagnostic independent of the production XPath filter and parser.
 try {
  $recent=@(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -MaxEvents 12 -ErrorAction Stop)
  try {foreach($record in $recent){Write-Host ('Recent native channel XML: '+$record.ToXml())}} finally {foreach($record in $recent){$record.Dispose()}}
 } catch {Write-Host ('Recent native channel read: '+$_.Exception.Message)}
 Get-CimInstance Win32_SystemDriver -Filter "Name='AppID'" | Select-Object Name,State,StartMode | ConvertTo-Json | Write-Host
 try {Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -ErrorAction Stop | Select-Object TaskName,State | ConvertTo-Json | Write-Host}catch{Write-Host ('AppID task read: '+$_.Exception.Message)}
 try {$nativeLog=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/MSI and Script');try{$nativeLog | Select-Object IsEnabled,LogType,ProviderLevel,ProviderKeywords,LogIsolation | ConvertTo-Json | Write-Host}finally{$nativeLog.Dispose()}}catch{Write-Host ('Channel metadata read: '+$_.Exception.Message)}
 Write-Host ((Get-WelaAppLockerPolicySnapshot Effective) | ConvertTo-Json -Depth 12)
}
finally {
 if($touched){
  try {Stop-DisposablePolicyConverter}catch{$cleanup+=$_.Exception.Message}
  try {Set-AppLockerPolicy -XmlPolicy $backup -ErrorAction Stop;Refresh-DisposableComputerPolicy;if($converterChanged -or -not $converterDisabled){Run-DisposablePolicyConverter};$restored=Get-WelaAppLockerPolicySnapshot Local;if($restored.Status -ne 'Observed' -or (Get-WelaAppLockerXmlKey $restored.Policy.Xml) -cne (Get-WelaAppLockerXmlKey $before.LocalPolicy.Policy.Xml)){throw 'Local policy restoration differs'};$effectiveRestored=Get-WelaAppLockerPolicySnapshot Effective;if($effectiveRestored.Status -ne 'Observed' -or (Get-WelaAppLockerXmlKey $effectiveRestored.Policy.Xml) -cne (Get-WelaAppLockerXmlKey $before.EffectiveGpPolicy.Policy.Xml)){throw 'Effective GP policy restoration differs'}}catch{$cleanup+=$_.Exception.Message}
  try {Stop-DisposablePolicyConverter;if($converterChanged){$null=Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop};$taskAfter=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop;if($taskAfter.State -ne $(if($converterDisabled){'Disabled'}else{'Ready'}) -or (Export-ScheduledTask -InputObject $taskAfter -ErrorAction Stop) -cne $converterBefore){throw 'Native PolicyConverter task definition was not restored'}}catch{$cleanup+=$_.Exception.Message}
  try {$log.IsEnabled=$enabled;$log.SaveChanges();$verify=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($log.LogName);try{if($verify.IsEnabled -ne $enabled){throw 'Channel restoration differs'}}finally{$verify.Dispose()}}catch{$cleanup+=$_.Exception.Message}
  if($before.Service.State -ne 'Running') {try {Stop-Service AppIDSvc -ErrorAction Stop}catch{Write-Host 'Protected AppIDSvc could not stop; startup mode was untouched. The disposable hosted VM is discarded after this job.'}}
  $afterService=Get-WelaAppLockerService;if($afterService.StartMode -ne $before.Service.StartMode){$cleanup+='AppIDSvc startup mode changed'}
 }
 $log.Dispose()
}
if($cleanup.Count){throw ('Native cleanup failed: '+($cleanup -join '; '))}
if($primary){throw $primary}
$cleanupReceipt=[pscustomobject]@{Head=$env:GITHUB_SHA;Engine=[string]$PSVersionTable.PSVersion;PolicyRestored=$true;ChannelRestored=$true;TaskRestored=$true;ServiceBefore=$before.Service;ServiceAfter=(Get-WelaAppLockerService);ServiceStateRestored=($before.Service.State -ceq (Get-WelaAppLockerService).State);ServiceStartupPreserved=($before.Service.StartMode -ceq (Get-WelaAppLockerService).StartMode);ProtectedServiceBoundary='If AppIDSvc refuses Stop, its running state is left for disposable VM teardown; no full service-state rollback claim.'}
[IO.File]::WriteAllText((Join-Path $root 'cleanup.json'),($cleanupReceipt|ConvertTo-Json -Depth 8))
Write-Host 'Original local/effective GP policy, channel enablement and converter task restored; service startup mode preserved.'
$global:LASTEXITCODE=0
