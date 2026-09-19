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
function Run-DisposablePolicyConverter {
 # Compare the scheduler's own raw timestamps; CIM DateTime timezone/kind differs across server builds.
 $prior=(Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop).LastRunTime.Ticks
 # Task Scheduler timestamps can have second precision. Separate consecutive owned invocations.
 Start-Sleep -Milliseconds 1100
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 Start-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop
 do {
  $task=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop
  $info=Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
  if($task.State -ne 'Running' -and $info.LastRunTime.Ticks -ne $prior){if($info.LastTaskResult -ne 0){throw ('Native policy conversion failed: '+$info.LastTaskResult)};return}
  Start-Sleep -Milliseconds 200
 }while([DateTime]::UtcNow -lt $deadline)
 throw ('Native policy conversion did not complete within thirty seconds. State='+$task.State+'; beforeTicks='+$prior+'; afterTicks='+$info.LastRunTime.Ticks+'; result='+$info.LastTaskResult)
}
$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/AppLockerReadiness.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AppLockerProbe.ps1"
$root=Join-Path $env:RUNNER_TEMP ('wela-applocker-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
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
$fixture='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Disposable Windows path only" Description="Owned native event fixture" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$policyPath=Join-Path $root 'fixture.xml';[IO.File]::WriteAllText($policyPath,$fixture)
$log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/EXE and DLL');$enabled=$log.IsEnabled;$touched=$false;$cleanup=@();$primary=$null
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
 do {$state=Get-WelaAppLockerProbeState;$ready=$false;try{$null=Get-WelaAppLockerProbeKey $state;$ready=$true}catch{};if($ready){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
 $probe=Invoke-WelaAppLockerProbe -Action Run -OutputPath (Join-Path $root 'evidence') -TimeoutSeconds 30
 if($probe.ExitCode -or $probe.Status -ne 'NativeExeEventObserved' -or $probe.EventId -ne 8003){throw ($probe|ConvertTo-Json -Depth 24)}
 foreach($artifact in $probe.Artifacts){if((Get-FileHash (Join-Path $probe.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Artifact hash mismatch'}}
 Write-Host "Native AppLocker 8003 observed under PowerShell $($PSVersionTable.PSVersion), build $($probe.Before.Host.Build). Zero Sigma credit."
} catch {
 $primary=$_;Write-Host $_
 Get-ChildItem -LiteralPath $root -Recurse -Filter 'candidate-*.xml'|ForEach-Object {Write-Host ([IO.File]::ReadAllText($_.FullName))}
 # Read-only diagnostic independent of the production XPath filter and parser.
 try {
  $recent=@(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 12 -ErrorAction Stop)
  try {foreach($record in $recent){Write-Host ('Recent native channel XML: '+$record.ToXml())}} finally {foreach($record in $recent){$record.Dispose()}}
 } catch {Write-Host ('Recent native channel read: '+$_.Exception.Message)}
 Get-CimInstance Win32_SystemDriver -Filter "Name='AppID'" | Select-Object Name,State,StartMode | ConvertTo-Json | Write-Host
 try {Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -ErrorAction Stop | Select-Object TaskName,State | ConvertTo-Json | Write-Host}catch{Write-Host ('AppID task read: '+$_.Exception.Message)}
 try {$nativeLog=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/EXE and DLL');try{$nativeLog | Select-Object IsEnabled,LogType,ProviderLevel,ProviderKeywords,LogIsolation | ConvertTo-Json | Write-Host}finally{$nativeLog.Dispose()}}catch{Write-Host ('Channel metadata read: '+$_.Exception.Message)}
 Write-Host ((Get-WelaAppLockerPolicySnapshot Effective) | ConvertTo-Json -Depth 12)
}
finally {
 if($touched){
  try {Set-AppLockerPolicy -XmlPolicy $backup -ErrorAction Stop;Refresh-DisposableComputerPolicy;if($converterChanged -or -not $converterDisabled){Run-DisposablePolicyConverter};$restored=Get-WelaAppLockerPolicySnapshot Local;if((Get-WelaAppLockerXmlKey $restored.Policy.Xml) -cne (Get-WelaAppLockerXmlKey $before.LocalPolicy.Policy.Xml)){throw 'Local policy restoration differs'}}catch{$cleanup+=$_.Exception.Message}
  try {if($converterChanged){$null=Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop};$taskAfter=Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop;if((Export-ScheduledTask -InputObject $taskAfter -ErrorAction Stop) -cne $converterBefore){throw 'Native PolicyConverter task definition was not restored'}}catch{$cleanup+=$_.Exception.Message}
  try {$log.IsEnabled=$enabled;$log.SaveChanges();$verify=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($log.LogName);try{if($verify.IsEnabled -ne $enabled){throw 'Channel restoration differs'}}finally{$verify.Dispose()}}catch{$cleanup+=$_.Exception.Message}
  if($before.Service.State -ne 'Running') {try {Stop-Service AppIDSvc -ErrorAction Stop}catch{Write-Host 'Protected AppIDSvc could not stop; startup mode was untouched. The disposable hosted VM is discarded after this job.'}}
  $afterService=Get-WelaAppLockerService;if($afterService.StartMode -ne $before.Service.StartMode){$cleanup+='AppIDSvc startup mode changed'}
 }
 $log.Dispose()
}
if($cleanup.Count){throw ('Native cleanup failed: '+($cleanup -join '; '))}
if($primary){throw $primary}
Write-Host 'Original local policy and channel state restored; service startup mode preserved.'
$global:LASTEXITCODE=0
