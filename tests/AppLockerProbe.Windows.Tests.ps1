param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){Write-Host 'Skipped: Windows required.';exit 0}
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit disposable GitHub-hosted policy-write opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/AppLockerReadiness.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AppLockerProbe.ps1"
$root=Join-Path $env:RUNNER_TEMP ('wela-applocker-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$before=Get-WelaAppLockerReadiness
if($before.Host.PartOfDomain -or $before.Management.Status -ne 'Observed' -or @($before.Management.ManagementEntries).Count -or $before.LocalPolicy.Status -ne 'Observed' -or $before.EffectiveGpPolicy.Status -ne 'Observed' -or $before.LocalPolicy.Policy.TotalRules -ne 0 -or $before.EffectiveGpPolicy.Policy.TotalRules -ne 0 -or $before.LocalPolicy.Policy.HasUnknownPolicyData -or $before.EffectiveGpPolicy.Policy.HasUnknownPolicyData){throw 'Disposable test requires empty, understood local/effective policies and no observed management.'}
$backup=Join-Path $root 'policy-before.xml';[IO.File]::WriteAllText($backup,$before.LocalPolicy.Policy.Xml)
$empty=Join-Path $root 'empty.xml';[IO.File]::WriteAllText($empty,'<AppLockerPolicy Version="1" />')
$fixture='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Disposable Windows path only" Description="Owned native event fixture" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$policyPath=Join-Path $root 'fixture.xml';[IO.File]::WriteAllText($policyPath,$fixture)
$log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/EXE and DLL');$enabled=$log.IsEnabled;$touched=$false;$cleanup=@();$primary=$null
try {
 $touched=$true
 # Exact empty placeholders can retain NotConfigured under -Merge. Clear only the verified empty disposable policy before exercising the real importer.
 Set-AppLockerPolicy -XmlPolicy $empty -ErrorAction Stop
 $result=Invoke-WelaAppLockerCommand -Action Import -PolicyPath $policyPath -Auto -BackupPath (Join-Path $root 'import-backup')
 if($result.ExitCode){throw ($result|ConvertTo-Json -Depth 20)}
 if($before.Service.StartMode -eq 'Disabled'){throw 'Test will not change protected AppIDSvc startup mode.'}
 if($before.Service.State -ne 'Running'){Start-Service AppIDSvc -ErrorAction Stop}
 $log.IsEnabled=$true;$log.SaveChanges()
 # Wait for actual effective audit-only policy, without treating elapsed time as success.
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do {$state=Get-WelaAppLockerProbeState;$ready=$false;try{$null=Get-WelaAppLockerProbeKey $state;$ready=$true}catch{};if($ready){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
 $probe=Invoke-WelaAppLockerProbe -Action Run -OutputPath (Join-Path $root 'evidence') -TimeoutSeconds 30
 if($probe.ExitCode -or $probe.Status -ne 'NativeExeEventObserved' -or $probe.EventId -ne 8003){throw ($probe|ConvertTo-Json -Depth 24)}
 foreach($artifact in $probe.Artifacts){if((Get-FileHash (Join-Path $probe.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Artifact hash mismatch'}}
 Write-Host "Native AppLocker 8003 observed under PowerShell $($PSVersionTable.PSVersion), build $($probe.Before.Host.Build). Zero Sigma credit."
} catch {$primary=$_;Write-Host $_;Get-ChildItem -LiteralPath $root -Recurse -Filter 'candidate-*.xml'|ForEach-Object {Write-Host ([IO.File]::ReadAllText($_.FullName))}}
finally {
 if($touched){
  try {Set-AppLockerPolicy -XmlPolicy $backup -ErrorAction Stop;$restored=Get-WelaAppLockerPolicySnapshot Local;if((Get-WelaAppLockerXmlKey $restored.Policy.Xml) -cne (Get-WelaAppLockerXmlKey $before.LocalPolicy.Policy.Xml)){throw 'Local policy restoration differs'}}catch{$cleanup+=$_.Exception.Message}
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
