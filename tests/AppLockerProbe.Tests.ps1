$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/AppLockerReadiness.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AppLockerProbe.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$policy='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Windows" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$state=[pscustomobject]@{Host=[pscustomobject]@{Status='Candidate';Is64BitProcess=$true;PartOfDomain=$false};Computer='TEST';Domain='WORKGROUP';Reader=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1000'};EffectivePolicy=[pscustomobject]@{Status='Observed';Policy=(ConvertFrom-WelaAppLockerXml $policy)};Service=[pscustomobject]@{Status='Observed';State='Running';StartMode='Manual'};Channel=[pscustomobject]@{Name='Microsoft-Windows-AppLocker/EXE and DLL';Enabled=$true;SecurityDescriptor='O:SYG:SYD:(A;;0x1;;;SY)'};Source='C:\Windows\System32\cmd.exe';SourceHash=('a'*64)}
$null=Get-WelaAppLockerProbeKey $state;Assert $true 'Valid audit-only prereqs'
foreach($mode in @('Enabled','NotConfigured')){$state.EffectivePolicy.Policy=ConvertFrom-WelaAppLockerXml ($policy.Replace('AuditOnly',$mode));Reject {Get-WelaAppLockerProbeKey $state} 'AuditOnly'}
$state.EffectivePolicy.Policy=ConvertFrom-WelaAppLockerXml $policy
$state.Service.State='Stopped';Reject {Get-WelaAppLockerProbeKey $state} 'already be running';$state.Service.State='Running'
$state.Channel.Enabled=$false;Reject {Get-WelaAppLockerProbeKey $state} 'enabled';$state.Channel.Enabled=$true
$process=[pscustomobject]@{Executable='C:\Temp\wela-owned.exe';ProcessId=1234;UserSid=$state.Reader.Sid;StartedUtc='2026-09-01T00:00:00.0000000Z'}
$event='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-AppLocker" Guid="{cbda4dbf-8d5d-4f69-9578-be14aa540d22}"/><EventID>8003</EventID><Version>0</Version><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-09-01T00:00:01.0000000Z"/><Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel><Computer>TEST</Computer></System><UserData><RuleAndFileData xmlns="http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0"><PolicyName>EXE</PolicyName><TargetUser>S-1-5-21-1-2-3-1000</TargetUser><TargetProcessId>1234</TargetProcessId><FilePath>C:\Temp\wela-owned.exe</FilePath></RuleAndFileData></UserData></Event>'
$end=([DateTimeOffset]::Parse('2026-09-01T00:00:02Z')).UtcDateTime
Assert (Test-WelaAppLockerProbeEvent $event $process $state $end) 'Exact fixture must match'
Assert (Test-WelaAppLockerProbeEvent ($event.Replace('8003','8002')) $process $state $end) 'Allowed event matches but has distinct EventId'
$mutations=@(@('8003','8004'),@('1234','1235'),@('S-1-5-21-1-2-3-1000','S-1-5-21-1-2-3-1001'),@('C:\Temp\wela-owned.exe','C:\Temp\other.exe'),@('<PolicyName>EXE','<PolicyName>DLL'),@('<Computer>TEST','<Computer>OTHER'),@('cbda4dbf','abda4dbf'),@('<Version>0','<Version>1'),@('00:00:01.0000000Z','00:00:03.0000000Z'),@('</System>','<EventID>8003</EventID></System>'),@('</RuleAndFileData>','<TargetUser>S-1-1-0</TargetUser></RuleAndFileData>'))
foreach($pair in $mutations){$bad=$event.Replace($pair[0],$pair[1]);Assert ($bad -cne $event) 'Mutation changed fixture';Assert (-not(Test-WelaAppLockerProbeEvent $bad $process $state $end)) ('Reject '+$pair[0])}
Assert (-not(Test-WelaAppLockerProbeEvent ('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]>'+$event) $process $state $end)) 'DTD rejected'
Reject {Invoke-WelaAppLockerProbe -Action Run} 'requires'
Reject {Invoke-WelaAppLockerProbe -Action Plan -OutputPath ignored} 'requires'
# Exercise actual orchestration with mocked native boundaries, including duplicate/drift/cap failures.
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-applocker-test-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$script:state=$state;$script:event=$event;$script:process=$process;$script:scenario='ok';$script:reads=0
function Get-WelaAppLockerProbeState {$script:reads++;if($script:scenario -eq 'drift' -and $script:reads -gt 1){$script:state.Service.StartMode='Auto'};$script:state}
function Start-WelaAppLockerProbeProcess {param($Root,$State);$path=Join-Path $Root 'fixed.exe';[IO.File]::WriteAllText($path,'fixed');$script:process|Add-Member NoteProperty ExecutableHash (Get-FileHash $path).Hash.ToLowerInvariant() -Force;$script:process.Executable=$path;$script:process}
function Read-WelaAppLockerProbeEvents {param($StartUtc,$EndUtc);[pscustomobject]@{Xml=if($script:scenario -eq 'duplicate'){@($script:event,$script:event)}else{@($script:event)};Capped=($script:scenario -eq 'cap')}}
function Test-WelaAppLockerProbeEvent {$true}
try {
 foreach($scenario in @('ok','duplicate','drift','cap')){$script:scenario=$scenario;$script:reads=0;$state.Service.StartMode='Manual';$result=Invoke-WelaAppLockerProbe Run (Join-Path $root $scenario) 1;Assert ($result.ReadyRuleCredit -eq 0 -and $result.PolicyChanges -eq 0) 'No readiness or changes';Assert (($result.ExitCode -eq 0) -eq ($scenario -eq 'ok')) "Expected outcome $scenario : $($result.Diagnostic)";Assert (Test-Path (Join-Path $result.OutputPath 'manifest.json')) 'Failure/success manifest retained'}
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "AppLocker probe tests passed: $count assertions."
