$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/AppLockerReadiness.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AppLockerScriptProbe.ps1"
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
$policy='<AppLockerPolicy Version="1"><RuleCollection Type="Script" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Windows" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$state=[pscustomobject]@{Host=[pscustomobject]@{Status='Candidate';Is64BitProcess=$true;PartOfDomain=$false;ProductType=3;Build=20348};MachineGuid='11111111-1111-1111-1111-111111111111';Management=[pscustomobject]@{Status='Observed'};Computer='TEST';Domain='WORKGROUP';Reader=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1000'};EffectivePolicy=[pscustomobject]@{Status='Observed';Policy=(ConvertFrom-WelaAppLockerXml $policy)};Service=[pscustomobject]@{Status='Observed';State='Running';StartMode='Manual'};Channel=[pscustomobject]@{Name='Microsoft-Windows-AppLocker/MSI and Script';Enabled=$true;SecurityDescriptor='O:SYG:SYD:(A;;0x1;;;SY)'};Source='C:\Windows\System32\cmd.ps1';SourceHash=('a'*64)}
$state|Add-Member NoteProperty LocalPolicy ($state.EffectivePolicy|ConvertTo-Json -Depth 20|ConvertFrom-Json)
$null=Get-WelaAppLockerScriptStateKey $state;Assert $true 'Valid audit-only prereqs'
foreach($mode in @('Enabled','NotConfigured')){$state.EffectivePolicy.Policy=ConvertFrom-WelaAppLockerXml ($policy.Replace('AuditOnly',$mode));Reject {Get-WelaAppLockerScriptStateKey $state} 'AuditOnly'}
$state.EffectivePolicy.Policy=ConvertFrom-WelaAppLockerXml $policy
$state.Service.State='Stopped';Reject {Get-WelaAppLockerScriptStateKey $state} 'already be running';$state.Service.State='Running'
$state.Channel.Enabled=$false;Reject {Get-WelaAppLockerScriptStateKey $state} 'enabled';$state.Channel.Enabled=$true
$process=[pscustomobject]@{ScriptPath='C:\Temp\wela-owned.ps1';ProcessId=1234;UserSid=$state.Reader.Sid;StartedUtc='2026-09-01T00:00:00.0000000Z';CompletedUtc='2026-09-01T00:00:02.0000000Z'}
$event='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-AppLocker" Guid="{cbda4dbf-8d5d-4f69-9578-be14aa540d22}"/><EventID>8006</EventID><Version>0</Version><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-09-01T00:00:01.0000000Z"/><Channel>Microsoft-Windows-AppLocker/MSI and Script</Channel><Computer>TEST</Computer></System><UserData><RuleAndFileData xmlns="http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0"><PolicyName>SCRIPT</PolicyName><TargetUser>S-1-5-21-1-2-3-1000</TargetUser><TargetProcessId>1234</TargetProcessId><FilePath>C:\Temp\wela-owned.ps1</FilePath></RuleAndFileData></UserData></Event>'
$end=[long]41
Assert (Test-WelaAppLockerScriptEvent $event $process $state $end) 'Exact fixture must match'
Assert (Test-WelaAppLockerScriptEvent ($event.Replace('8006','8005')) $process $state $end) 'Allowed event matches but has distinct EventId'
$mutations=@(@('8006','8007'),@('1234','1235'),@('S-1-5-21-1-2-3-1000','S-1-5-21-1-2-3-1001'),@('C:\Temp\wela-owned.ps1','C:\Temp\other.ps1'),@('<PolicyName>SCRIPT','<PolicyName>DLL'),@('<Computer>TEST','<Computer>OTHER'),@('cbda4dbf','abda4dbf'),@('<Version>0','<Version>1'),@('00:00:01.0000000Z','00:00:03.0000000Z'),@('</System>','<EventID>8006</EventID></System>'),@('</RuleAndFileData>','<TargetUser>S-1-1-0</TargetUser></RuleAndFileData>'))
foreach($pair in $mutations){$bad=$event.Replace($pair[0],$pair[1]);Assert ($bad -cne $event) 'Mutation changed fixture';Assert (-not(Test-WelaAppLockerScriptEvent $bad $process $state $end)) ('Reject '+$pair[0])}
Assert (-not(Test-WelaAppLockerScriptEvent ('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]>'+$event) $process $state $end)) 'DTD rejected'
Reject {Invoke-WelaAppLockerScriptProbe -Action Run} 'requires'
Reject {Invoke-WelaAppLockerScriptProbe -Action Plan -OutputPath ignored} 'requires'

Assert (-not(Test-WelaAppLockerScriptEvent $event $process $state 42)) 'Previously observed record is rejected'
Assert (-not(Test-WelaAppLockerScriptEvent ($event.Replace('00:00:01.0000000Z','00:00:02.0000001Z')) $process $state $end)) 'A 100ns late record is rejected without clock padding'
Assert (Test-WelaAppLockerScriptEvent ($event.Replace('00:00:01.0000000Z','00:00:00.0000000Z')) $process $state $end) 'Exact inclusive start is accepted'
Assert (Test-WelaAppLockerScriptEvent ($event.Replace('00:00:01.0000000Z','00:00:02.0000000Z')) $process $state $end) 'Exact inclusive completion is accepted'
$worker=[IO.File]::ReadAllText("$repo/scripts/AppLockerScriptWorker.ps1")
$text=New-WelaAppLockerScriptText $worker ('a'*32)
Assert ($text -notlike '*__WELA_SCRIPT_NONCE__*') 'All three fixed nonce placeholders replaced'
Reject {New-WelaAppLockerScriptText $worker ('a'*31+"'" )} 'nonce'
Reject {New-WelaAppLockerScriptText ($worker+'__WELA_SCRIPT_NONCE__') ('a'*32)} 'template'
$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
Assert (-not $errors.Count) 'Generated worker parses'
# Use the production orchestration with mocked native read/launch boundaries.
# These fixtures never stand in for actual native success; the Windows matrix does that.
$script:ScriptRoot=$repo;$script:scenario='ok';$script:reads=0;$script:state=$state;$script:event=$event
$script:token=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1000';AuthenticationId='0x123';Groups=@();Privileges=@();TokenId='0x456';ModifiedId='0x789'}
function Initialize-WelaAppLockerScriptNative {}
function Get-WelaAppLockerScriptReader {if($script:scenario -eq 'reader-drift' -and $script:reads -gt 2){$script:token.ModifiedId='0xabc'};$script:token|ConvertTo-Json -Depth 8|ConvertFrom-Json}
function Get-WelaAppLockerScriptUtcNow {([DateTimeOffset]::Parse('2026-09-01T00:00:00Z')).UtcDateTime}
function Get-WelaAppLockerScriptState {$script:reads++;if($script:scenario -eq 'drift' -and $script:reads -gt 2){$script:state.Service.StartMode='Auto'};$script:state|ConvertTo-Json -Depth 20|ConvertFrom-Json}
function Read-WelaAppLockerScriptBoundary {41}
function Start-WelaAppLockerScriptProcess {
 param($Root,$State,$Reader,$SourcesKey)
 if($script:scenario -eq 'reader-drift'){$script:token.ModifiedId='0xabc'}
 $artifact=Write-WelaArrivalArtifact $Root 'fixed.ps1' 'fixed'
 [pscustomobject]@{ScriptPath=(Join-Path $Root 'fixed.ps1');ScriptSha256=$artifact.Sha256;ScriptArtifact=$artifact;Nonce=('a'*32)}
}
function Read-WelaAppLockerScriptEvents {param($Boundary);if($script:scenario -eq 'denied'){throw [UnauthorizedAccessException]::new('Native query denied')};[pscustomobject]@{Xml=if($script:scenario -eq 'duplicate'){@($script:event,$script:event)}elseif($script:scenario -eq 'absent'){@()}else{@($script:event)};Complete=($script:scenario -ne 'cap')}}
function Test-WelaAppLockerScriptEvent {$true}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-applocker-script-test-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
try {
 foreach($scenario in @('ok','duplicate','drift','cap','denied','absent','reader-drift')){
  $script:scenario=$scenario;$script:reads=0;$state.Service.StartMode='Manual';$script:token.ModifiedId='0x789'
  $result=Invoke-WelaAppLockerScriptProbe Run (Join-Path $root $scenario) 1
  Assert ($result.ReadyRuleCredit -eq 0 -and $result.PolicyChanges -eq 0) 'No readiness or configuration credit'
  Assert (($result.ExitCode -eq 0) -eq ($scenario -eq 'ok')) "Expected outcome $scenario : $($result.Diagnostic)"
  Assert (($result.Status -ceq 'NativeScriptEventObserved') -eq ($scenario -eq 'ok')) 'Only complete success receives observed status'
  Assert (Test-Path (Join-Path $result.OutputPath 'manifest.json')) 'Success/failure manifest retained'
 }
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "AppLocker Script fixtures passed: $count assertions."
