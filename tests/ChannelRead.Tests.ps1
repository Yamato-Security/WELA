$ErrorActionPreference='Stop'
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/WefArrival.ps1')
. (Join-Path $script:ScriptRoot 'scripts/ChannelRead.ps1')
$script:passed=0
function Assert($value,$message){if(-not $value){throw $message};$script:passed++}
function Refuses([scriptblock]$action){$caught=$false;try{&$action|Out-Null}catch{$caught=$true};Assert $caught 'Expected refusal'}
foreach($channels in @(@(),@('Sysmon'),@('ForwardedEvents'),@('Security','Security'),@('security'),@('Security','System','Application','Windows PowerShell','Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-DNS-Client/Operational','Microsoft-Windows-LSA/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-SMBClient/Operational'))){Refuses {Get-WelaChannelReadSelection $channels}}
Assert (@(Get-WelaChannelReadSelection @('Security','System')).Count -eq 2) 'Reviewed channels accepted'
foreach($case in @(@(5,'Denied'),@(15007,'Absent'),@(2,'Absent'),@(87,'Unknown'),@(1460,'Unknown'))){$failure=Get-WelaChannelReadFailure ([ComponentModel.Win32Exception]::new($case[0]));Assert ($failure.Status -eq $case[1]) 'Native numeric error classification'}
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
    Assert ((Get-WelaChannelReadFailure ([Diagnostics.Eventing.Reader.EventLogNotFoundException]::new('synthetic absent channel'))).Status -eq 'Absent') 'Actual EventLogNotFoundException classification'
    Assert ((Get-WelaChannelReadFailure ([Diagnostics.Eventing.Reader.EventLogException]::new('native code unexposed'))).Status -eq 'Unknown') 'EventLogException without exposed native code stays unknown'
}
Assert ((Get-WelaChannelReadFailure ([InvalidOperationException]::new('outer',[UnauthorizedAccessException]::new('inner')))).Status -eq 'Denied') 'Wrapped access denial'
$script:prepared=0;$script:counter=0;$script:driftAt=0;$script:queryState='EventObserved';$script:hostDrift=$false;$script:hostReads=0;$script:sourceDrift=$false;$script:sourceReads=0
function Get-WelaChannelReader {$script:counter++;[pscustomobject][ordered]@{UserSid='S-1-5-21-1-2-3-1001';TokenId='01';AuthenticationId='02';ModifiedId=($script:prepared.ToString()+':'+$(if($script:driftAt -and $script:counter -ge $script:driftAt){'04'}else{'03'}))}}
function Get-WelaChannelReadHost {$script:hostReads++;[pscustomobject]@{Build=$(if($script:hostDrift -and $script:hostReads -gt 1){26100}else{20348})}}
function Get-WelaChannelReadSources {$script:sourceReads++;[pscustomobject]@{Hash=$(if($script:sourceDrift -and $script:sourceReads -gt 1){'b'}else{'a'})}}
# Metadata preparation deliberately changes the synthetic ModifiedId, as Windows APIs can.
function Get-WelaNativeChannel {param($Name)$script:prepared++;[pscustomobject]@{Name=$Name;State='Unknown';Diagnostic='Metadata denied'}}
function Read-WelaChannelLatest {param($Channel)[pscustomobject]@{Channel=$Channel;Status=$script:queryState;Event=$(if($script:queryState -eq 'EventObserved'){[pscustomobject]@{RecordId=42}}else{$null})}}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('wela-channel-read-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $fixture
function RunFixture {
    $script:counter=0;$script:hostReads=0;$script:sourceReads=0
    Invoke-WelaChannelRead @('Security') (Join-Path $fixture ([guid]::NewGuid().ToString('N')))
}
try{
    foreach($status in @('EventObserved','ReadAllowedEmpty','Denied','Absent','Unknown')){
        $script:queryState=$status;$report=RunFixture
        Assert ($report.Status -eq 'Completed') 'Completed query observation'
        Assert ($report.Results[0].AccessVerified -eq ($status -in @('EventObserved','ReadAllowedEmpty'))) 'Access conclusion follows actual query'
        Assert ($report.ExitCode -eq $(if($status -in @('EventObserved','ReadAllowedEmpty')){0}else{1})) 'Exit follows query proof'
        Assert ($report.ReadyRuleCredit -eq 0 -and $report.ConfigurationChanges -eq 0) 'No inferred readiness or mutation'
        Assert ($report.Results[0].ConfigurationObservation.State -eq 'Unknown') 'Metadata access is independent'
        Assert (Test-Path (Join-Path $report.OutputPath 'result.json')) 'Saved bounded report'
        Refuses {Invoke-WelaChannelRead @('Security') $report.OutputPath}
    }
    $script:queryState='EventObserved'
    foreach($at in @(2,3,4)){$script:driftAt=$at;$report=RunFixture;Assert ($report.Status -eq 'Unverified' -and $report.ExitCode -eq 1) 'Token drift cannot prove access';Assert (@($report.Results|Where-Object AccessVerified).Count -eq 0) 'All positive conclusions invalidated'}
    $script:driftAt=0;$script:hostDrift=$true;$report=RunFixture;Assert ($report.Status -eq 'Unverified' -and -not $report.Results[0].AccessVerified) 'Host drift invalidates access'
    $script:hostDrift=$false;$script:sourceDrift=$true;$report=RunFixture;Assert ($report.Status -eq 'Unverified' -and -not $report.Results[0].AccessVerified) 'Implementation drift invalidates access'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
$engine=(Get-Process -Id $PID).Path
foreach($case in @(
    @{Args=@('channel-read','-Help');Exit=0},
    @{Args=@('channel-read','-Help','-Auto');Exit=1},
    @{Args=@('channel-read','-Help','-GrantEventLogReaders');Exit=1},
    @{Args=@('channel-read','-Help','-Role','DomainController');Exit=1},
    @{Args=@('help','-ChannelReadName','Security');Exit=1}
)){
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try{$text=&$engine -NoProfile -File (Join-Path $script:ScriptRoot 'WELA.ps1') @($case.Args) 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
    Assert ($code -eq $case.Exit) ('CLI boundary '+($case.Args -join ' ')+': '+($text|Out-String))
}
$global:LASTEXITCODE=0
Write-Host "Channel read fixtures passed: $script:passed"
