$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
$script:checks=0
function Assert($Condition,[string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
function Throws([scriptblock]$Code,[string]$Message) { $caught=$false; try { & $Code | Out-Null } catch { $caught=$true }; Assert $caught $Message }
$context=[pscustomobject]@{Status='Observed';RolesStatus='Observed';ProductType=3;DomainRole=2;DomainJoined=$false;Build=20348;UBR=4000;Edition='ServerDatacenter';Domain='WORKGROUP';Architecture='64-bit';ProcessorArchitecture=9;InstalledRoles=@('Web-Server')}
$script:state=[pscustomobject]@{capturedAtUtc=[DateTime]::UtcNow.ToString('o');context=[pscustomobject]@{computer='test-host';role='MemberServer';build=20348;patch='20348.4000';domainJoined=$false;installedRoles=@('Web-Server')};hostObservation=$context;auditPolicies=@{'0cce922b-69ae-11d9-bed3-505054503030'=1};auditPrecedence=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=1};commandLineCapture=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=1};securityChannelEnabled=$true}
$script:process=[pscustomobject]@{ProcessId=123;ParentProcessId=456;Executable='C:\Windows\System32\cmd.exe';Arguments='/d /c echo WELA_PROBE_0123456789abcdef0123456789abcdef';Marker='WELA_PROBE_0123456789abcdef0123456789abcdef';StartedUtc=[DateTime]::UtcNow.AddSeconds(-1).ToString('o');ExitCode=0}
$time=[DateTime]::UtcNow.ToString('o')
$script:xml=@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4688</EventID><Version>2</Version><EventRecordID>100</EventRecordID><Channel>Security</Channel><Computer>test-host</Computer><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="$time"/></System><EventData><Data Name="NewProcessId">0x7b</Data><Data Name="ProcessId">0x1c8</Data><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">"C:\Windows\System32\cmd.exe" /d /c echo WELA_PROBE_0123456789abcdef0123456789abcdef</Data></EventData></Event>
"@
Assert (Test-WelaProbeEvent $xml $process $state ([DateTime]::UtcNow)) 'complete native-shaped event matches'
foreach ($replacement in @(@('0x7b','0x7c'),@('0x1c8','0x1c9'),@('WELA_PROBE_0123456789abcdef0123456789abcdef','WELA_PROBE_wrong'),@('<EventID>4688</EventID>','<EventID>4689</EventID>'),@('<Version>2</Version>','<Version>1</Version>'),@('test-host','other-host'),@('0x8020000000000000','0x8010000000000000'),@('<Channel>Security</Channel>','<Channel>System</Channel>'),@('<EventRecordID>100</EventRecordID>','<EventRecordID>0</EventRecordID>'),@('Name="Microsoft-Windows-Security-Auditing"','Name="Other"'),@('<Data Name="ProcessId">0x1c8</Data>','<Data Name="ProcessId">0x1c8</Data><Data Name="ProcessId">0x1c8</Data>'))) {
    Assert (-not (Test-WelaProbeEvent ($xml.Replace($replacement[0],$replacement[1])) $process $state ([DateTime]::UtcNow))) "mismatch rejected: $($replacement[0])"
}
Assert (-not (Test-WelaProbeEvent ('<!DOCTYPE Event [<!ENTITY xx SYSTEM "file:///etc/passwd">]>'+$xml) $process $state ([DateTime]::UtcNow))) 'external entity rejected'
Assert (-not (Test-WelaProbeEvent $xml $process $state ([DateTime]::UtcNow.AddDays(-1)))) 'future relative event rejected'
$prior=$process.StartedUtc; $process.StartedUtc=[DateTime]::UtcNow.AddDays(1).ToString('o')
Assert (-not (Test-WelaProbeEvent $xml $process $state ([DateTime]::UtcNow))) 'event predating probe rejected'; $process.StartedUtc=$prior
Assert-WelaProbePrerequisites $state
foreach ($field in @('role','patch','domainJoined','installedRoles')) {
    $prior=$state.context.$field
    switch ($field) {
        'role' { $state.context.role='DomainController' }
        'patch' { $state.context.patch='20348.9999' }
        'domainJoined' { $state.context.domainJoined=$true }
        'installedRoles' { $state.context.installedRoles=@('ADCS-Cert-Authority') }
    }
    Throws { Assert-WelaProbePrerequisites $state } "contradictory native context $field rejected"
    $state.context.$field=$prior
}
$state.context.role='ADCS'
Throws { Assert-WelaProbePrerequisites $state } 'CA label without its installed role cannot establish a CA probe context'
$state.context.role='MemberServer'
foreach ($mask in @(0,2,$null,'1')) { $state.auditPolicies['0cce922b-69ae-11d9-bed3-505054503030']=$mask; Throws { Assert-WelaProbePrerequisites $state } 'missing success bit or unknown mask rejected' }
$state.auditPolicies['0cce922b-69ae-11d9-bed3-505054503030']=1
$state.auditPrecedence.Type='String'; Throws { Assert-WelaProbePrerequisites $state } 'string masquerading as DWORD rejected'; $state.auditPrecedence.Type='DWord'
$state.commandLineCapture.Value=0; Throws { Assert-WelaProbePrerequisites $state } 'missing command line capture rejected'; $state.commandLineCapture.Value=1
$state.securityChannelEnabled=$false; Throws { Assert-WelaProbePrerequisites $state } 'disabled Security rejected'; $state.securityChannelEnabled=$true
$state.hostObservation.RolesStatus='Unknown'; Throws { Assert-WelaProbePrerequisites $state } 'unknown roles rejected'; $state.hostObservation.RolesStatus='Observed'
$script:launched=0; $script:reads=0; $script:scenario='success'
function Get-WelaProbeState { $script:reads++; if ($scenario -eq 'denied') { throw 'denied' }; if ($scenario -eq 'drift' -and $reads -gt 2) { $script:state.auditPolicies['0cce922b-69ae-11d9-bed3-505054503030']=3 }; return $script:state }
function Start-WelaProbeProcess { $script:launched++; return $script:process }
function Read-WelaProbeEvents {
    if ($scenario -eq 'query-denied') { throw 'Security access denied' }
    if ($scenario -eq 'ambiguous') { return [pscustomobject]@{Xml=@($script:xml,$script:xml);Capped=$false} }
    if ($scenario -eq 'timeout') { return [pscustomobject]@{Xml=@();Capped=$false} }
    [pscustomobject]@{Xml=@($script:xml);Capped=($scenario -eq 'cap')}
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-native-probe-tests-'+[guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $root
try {
    # PowerShell's current location is independent of the process working directory.
    $relativeName='relative-probe-'+[guid]::NewGuid().ToString('N')
    Push-Location $root
    try {
        $relative=Invoke-WelaNativeValidation -Action Run -OutputPath $relativeName -TimeoutSeconds 1
        Assert ($relative.ExitCode -eq 0 -and $relative.OutputPath -eq (Join-Path $root $relativeName)) 'relative probe destination resolves against the PowerShell location'
        Assert (Test-Path -LiteralPath (Join-Path $root "$relativeName/manifest.json")) 'relative probe manifest is written in the requested location'
    } finally { Pop-Location }
    $script:launched=0
    $plan=Invoke-WelaNativeValidation
    Assert ($plan.Status -eq 'PrerequisitesObserved' -and $launched -eq 0 -and $plan.Artifacts.Count -eq 0) 'default Plan observes without launching or exporting'
    Throws { Invoke-WelaNativeValidation -Action Run } 'Run needs new destination'
    Throws { Invoke-WelaNativeValidation -OutputPath (Join-Path $root 'unused') } 'Plan rejects output destination'
    foreach ($case in @('success','cap','ambiguous','timeout','denied','query-denied','drift')) {
        $script:scenario=$case; $script:reads=0; $script:state.auditPolicies['0cce922b-69ae-11d9-bed3-505054503030']=1
        $destination=Join-Path $root $case
        $result=Invoke-WelaNativeValidation -Action Run -OutputPath $destination -TimeoutSeconds 1
        Assert (Test-Path (Join-Path $destination 'manifest.json')) 'partial and completed manifests are retained'
        Assert ($result.ReadyRuleCredit -eq 0 -and $result.PolicyChanges -eq 0) 'no policy changes or readiness credit'
        if ($case -eq 'success') {
            Assert ($result.Status -eq 'NativeEventObserved' -and $result.ExitCode -eq 0 -and $result.Artifacts.Count -eq 4) 'exact native probe artifact set collected'
            foreach ($artifact in $result.Artifacts) { Assert ((Get-FileHash -LiteralPath (Join-Path $destination $artifact.path)).Hash.ToLowerInvariant() -ceq $artifact.sha256) 'artifact hashes verify' }
        } else { Assert ($result.Status -eq 'Unverified' -and $result.ExitCode -eq 1 -and $result.Diagnostic) "failure cannot claim telemetry: $case" }
        Throws { Invoke-WelaNativeValidation -Action Run -OutputPath $destination } 'existing output directory refused'
    }
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
# The public dispatcher must reject probe options before it reaches unrelated mutation paths.
foreach ($args in @(@('configure','-Profile','wela','-ProbeAction','Plan'),@('native-validation','-Auto'),@('native-validation','-Role','Client','-Build','26100'))) {
    $saved=$ErrorActionPreference; $ErrorActionPreference='Continue'
    try { $output=& (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $repo 'WELA.ps1') @args 2>&1; $code=$LASTEXITCODE } finally { $ErrorActionPreference=$saved }
    Assert ($code -ne 0 -and ($output -join ' ') -match 'No command') 'public scope guard fails before execution'
}
$global:LASTEXITCODE=0
Write-Host "Passed $script:checks native-validation assertions. Fixtures are synthetic; no native telemetry is claimed."
