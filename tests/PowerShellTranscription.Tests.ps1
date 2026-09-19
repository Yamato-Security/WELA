$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/PowerShellTranscription.ps1')
$script:checks = 0
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
function Assert-Throws([scriptblock]$Action, [string]$Message) { $thrown = $false; try { & $Action } catch { $thrown = $true }; Assert $thrown $Message }
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-transcription-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$originalCapability = ${function:Get-WelaTranscriptCapability}
function New-Value($Value = $null, [string]$Type = '') {
    [pscustomobject]@{ KeyExists = [bool]$Type; ValueExists = [bool]$Type; Value = $Value; Type = $(if ($Type) { $Type } else { $null }) }
}
function Reset-Mocks {
    $script:machine = @{ EnableTranscripting = New-Value; OutputDirectory = New-Value; EnableInvocationHeader = New-Value }
    $script:user = @{ EnableTranscripting = New-Value; OutputDirectory = New-Value; EnableInvocationHeader = New-Value }
    $script:writes = @(); $script:reads = 0; $script:destinationReads = 0; $script:registryFailure = $false
    $script:viewMismatch = $false; $script:destinationFailure = $false; $script:destinationRisk = $false
    $script:race = $false; $script:drift = $false; $script:writeFailure = ''; $script:locationReadbackFailure = $false
    $script:headerDrift = $false; $script:onPrompt = $null; $script:version = '5.1.26100.0'
}
function Get-WelaTranscriptCapability {
    [pscustomobject]@{ Status = 'Supported'; TargetEngine = 'Windows PowerShell 5.1'; Views = @('Registry64', 'Registry32'); Diagnostic = 'Mock engine' }
}
function Get-WelaTranscriptRegistryValue {
    param($Hive = 'LocalMachine', $View, $SubKey, $Name)
    $script:reads++
    if ($script:registryFailure) { throw 'Registry read denied' }
    if ($Name -eq 'PowerShellVersion') { return New-Value $script:version String }
    $values = if ($Hive -eq 'CurrentUser') { $script:user } else { $script:machine }
    $result = $values[$Name] | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    if ($script:viewMismatch -and $View -eq 'Registry32' -and $Name -eq 'EnableTranscripting' -and $Hive -eq 'LocalMachine') { $result = New-Value 2 DWord }
    if ($script:drift -and $script:destinationReads -ge 3 -and $Name -eq 'EnableTranscripting' -and $Hive -eq 'LocalMachine') { $result = New-Value 0 DWord }
    if ($script:headerDrift -and $script:writes.Count -gt 0 -and $Name -eq 'EnableInvocationHeader' -and $Hive -eq 'LocalMachine') { $result = New-Value 0 DWord }
    return $result
}
function Get-WelaTranscriptDestination {
    param($Path)
    $script:destinationReads++
    $sddl = if ($script:race -and $script:destinationReads -gt 1) { 'changed' } else { 'private-directory-acl' }
    [pscustomobject]@{ RequestedPath = $Path; Path = $Path; Status = $(if ($script:destinationRisk) { 'Blocked' } elseif ($script:destinationFailure) { 'Unknown' } else { 'Observed' });
        ConfigureAllowed = -not ($script:destinationFailure -or $script:destinationRisk); Acl = @{ Sddl = $sddl };
        ShareAuthorization = $(if ($Path.StartsWith('\\')) { 'Unknown' } else { 'NotApplicable' }); WriterAuthorization = 'Unknown'; CollectorAuthorization = 'Unknown';
        Diagnostic = 'Mock directory; effective access remains unverified' }
}
function Set-WelaTranscriptRegistryValue {
    param($Name, $Value, $Type)
    if ($Name -eq $script:writeFailure) { throw "Mock $Name write denied" }
    $script:writes += $Name
    if ($Name -eq 'OutputDirectory' -and $script:locationReadbackFailure) { return }
    $script:machine[$Name] = New-Value $Value $Type
    foreach ($entry in $script:machine.Values) { $entry.KeyExists = $true }
}
function Read-Host { param($Prompt) if ($script:onPrompt) { & $script:onPrompt }; return 'y' }
function Configure([switch]$DryRun, [switch]$Prompt, [string]$Path = 'C:\ReviewedTranscripts') {
    Invoke-WelaTranscriptCommand -Action Configure -OutputDirectory $Path -Auto:(-not $Prompt) -DryRun:$DryRun `
        -BackupPath (Join-Path $root ([guid]::NewGuid().ToString('N')))
}
try {
    foreach ($path in @('C:\ReviewedTranscripts', '\\collector.example.test\Transcripts', '\\collector\Transcripts\Windows')) {
        Test-WelaTranscriptDirectoryPath $path; Assert $true "absolute path accepted: $path"
    }
    foreach ($path in @('', '.\transcripts', 'C:relative', 'C:\..\transcripts', '%TEMP%\transcripts', 'C:\foo*', '\\?\C:\transcripts', '\\.\pipe\name', 'C:\transcripts:stream', 'https://collector/logs')) {
        Assert-Throws { Test-WelaTranscriptDirectoryPath $path } "unsafe/ambiguous path rejected: $path"
    }
    Reset-Mocks
    Assert-Throws { Invoke-WelaTranscriptCommand -Action Plan } 'plan requires an explicit reviewed path'
    Assert-Throws { Invoke-WelaTranscriptCommand -Action Configure -Auto } 'configure cannot fall back to per-user Documents'
    Assert-Throws { Invoke-WelaTranscriptCommand -Action Audit -DryRun } 'dry-run only applies to configure'
    $report = Invoke-WelaTranscriptCommand -Action Audit
    Assert ($report.Results[0].Status -eq 'Unknown' -and $script:writes.Count -eq 0) 'missing output policy remains unknown during audit'
    $report = Invoke-WelaTranscriptCommand -Action Plan -OutputDirectory 'C:\ReviewedTranscripts'
    Assert ($report.Results[0].Status -eq 'ChangeRequired' -and $report.Benchmark -like '*Level 2 only*') 'opt-in plan explicitly identifies Level 2'
    Assert ($report.Telemetry.SigmaEvtxCredit -eq 0 -and $report.Telemetry.EventIds.Count -eq 0 -and $report.VerificationScope -like '*PowerShell 7*unverified*') 'transcript text gives no EVTX or PowerShell 7 session credit'
    Reset-Mocks; $report = Configure -DryRun
    Assert ($report.DryRun -and $report.Skipped -eq 1 -and $script:writes.Count -eq 0 -and -not (Test-Path $report.BackupPath)) 'dry-run makes no registry or recovery-directory writes'
    Reset-Mocks; $report = Configure
    Assert ($report.ExitCode -eq 0 -and $report.Results[0].Status -eq 'Applied') 'new policy applies and verifies'
    Assert (($script:writes -join ',') -eq 'OutputDirectory,EnableTranscripting') 'reviewed location is written and verified before enabling transcription'
    Assert ($script:machine.EnableTranscripting.Type -eq 'DWord' -and $script:machine.EnableTranscripting.Value -eq 1 -and $script:machine.OutputDirectory.Type -eq 'String') 'exact canonical registry types'
    Assert (-not $script:machine.EnableInvocationHeader.ValueExists) 'absent invocation-header preference remains absent even when key is created'
    $journal = Get-Content (Join-Path $report.BackupPath 'before.jsonl') -Raw | ConvertFrom-Json
    Assert ($journal.Before.Policy.Count -eq 2 -and -not $journal.Before.Policy[0].Machine.OutputDirectory.ValueExists -and $journal.Before.Destination.Acl.Sddl -eq 'private-directory-acl') 'journal records both views and original destination security observations'
    $script:destinationReads = 0; $again = Configure
    Assert ($again.Results[0].Status -eq 'AlreadyCompliant' -and $script:writes.Count -eq 2) 'repeat configuration is idempotent'
    Reset-Mocks; $script:machine.EnableInvocationHeader = New-Value 1 DWord
    $script:user.EnableTranscripting = New-Value 0 DWord
    $report = Configure
    Assert ($report.ExitCode -eq 0 -and $script:machine.EnableInvocationHeader.Value -eq 1 -and $script:user.EnableTranscripting.Value -eq 0) 'existing header and user policy are preserved'
    Reset-Mocks; $script:machine.EnableTranscripting = New-Value '1' String
    $script:machine.OutputDirectory = New-Value 'C:\ReviewedTranscripts' ExpandString
    $report = Configure
    Assert ($report.ExitCode -eq 0 -and $script:machine.EnableTranscripting.Type -eq 'DWord' -and $script:machine.OutputDirectory.Type -eq 'String') 'numeric strings and ExpandString are repaired by explicit configure'
    Reset-Mocks; $script:viewMismatch = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'shared-view mismatch fails closed'
    Reset-Mocks; $script:registryFailure = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'registry read failure cannot be mistaken for absent configuration'
    foreach ($risk in @('destinationFailure', 'destinationRisk')) {
        Reset-Mocks; Set-Variable -Scope Script -Name $risk -Value $true; $report = Configure
        Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'unreadable or known-unsafe destination blocks writes'
    }
    Reset-Mocks; $report = Configure -Path '\\collector\Transcripts'
    Assert ($report.ExitCode -eq 0 -and $report.Results[0].After.Destination.ShareAuthorization -eq 'Unknown' -and $report.Results[0].After.Destination.WriterAuthorization -eq 'Unknown') 'explicit UNC configure retains unknown share and writer authorization'
    Reset-Mocks; $script:race = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0 -and $report.Results[0].Diagnostic -like '*changed after*') 'destination ACL race fails before writing'
    Reset-Mocks; $script:locationReadbackFailure = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and ($script:writes -join ',') -eq 'OutputDirectory') 'bad location readback prevents enablement'
    Reset-Mocks; $script:writeFailure = 'EnableTranscripting'; $report = Configure
    Assert ($report.ExitCode -eq 1 -and (Test-Path (Join-Path $report.BackupPath 'before.jsonl')) -and $script:machine.OutputDirectory.ValueExists) 'partial write failure retains accurate recovery evidence'
    Reset-Mocks; $script:drift = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and $report.Results[0].Status -eq 'Overridden') 'final policy drift is overridden'
    Reset-Mocks; $script:headerDrift = $true; $report = Configure
    Assert ($report.ExitCode -eq 1 -and $report.Results[0].Diagnostic -like '*Invocation-header*') 'unrequested header change fails verification'
    Reset-Mocks
    $script:onPrompt = { Get-ChildItem $root -Directory | Remove-Item -Recurse -Force }
    $report = Configure -Prompt
    Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) 'journal write failure prevents policy changes'
    Reset-Mocks
    $path = Join-Path $root 'report.json'
    $null = Invoke-WelaTranscriptCommand -Action Plan -OutputDirectory 'C:\ReviewedTranscripts' -ResultsPath $path
    $export = Get-Content $path -Raw | ConvertFrom-Json
    Assert ($export.Telemetry.SigmaEvtxCredit -eq 0 -and $export.Results[0].Before.TranscriptGeneration -eq 'Unverified') 'JSON retains generation and coverage limits'
    # Test actual capability classification through stubbed OS filesystem/registry reads.
    Set-Item function:Get-WelaTranscriptCapability $originalCapability
    $savedOs = $env:OS; $savedWindir = $env:windir
    try {
        $env:OS = 'Windows_NT'; $env:windir = $root
        function Test-Path { param($LiteralPath, $PathType, $ErrorAction) return $true }
        $script:version = '5.1.26100.0'; Assert ((Get-WelaTranscriptCapability).Status -eq 'Supported') '5.1 engine recognized from PowerShell 7 host'
        $script:version = '4.0'; Assert ((Get-WelaTranscriptCapability).Status -eq 'Unknown') 'older engine is not assumed to support the target policy'
    } finally { $env:OS = $savedOs; $env:windir = $savedWindir }
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) 'combined WELA entry point parses'
    Write-Host "Passed $script:checks transcription mock assertions. No Windows policy, ACL or share was changed."
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
