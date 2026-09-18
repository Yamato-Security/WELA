# Safe fixtures only: never invokes real wevtutil or changes a Windows channel.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/EventLogSettings.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/EventLogConfiguration.ps1')
$script:ScriptRoot = $repo
$script:assertions = 0
$script:cleanup = New-Object 'System.Collections.Generic.List[string]'
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
function New-TestContext([switch]$DryRun, [switch]$Prompt) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-eventlog-' + [guid]::NewGuid().ToString('N'))
    if (-not $DryRun) { $script:cleanup.Add($path) }
    New-WelaConfigurationContext -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath $path
}
function New-State([string]$Log, [long]$Bytes = 1048576, [string]$Mode = 'Retain') {
    [pscustomobject]@{ Log = $Log; ReadStatus = 'Available'; MaximumSizeInBytes = $Bytes; LogMode = $Mode; FileSize = 100; IsEnabled = $true; Diagnostic = '' }
}
$data = Import-WelaEventLogProfiles
$wela = Get-WelaEventLogProfile
Assert ($data.profiles.Count -eq 4 -and $wela.controls.Count -eq 28) 'Catalog includes four separate source/collector choices and all WELA channels'
foreach ($log in @('Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-AppLocker/Packaged app-Deployment', 'Microsoft-Windows-AppLocker/Packaged app-Execution', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall')) {
    Assert (($wela.controls | Where-Object log -eq $log).minimumBytes -eq 268435456) "$log uses the same 256 MiB audit/apply threshold"
}
Assert (($wela.controls | Where-Object log -eq 'Setup').minimumBytes -eq 33554432) 'WELA includes Setup at CIS 32 MiB minimum'
Assert (($wela.controls | Where-Object log -eq 'Security').minimumBytes -eq 1073741824) 'Default preserves WELA configure 1024 MiB Security choice'
Assert (((Get-WelaEventLogProfile 'asd-source-2021-10').controls | Where-Object log -eq 'Security').minimumBytes -eq 2147483648) 'ASD Security size remains a 64-bit 2048 MiB byte count'
$collector = Get-WelaEventLogProfile 'asd-collector-archive-2021-10'
Assert ($collector.kind -eq 'collector' -and $collector.controls.Count -eq 1 -and $collector.controls[0].log -eq 'ForwardedEvents' -and $collector.controls[0].mode -eq 'AutoBackup') 'Collector archive does not leak into source logs'
Assert ((ConvertTo-WelaEventLogBytes 1048577) -eq 1114112) 'Fractional 64 KiB request rounds upward, never below the requested minimum'
Assert ((ConvertTo-WelaEventLogBytes 2147483648) -eq 2147483648) 'Aligned 2 GiB remains exact without integer overflow'
$caught = $false; try { Get-WelaEventLogProfile 'unrecognized' } catch { $caught = $true }
Assert $caught 'Unknown profile fails rather than silently using default values'

# Exercise the real reader inside its module, safely replacing only Get-WinEvent.
$module = Get-Module EventLogSettings
& $module {
    $script:case = 'normal'
    function script:Get-WinEvent {
        param($ListLog, $ErrorAction)
        if ($script:case -eq 'denied') { throw [UnauthorizedAccessException]::new('fixture access denied') }
        if ($script:case -eq 'missing') { throw [Management.Automation.ErrorRecord]::new([Exception]::new('fixture missing'), 'NoMatchingLogsFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $ListLog) }
        [pscustomobject]@{ MaximumSizeInBytes = $(if ($script:case -eq 'null') { $null } else { 1048577 }); LogMode = 'Circular'; FileSize = 42; IsEnabled = $false }
    }
}
$observed = Get-WelaEventLogState 'Fixture'
Assert ($observed.ReadStatus -eq 'Available' -and $observed.MaximumSizeInBytes -eq 1048577 -and -not $observed.IsEnabled) 'Reader preserves exact bytes and does not claim a disabled channel is enabled'
& $module { $script:case = 'denied' }
Assert ((Get-WelaEventLogState 'Fixture').ReadStatus -eq 'Unreadable') 'Access denial is not classified as a missing channel'
& $module { $script:case = 'missing' }
Assert ((Get-WelaEventLogState 'Fixture').ReadStatus -eq 'Missing') 'Known missing-channel error remains explicit'
& $module { $script:case = 'null' }
Assert ((Get-WelaEventLogState 'Fixture').ReadStatus -eq 'Unreadable') 'Null maximum does not become a static/default size'
& $module { Remove-Item Function:script:Get-WinEvent }

# The audit compares bytes, not rounded display values, and never invents duration.
$audit = @(Get-WelaEventLogAudit -Profile 'cis-v4-source' -Read { param($log) New-State $log 33554431 })
Assert (($audit | Where-Object Log -eq 'Setup').SizeStatus -eq 'BelowMinimum') 'One byte under the minimum is not rounded to compliant'
Assert (@($audit | Where-Object RetentionDays -ne 'Unknown').Count -eq 0) 'Buffer size is not converted into an unmeasured retention age'
$audit = @(Get-WelaEventLogAudit -Profile 'cis-v4-source' -Read { param($log) [pscustomobject]@{ ReadStatus = 'Unreadable'; MaximumSizeInBytes = $null; LogMode = $null; IsEnabled = $null; Diagnostic = 'denied' } })
Assert ($audit[0].SizeStatus -eq 'Unknown' -and $null -eq $audit[0].CurrentMaximumBytes -and $audit[0].Diagnostic -eq 'denied') 'Unreadable audit rows retain unknown state and failure evidence'

# Script-scoped fixtures override exported commands at the same scope as helpers.
function Reset-Fixture([string]$Profile = 'cis-v4-source', [long]$Bytes = 1048576, [string]$Mode = 'Retain') {
    $script:states = @{}; $script:writes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($control in (Get-WelaEventLogProfile $Profile).controls) { $script:states[$control.log] = New-State $control.log $Bytes $Mode }
    $script:failWrite = $false; $script:falseSuccess = $false; $script:growOnPrompt = $false; $script:unreadableOnPrompt = $false
}
function Get-WelaEventLogState {
    param($Log)
    if (-not $script:states.ContainsKey($Log)) { return [pscustomobject]@{ ReadStatus = 'Missing'; Diagnostic = 'Fixture channel absent' } }
    # Return a snapshot, not the mutable fixture reference, so journals are realistic.
    return $script:states[$Log].PSObject.Copy()
}
function Read-Host {
    param($Prompt)
    if ($script:growOnPrompt) { foreach ($key in @($script:states.Keys)) { $script:states[$key].MaximumSizeInBytes = 4294967296 } }
    if ($script:unreadableOnPrompt) { foreach ($key in @($script:states.Keys)) { $script:states[$key].ReadStatus = 'Unreadable' } }
    return 'Y'
}
function Invoke-WelaNative {
    param($FilePath, $Arguments)
    Assert ($FilePath -eq 'wevtutil.exe' -and $Arguments[0] -eq 'sl') 'Only the intended native channel-setting command is issued'
    Assert (Test-Path -LiteralPath (Join-Path $script:activeContext.BackupPath 'before.jsonl')) 'Pre-change journal is durable before each native write'
    $script:writes.Add(@($Arguments))
    if ($script:failWrite) { throw 'fixture native nonzero exit' }
    if (-not $script:falseSuccess) {
        $current = $script:states[$Arguments[1]]
        foreach ($argument in $Arguments) {
            if ($argument -like '/ms:*') { $current.MaximumSizeInBytes = [long]$argument.Substring(4) }
        }
        if ($Arguments -contains '/ab:true' -and $Arguments -contains '/rt:true') { $current.LogMode = 'AutoBackup' }
        if ($Arguments -contains '/ab:false' -and $Arguments -contains '/rt:false') { $current.LogMode = 'Circular' }
    }
    [pscustomobject]@{ Diagnostic = 'Safe fixture write' }
}
try {
    Reset-Fixture 'wela-source-2.2.0'
    $script:activeContext = New-TestContext
    Set-WelaEventLogProfileControls -Context $script:activeContext
    $audit = @(Get-WelaEventLogAudit -Read { param($log) Get-WelaEventLogState $log })
    Assert (@($audit | Where-Object SizeStatus -ne 'Compliant').Count -eq 0) 'Successful default configuration leaves no default-profile size warning'
    Assert (@($script:writes | Where-Object { ($_ -join ' ') -match '/[ar][bt]:' }).Count -eq 0) 'Ordinary configuration never changes retention modes'
    Assert ($script:states.Security.LogMode -eq 'Retain') 'Existing retain policy is preserved without explicit mode opt-in'
    $result = Complete-WelaConfiguration -Context $script:activeContext
    Assert ($result.ExitCode -eq 0) 'All default sizes pass final verification'

    Reset-Fixture 'cis-v4-source' 4294967296
    $script:activeContext = New-TestContext
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'cis-v4-source'
    Assert ($script:writes.Count -eq 0 -and $script:activeContext.Checks.Count -eq 4) 'Minimum mode preserves larger buffers and still registers final verification'
    $script:states.Setup.MaximumSizeInBytes = 1048576
    $result = Complete-WelaConfiguration -Context $script:activeContext
    Assert ($result.ExitCode -eq 1 -and @($result.Results | Where-Object Status -eq 'Overridden').Count -eq 1) 'Final drift is not reported as success'

    Reset-Fixture 'cis-v4-source' 4294967296
    $script:activeContext = New-TestContext
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'cis-v4-source' -ResizeLogs -ApplyLogMode
    Assert ($script:states.Setup.MaximumSizeInBytes -eq 33554432 -and $script:states.Setup.LogMode -eq 'Circular') 'Explicit resize and mode flags allow reviewed shrink/circular choices'
    Assert ($script:writes[0] -contains '/rt:false' -and $script:writes[0] -contains '/ab:false') 'Source circular uses both retention and autobackup false'
    $firstJournal = (Get-Content -LiteralPath (Join-Path $script:activeContext.BackupPath 'before.jsonl'))[0] | ConvertFrom-Json
    Assert ($firstJournal.Before.MaximumSizeInBytes -eq 4294967296 -and $firstJournal.Before.LogMode -eq 'Retain') 'Journal records exact previous bytes and mode for manual recovery'

    Reset-Fixture 'asd-collector-archive-2021-10'
    $script:activeContext = New-TestContext
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'asd-collector-archive-2021-10' -ApplyLogMode
    Assert ($script:writes.Count -eq 1 -and $script:writes[0] -contains '/rt:true' -and $script:writes[0] -contains '/ab:true') 'Collector archive explicitly applies retention plus autobackup'
    Assert ($script:states.ForwardedEvents.MaximumSizeInBytes -eq 2147483648 -and $script:states.ForwardedEvents.LogMode -eq 'AutoBackup') 'Collector exact 2 GiB and mode are read back'

    Reset-Fixture
    $script:activeContext = New-TestContext -DryRun
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'cis-v4-source' -ResizeLogs -ApplyLogMode
    Assert ($script:writes.Count -eq 0 -and -not (Test-Path -LiteralPath $script:activeContext.BackupPath)) 'Dry run performs no native writes and creates no journal'

    Reset-Fixture
    $script:activeContext = New-TestContext -Prompt; $script:growOnPrompt = $true
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'cis-v4-source'
    Assert ($script:writes.Count -eq 0 -and $script:states.Setup.MaximumSizeInBytes -eq 4294967296) 'Fresh prewrite state preserves buffer enlarged during operator confirmation'

    Reset-Fixture
    $script:activeContext = New-TestContext -Prompt; $script:unreadableOnPrompt = $true
    Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'cis-v4-source'
    Assert ($script:writes.Count -eq 0 -and $script:activeContext.Results[0].Status -eq 'Failed') 'Unknown fresh state refuses writes'

    foreach ($case in @('missing', 'denied', 'native', 'false-success', 'journal')) {
        Reset-Fixture 'asd-collector-archive-2021-10'
        $script:activeContext = New-TestContext
        if ($case -eq 'missing') { $script:states.Clear() }
        if ($case -eq 'denied') { $script:states.ForwardedEvents.ReadStatus = 'Unreadable'; $script:states.ForwardedEvents.Diagnostic = 'access denied' }
        if ($case -eq 'native') { $script:failWrite = $true }
        if ($case -eq 'false-success') { $script:falseSuccess = $true }
        if ($case -eq 'journal') { $script:activeContext.BackupPath = Join-Path $script:activeContext.BackupPath 'absent-parent' }
        Set-WelaEventLogProfileControls -Context $script:activeContext -Profile 'asd-collector-archive-2021-10' -ApplyLogMode
        $result = Complete-WelaConfiguration -Context $script:activeContext
        Assert ($result.ExitCode -eq 1 -and $result.Results[0].Status -eq 'Failed') "$case is surfaced as failed configuration"
        if ($case -in @('missing', 'denied', 'journal')) { Assert ($script:writes.Count -eq 0) "$case prevents the native write" }
    }

    # Parse actual production entry points; same profile is selected in both paths.
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) 'WELA remains parseable'
    $configure = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConfigureAuditSettings' }, $true).Extent.Text
    Assert ($configure.Contains("Set-WelaEventLogProfileControls -Context `$context -Profile 'wela-source-2.2.0'") -and $configure -notmatch '-Property MaximumSizeInBytes') 'Default configure consumes the shared model rather than another hardcoded size list'
    $release = Get-Content (Join-Path $repo '.github/workflows/release.yml') -Raw
    foreach ($directory in @('config', 'scripts', 'modules')) { Assert ($release -match "Copy-Item -Recurse -Path ./($directory) ") "Release packages the new $directory dependency" }

    Reset-Fixture
    $output = Join-Path ([IO.Path]::GetTempPath()) ('wela-eventlog-results-' + [guid]::NewGuid().ToString('N') + '.json')
    $script:cleanup.Add($output)
    $result = Invoke-WelaEventLogConfiguration -Profile 'cis-v4-source' -DryRun -ResultsPath $output
    $saved = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Assert ($result.ExitCode -eq 0 -and $saved.Scope -eq 'event-log-size-and-mode-only' -and $saved.LogProfile -eq 'cis-v4-source') 'Dedicated configuration exports its narrow scope and selected log profile'
    Assert ($saved.Results.Count -eq 4 -and $saved.Results[0].SourceIds -contains 'cis-v4' -and $saved.RetentionDays -eq 'Unknown') 'Structured result preserves source provenance and unknown retention duration'

    # Execute only actual option guards, then the dispatcher with harmless stubs.
    $guards = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match 'No command was run|selects advanced audit policy only|LogProfile is supported only' })
    $guardBlock = [scriptblock]::Create(($guards | ForEach-Object { $_.Extent.Text }) -join "`n")
    $Cmd = 'configure'; $Profile = 'wela-2.2.0'; $LogProfile = 'cis-v4-source'; $ResizeLogs = $false; $ApplyLogMode = $false; $DryRun = $true
    $caught = $false; try { & $guardBlock } catch { $caught = $true }
    Assert $caught 'Advanced audit profile configure rejects log options instead of silently ignoring them'
    $Cmd = 'configure-eventlogs'; $Profile = 'wela-2.2.0'
    $caught = $false; try { & $guardBlock } catch { $caught = $true }
    Assert $caught 'Event-log command rejects the advanced -Profile option'
    $Profile = $null; $ResizeLogs = $true; $ApplyLogMode = $true
    & $guardBlock
    Assert $true 'Dedicated event-log dry run accepts explicit size/mode options'
    $Help = $false; $Baseline = $null; $Auto = $true; $BackupPath = $null; $ResultsPath = $null
    function TestWindows { return $true }
    function TestAdministrator { return $true }
    function Invoke-WelaEventLogConfiguration {
        param($Profile, [switch]$Auto, [switch]$DryRun, [switch]$ResizeLogs, [switch]$ApplyLogMode, $BackupPath, $ResultsPath)
        $script:dispatched = @{ Profile = $Profile; DryRun = [bool]$DryRun; ResizeLogs = [bool]$ResizeLogs; ApplyLogMode = [bool]$ApplyLogMode }
        [pscustomobject]@{ ExitCode = 0 }
    }
    $dispatch = $ast.Find({ param($n) $n -is [Management.Automation.Language.SwitchStatementAst] -and $n.Condition.Extent.Text -eq '$Cmd.ToLower()' }, $false)
    & ([scriptblock]::Create($dispatch.Extent.Text)) | Out-Null
    Assert ($script:dispatched.Profile -eq 'cis-v4-source' -and $script:dispatched.DryRun -and $script:dispatched.ResizeLogs -and $script:dispatched.ApplyLogMode) 'CLI passes every explicit event-log choice to the dedicated runner'
} finally {
    foreach ($path in $script:cleanup) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
}
$global:LASTEXITCODE = 0
Write-Host "PASS: $script:assertions event-log assertions; no machine policies changed."
