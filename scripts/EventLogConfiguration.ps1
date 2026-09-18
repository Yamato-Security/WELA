# Uses the same configuration runner as other native WELA settings. No closures.
function Set-WelaEventLogProfileControls {
    param($Context, [string]$Profile = 'wela-source-2.2.0', [switch]$ResizeLogs, [switch]$ApplyLogMode)
    $selected = Get-WelaEventLogProfile -Id $Profile
    foreach ($control in $selected.controls) {
        $state = @{
            Log = $control.log; Bytes = (ConvertTo-WelaEventLogBytes $control.minimumBytes)
            ExactSize = [bool]$ResizeLogs; Mode = $(if ($ApplyLogMode) { $control.mode } else { $null })
            Context = $Context; BeforeWrite = $null
        }
        $read = {
            param($state)
            $observed = Get-WelaEventLogState -Log $state.Log
            if ($observed.ReadStatus -ne 'Available') { throw "$($observed.ReadStatus) channel '$($state.Log)': $($observed.Diagnostic)" }
            return $observed
        }
        $test = {
            param($value, $state)
            $sizeOK = if ($state.ExactSize) { $value.MaximumSizeInBytes -eq $state.Bytes } else { $value.MaximumSizeInBytes -ge $state.Bytes }
            return $sizeOK -and (-not $state.Mode -or $value.LogMode -eq $state.Mode)
        }
        $apply = {
            param($state)
            # Recheck after prompting/journaling. A newly increased buffer must not
            # be shrunk in minimum mode. Windows has no atomic compare-and-set here.
            $fresh = Get-WelaEventLogState -Log $state.Log
            if ($fresh.ReadStatus -ne 'Available') { throw 'Event-log state became unreadable before write.' }
            $arguments = @('sl', $state.Log)
            if (($state.ExactSize -and $fresh.MaximumSizeInBytes -ne $state.Bytes) -or $fresh.MaximumSizeInBytes -lt $state.Bytes) {
                $arguments += "/ms:$($state.Bytes)"
            }
            if ($state.Mode -and $fresh.LogMode -ne $state.Mode) {
                if ($state.Mode -eq 'Circular') { $arguments += @('/rt:false', '/ab:false') }
                elseif ($state.Mode -eq 'AutoBackup') { $arguments += @('/rt:true', '/ab:true') }
                else { throw 'Unsupported event-log mode.' }
            }
            if ($arguments.Count -gt 2) {
                # The prompt can outlive another administrator's change. Keep the
                # fresh snapshot as well as the runner's original observation.
                $state.BeforeWrite = $fresh
                [ordered]@{
                    Version = 1; ComputerName = $env:COMPUTERNAME; RecordedUtc = [DateTime]::UtcNow.ToString('o')
                    Id = "EventLog/$($state.Log)/ProfileSettings"; Kind = 'EventLog'; Phase = 'ImmediatePreWrite'
                    Target = @{ Log = $state.Log }; Before = $fresh
                    Desired = @{ MaximumSizeInBytes = $state.Bytes; SizeMode = $(if ($state.ExactSize) { 'Exact' } else { 'Minimum' }); LogMode = $state.Mode }
                } | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath (Join-Path $state.Context.BackupPath 'before.jsonl') -Encoding UTF8 -ErrorAction Stop
                Invoke-WelaNative -FilePath 'wevtutil.exe' -Arguments $arguments
            }
        }
        $description = if ($ResizeLogs) { "Set exact size $($state.Bytes) bytes (shrinking can discard events)." } else { "Set minimum size $($state.Bytes) bytes; preserve larger buffers." }
        $description += if ($ApplyLogMode) { " Apply $($state.Mode) mode." } else { ' Preserve the current retention mode.' }
        Invoke-WelaConfigurationControl -Context $Context -Id "EventLog/$($control.log)/ProfileSettings" -Kind EventLog `
            -Target @{ Log = $control.log; Profile = $selected.id } `
            -Desired @{ MaximumSizeInBytes = $state.Bytes; SizeMode = $(if ($ResizeLogs) { 'Exact' } else { 'Minimum' }); LogMode = $state.Mode } `
            -Description $description `
            -Read $read -Compliant $test -Apply $apply -CallbackState $state
        $result = $Context.Results[$Context.Results.Count - 1]
        $result | Add-Member NoteProperty SourceIds @($control.sourceIds)
        $result | Add-Member NoteProperty Evidence $control.evidence
        $result | Add-Member NoteProperty RecommendedMode $control.mode
        $result | Add-Member NoteProperty RetentionDays 'Unknown'
        $result | Add-Member NoteProperty BeforeWrite $state.BeforeWrite
    }
}

function Invoke-WelaEventLogConfiguration {
    param([string]$Profile = 'wela-source-2.2.0', [switch]$Auto, [switch]$DryRun,
          [switch]$ResizeLogs, [switch]$ApplyLogMode, [string]$BackupPath, [string]$ResultsPath)
    # Validate before a journal is created. The CLI checks Windows/elevation.
    $selected = Get-WelaEventLogProfile -Id $Profile
    $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
    Set-WelaEventLogProfileControls -Context $context -Profile $Profile -ResizeLogs:$ResizeLogs -ApplyLogMode:$ApplyLogMode
    $report = Complete-WelaConfiguration -Context $context -Scope 'event-log-size-and-mode-only'
    $report | Add-Member NoteProperty LogProfile $selected.id
    $report | Add-Member NoteProperty ProfileKind $selected.kind
    $report | Add-Member NoteProperty RetentionDays 'Unknown'
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode = 1; Write-Host "[Failed] Writing event-log results: $_" -ForegroundColor Red }
    }
    return $report
}
