# Shared, native event-log size and retention model. Windows PowerShell 5.1 compatible.
function ConvertTo-WelaEventLogBytes {
    param([ValidateRange(1048576, 2199023255552)][long]$Bytes)
    # wevtutil uses 64 KiB units. Round UP so a minimum never becomes too small.
    return [long]([math]::Ceiling($Bytes / 65536.0) * 65536)
}

function Import-WelaEventLogProfiles {
    param([string]$Path = (Join-Path $PSScriptRoot '../config/eventlog_profiles.json'))
    $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($data.schemaVersion -ne 1) { throw 'Unsupported event-log profile schema.' }
    $ids = @{}
    foreach ($profile in $data.profiles) {
        if (-not $profile.id -or $ids.ContainsKey($profile.id)) { throw 'Missing or duplicate event-log profile ID.' }
        $ids[$profile.id] = $true
        if ($profile.kind -notin @('source', 'collector') -or $profile.scope -ne 'event-log-size-and-mode-only') { throw "Invalid event-log profile: $($profile.id)" }
        $logs = @{}
        foreach ($control in $profile.controls) {
            if (-not $control.log -or $control.log -match '[*?\[\]\r\n]' -or $logs.ContainsKey($control.log)) { throw "Invalid/duplicate event log: $($control.log)" }
            $logs[$control.log] = $true
            if ($control.mode -notin @('Circular', 'AutoBackup') -or -not $control.evidence) { throw "Invalid mode/evidence: $($control.log)" }
            if ($control.minimumBytes -isnot [long] -and $control.minimumBytes -isnot [int]) { throw 'Log size must be an integer byte count.' }
            $null = ConvertTo-WelaEventLogBytes $control.minimumBytes
            if (@($control.sourceIds).Count -eq 0) { throw 'Event-log source evidence is required.' }
            foreach ($id in $control.sourceIds) {
                if (-not $data.sources.PSObject.Properties[$id]) { throw "Unknown event-log source: $id" }
            }
        }
        if ($logs.Count -eq 0) { throw 'An event-log profile must contain controls.' }
    }
    return $data
}

function Get-WelaEventLogProfile {
    param([string]$Id = 'wela-source-2.2.0')
    $data = Import-WelaEventLogProfiles
    $profile = @($data.profiles | Where-Object { $_.id -eq $Id })
    if ($profile.Count -ne 1) { throw "Unknown log profile '$Id'. Use eventlog-profiles to list IDs." }
    return $profile[0]
}

function Get-WelaEventLogState {
    param([string]$Log)
    $state = [ordered]@{
        Log = $Log; ReadStatus = 'Unreadable'; MaximumSizeInBytes = $null
        LogMode = $null; FileSize = $null; IsEnabled = $null; Diagnostic = ''
    }
    try {
        $info = @(Get-WinEvent -ListLog $Log -ErrorAction Stop)
        if ($info.Count -ne 1 -or $null -eq $info[0].MaximumSizeInBytes -or [long]$info[0].MaximumSizeInBytes -le 0) { throw 'A unique channel with a readable positive maximum size was not returned.' }
        if ([string]$info[0].LogMode -notin @('Circular', 'AutoBackup', 'Retain')) { throw 'Channel retention mode is unknown.' }
        $state.MaximumSizeInBytes = [long]$info[0].MaximumSizeInBytes
        $state.LogMode = [string]$info[0].LogMode
        $state.FileSize = $info[0].FileSize
        $state.IsEnabled = $info[0].IsEnabled
        $state.ReadStatus = 'Available'
    } catch {
        # Do not turn permission/provider failures into a claim that a channel is absent.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*' -or $_.Exception.GetType().FullName -eq 'System.Diagnostics.Eventing.Reader.EventLogNotFoundException') { $state.ReadStatus = 'Missing' }
        $state.Diagnostic = $_.ToString()
    }
    return [pscustomobject]$state
}

function Get-WelaEventLogAudit {
    param([string]$Profile = 'wela-source-2.2.0', [scriptblock]$Read = { param($log) Get-WelaEventLogState -Log $log })
    $selected = Get-WelaEventLogProfile -Id $Profile
    foreach ($control in $selected.controls) {
        $current = & $Read $control.log
        $available = $current.ReadStatus -eq 'Available'
        $target = ConvertTo-WelaEventLogBytes $control.minimumBytes
        [pscustomobject][ordered]@{
            Profile = $selected.id; Log = $control.log; ReadStatus = $current.ReadStatus
            CurrentMaximumBytes = $current.MaximumSizeInBytes
            CurrentMaximumMiB = $(if ($available) { $current.MaximumSizeInBytes / 1048576.0 } else { $null })
            MinimumBytes = [long]$control.minimumBytes; RoundedTargetBytes = $target
            SizeStatus = $(if (-not $available) { 'Unknown' } elseif ($current.MaximumSizeInBytes -ge $target) { 'Compliant' } else { 'BelowMinimum' })
            CurrentMode = $current.LogMode; RecommendedMode = $control.mode
            ModeStatus = $(if (-not $available) { 'Unknown' } elseif ($current.LogMode -eq $control.mode) { 'Compliant' } else { 'Different' })
            RetentionDays = 'Unknown'; IsEnabled = $current.IsEnabled
            IsNearlyFull = $(if ($available -and $null -ne $current.FileSize) { $current.FileSize -ge ($current.MaximumSizeInBytes * 0.95) } else { $null })
            SourceIds = ($control.sourceIds -join ','); Evidence = $control.evidence; Diagnostic = $current.Diagnostic
        }
    }
}

Export-ModuleMember -Function ConvertTo-WelaEventLogBytes, Import-WelaEventLogProfiles, Get-WelaEventLogProfile, Get-WelaEventLogState, Get-WelaEventLogAudit
