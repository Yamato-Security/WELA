# Uses the shared configuration runner; no live writes occur in Audit or Plan.
function Test-WelaNativeChannelSnapshot {
    param($Snapshot)
    return $Snapshot.State -in @('Enabled', 'Disabled') -and $Snapshot.IsEnabled -is [bool] -and
        $null -ne $Snapshot.MaximumSizeInBytes -and $Snapshot.MaximumSizeInBytes -gt 0 -and
        $Snapshot.LogMode -in @('Circular', 'AutoBackup', 'Retain') -and
        -not [string]::IsNullOrWhiteSpace($Snapshot.SecurityDescriptor)
}

function Test-WelaNativeChannelSnapshotEqual {
    param($First, $Second)
    if (-not (Test-WelaNativeChannelSnapshot $First) -or -not (Test-WelaNativeChannelSnapshot $Second)) { return $false }
    return $First.Name -eq $Second.Name -and $First.IsEnabled -eq $Second.IsEnabled -and
        $First.MaximumSizeInBytes -eq $Second.MaximumSizeInBytes -and $First.LogMode -eq $Second.LogMode -and
        (Test-WelaChannelDescriptorEqual $First.SecurityDescriptor $Second.SecurityDescriptor)
}

function Get-WelaNativeChannelPlan {
    param($Profile, [switch]$GrantEventLogReaders)
    foreach ($control in $Profile.controls) {
        $before = Get-WelaNativeChannel -Name $control.channel
        $access = if ($control.readerSid) { Get-WelaChannelAccessPlan -SecurityDescriptor $before.SecurityDescriptor } else { $null }
        $minimum = ConvertTo-WelaEventLogBytes $control.sourceExampleBytes
        $valid = Test-WelaNativeChannelSnapshot $before
        $desiredAcl = $before.SecurityDescriptor
        if ($GrantEventLogReaders -and $control.readerSid -and $access.State -eq 'GrantRequired') { $desiredAcl = $access.ProposedDescriptor }
        $status = if (-not $valid) { if ($before.State -eq 'Not installed') { 'NotInstalled' } else { 'Unknown' } }
            elseif ($GrantEventLogReaders -and $access -and $access.State -notin @('GrantPresent', 'GrantRequired')) { 'ManualReview' }
            elseif (($null -ne $control.enabled -and $before.IsEnabled -ne $control.enabled) -or $before.MaximumSizeInBytes -lt $minimum -or
                ($GrantEventLogReaders -and $access -and $access.State -eq 'GrantRequired')) { 'ChangeRequired' } else { 'RequestedSettingsMatch' }
        [pscustomobject][ordered]@{
            Definition = $control; Before = $before; Status = $status; Access = $access
            Desired = [pscustomobject]@{
                IsEnabled = $(if ($null -eq $control.enabled) { $before.IsEnabled } else { $control.enabled })
                SourceExampleBytes = [long]$control.sourceExampleBytes; RoundedMinimumBytes = $minimum
                MaximumSizeInBytes = $(if ($valid) { [math]::Max([long]$before.MaximumSizeInBytes, $minimum) } else { $null })
                LogMode = $before.LogMode; SecurityDescriptor = $desiredAcl
                AccessChangeRequested = [bool]($GrantEventLogReaders -and $control.readerSid)
            }
            Prerequisites = @($(if ($access -and $access.State -ne 'GrantPresent') { "Event Log Readers read ACE: $($access.State). Use -GrantEventLogReaders only after reviewing the proposed descriptor; manual-review states cannot be changed automatically." }),
                'Effective forwarding identity read access and actual event/forwarding evidence remain unverified.') | Where-Object { $_ }
        }
    }
}

function Set-WelaNativeChannelControls {
    param($Context, [array]$Plan, [string]$Profile)
    foreach ($entry in $Plan) {
        $channel = $entry.Definition.channel
        $id = "NativeChannel/$channel/Settings"
        if ($entry.Status -in @('NotInstalled', 'Unknown', 'ManualReview')) {
            $Context.Results.Add([pscustomobject]@{
                Id = $id; Kind = 'NativeChannel'; Target = @{ Channel = $channel; Profile = $Profile }
                Desired = $entry.Desired; Before = $entry.Before; After = $null; Status = 'Failed'
                Diagnostic = "$($entry.Status): channel metadata/ACL cannot safely be configured. $($entry.Access.Diagnostic)"
            })
            continue
        }
        $state = @{ Entry = $entry; InitialRead = $true; Snapshot = $null }
        $read = {
            param($state)
            $current = Get-WelaNativeChannel -Name $state.Entry.Definition.channel
            if (-not (Test-WelaNativeChannelSnapshot $current)) { throw 'Channel settings became unreadable; no assumed defaults are used.' }
            if ($state.InitialRead) {
                # The plan may outlive another writer. Never apply an ACL based on
                # an old descriptor, even before the shared runner's first read.
                if (-not (Test-WelaNativeChannelSnapshotEqual $state.Entry.Before $current)) { throw 'Channel settings changed after planning; review a fresh plan before retrying.' }
                $state.Snapshot = $current; $state.InitialRead = $false
            }
            return $current
        }
        $test = {
            param($current, $state)
            $desired = $state.Entry.Desired
            return $current.IsEnabled -eq $desired.IsEnabled -and $current.MaximumSizeInBytes -eq $desired.MaximumSizeInBytes -and
                $current.LogMode -eq $desired.LogMode -and (Test-WelaChannelDescriptorEqual $current.SecurityDescriptor $desired.SecurityDescriptor)
        }
        $apply = {
            param($state)
            $entry = $state.Entry
            $fresh = Get-WelaNativeChannel -Name $entry.Definition.channel
            if (-not (Test-WelaNativeChannelSnapshotEqual $state.Snapshot $fresh)) { throw 'Channel settings changed after the recovery snapshot; no channel write was attempted.' }
            $arguments = @('sl', $entry.Definition.channel)
            if ($fresh.IsEnabled -ne $entry.Desired.IsEnabled) { $arguments += '/e:true' }
            if ($fresh.MaximumSizeInBytes -ne $entry.Desired.MaximumSizeInBytes) { $arguments += "/ms:$($entry.Desired.MaximumSizeInBytes)" }
            if (-not (Test-WelaChannelDescriptorEqual $fresh.SecurityDescriptor $entry.Desired.SecurityDescriptor)) {
                if (-not $entry.Desired.AccessChangeRequested -or $entry.Access.State -ne 'GrantRequired') { throw 'An ACL difference has no explicit, validated read-grant request.' }
                $arguments += "/ca:$($entry.Desired.SecurityDescriptor)"
            }
            if ($arguments.Count -gt 2) { Invoke-WelaNative -FilePath 'wevtutil.exe' -Arguments $arguments }
        }
        Invoke-WelaConfigurationControl -Context $Context -Id $id -Kind NativeChannel -Target @{ Channel = $channel; Profile = $Profile } `
            -Desired $entry.Desired -Read $read -Compliant $test -Apply $apply -CallbackState $state `
            -Description "Apply declared enable/minimum-size settings; preserve larger buffers, retention and existing ACEs. Add only the Event Log Readers read ACE when explicitly requested."
    }
}

function Invoke-WelaNativeChannelCommand {
    param([ValidateSet('Audit', 'Plan', 'Configure')][string]$Action = 'Audit',
        [string]$Profile = 'microsoft-wef-appendix-c',
        [ValidateSet('Baseline', 'Suspect', 'Both')][string]$QuerySet = 'Both',
        [switch]$GrantEventLogReaders, [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($env:OS -ne 'Windows_NT') { throw 'Native channel settings require Windows.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun requires ChannelAction Configure; Audit and Plan are read-only.' }
    $selected = Get-WelaNativeChannelProfile -Id $Profile
    $plan = @(Get-WelaNativeChannelPlan -Profile $selected -GrantEventLogReaders:$GrantEventLogReaders)
    if ($Action -eq 'Configure') {
        $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaNativeChannelControls -Context $context -Plan $plan -Profile $selected.id
        $report = Complete-WelaConfiguration -Context $context -Scope 'native-channel-settings-only' `
            -SuccessMessage 'Requested channel settings verified. Forwarding identity read access and event/ingestion evidence remain unverified.'
    } else {
        $report = [pscustomobject]@{ Scope = 'native-channel-settings-only'; ExitCode = $(if (@($plan | Where-Object Status -in @('Unknown', 'NotInstalled', 'ManualReview')).Count) { 1 } else { 0 }) }
    }
    # Read inventory after configuration so exports do not show only stale pre-state.
    $inventory = @(Get-WelaNativeChannelInventory -Profile $selected -QuerySet $QuerySet)
    $current = if ($Action -eq 'Configure') { @(Get-WelaNativeChannelPlan -Profile $selected -GrantEventLogReaders:$GrantEventLogReaders) } else { $plan }
    $excluded = @()
    foreach ($set in @('Baseline', 'Suspect')) {
        if ($QuerySet -eq 'Both' -or $QuerySet -eq $set) {
            foreach ($query in $selected.querySets.$set.excludedQueries) { $excluded += [pscustomobject]@{ QuerySet = $set; QueryId = $query.queryId; Reason = $query.reason } }
        }
    }
    $report | Add-Member NoteProperty Action $Action
    $report | Add-Member NoteProperty ChannelProfile $selected.id
    $report | Add-Member NoteProperty Source $selected.source
    $report | Add-Member NoteProperty WefQuerySet $QuerySet
    $report | Add-Member NoteProperty GrantEventLogReadersRequested ([bool]$GrantEventLogReaders)
    $report | Add-Member NoteProperty Controls $current
    $report | Add-Member NoteProperty QueryInventory $inventory
    $report | Add-Member NoteProperty ExcludedQueries $excluded
    $report | Add-Member NoteProperty ForwardingReadiness 'Not verified'
    $report | Add-Member NoteProperty UnverifiedPrerequisites @('Forwarding token/group membership (including Network Service where applicable)', 'WinRM and collector/subscription configuration', 'Representative native events, identity read access and collector ingestion')
    Write-Host 'Native query inventory and channel settings are observations only. Forwarding access, event generation and ingestion are not verified; no Sigma coverage increase is claimed.' -ForegroundColor Yellow
    $current | Select-Object @{n='Channel';e={$_.Definition.channel}}, Status, @{n='ReaderAce';e={$_.Access.State}}, @{n='SourceBytes';e={$_.Desired.SourceExampleBytes}}, @{n='MinimumBytes';e={$_.Desired.RoundedMinimumBytes}} | Format-Table -AutoSize | Out-Host
    $inventory | Select-Object @{n='RequiredChannel';e={$_.Channel.Name}}, @{n='State';e={$_.Channel.State}}, EffectiveReadAccess | Format-Table -AutoSize | Out-Host
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode = 1; Write-Host "[Failed] Writing channel results: $_" -ForegroundColor Red }
    }
    return $report
}
