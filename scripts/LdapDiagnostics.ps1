# Opt-in local DC diagnostics; separate from MDI-required Security auditing.
function Get-WelaLdapDefinitions {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS'
    @(
        [pscustomobject]@{Id='FieldEngineering';Path="$root\Diagnostics";Name='15 Field Engineering';Unit='verbosity';DocumentedDefault=0}
        [pscustomobject]@{Id='SearchTime';Path="$root\Parameters";Name='Search Time Threshold (msecs)';Unit='milliseconds';DocumentedDefault=30000}
        [pscustomobject]@{Id='Expensive';Path="$root\Parameters";Name='Expensive Search Results Threshold';Unit='entry threshold';DocumentedDefault=10000}
        [pscustomobject]@{Id='Inefficient';Path="$root\Parameters";Name='Inefficient Search Results Threshold';Unit='entry threshold';DocumentedDefault=1000}
    )
}

function Get-WelaLdapHost {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [pscustomobject]@{Status='NotApplicable';Diagnostic='Windows domain controller required.'} }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($os.ProductType -notin @(1,2,3) -or $system.DomainRole -notin @(0,1,2,3,4,5)) { throw 'Cannot classify the Windows role.' }
    if ($os.ProductType -ne 2 -and $system.DomainRole -notin @(4,5)) { return [pscustomobject]@{Status='NotApplicable';Diagnostic='Client/member/CA without DC role: no NTDS diagnostics changes.'} }
    if ($os.ProductType -ne 2 -or $system.DomainRole -notin @(4,5)) { throw 'Conflicting domain-controller role observations.' }
    if ([int]$os.BuildNumber -notin @(20348,26100)) { return [pscustomobject]@{Status='Unknown';Diagnostic='This workflow supports Server 2022/2025 DC builds 20348/26100.'} }
    if (-not [Environment]::Is64BitProcess) { throw 'Run the LDAP workflow in 64-bit PowerShell.' }
    [pscustomobject]@{Status='Applicable';ComputerName=$env:COMPUTERNAME;Build=[int]$os.BuildNumber;Diagnostic='Local domain controller; event generation remains unverified.'}
}

function Get-WelaLdapSnapshot {
    $hostState = Get-WelaLdapHost
    $values = @()
    if ($hostState.Status -eq 'Applicable') {
        foreach ($definition in Get-WelaLdapDefinitions) {
            $values += [pscustomobject]@{Definition=$definition;State=(Get-WelaRegistryState -Path $definition.Path -Name $definition.Name)}
        }
    }
    [pscustomobject]@{Host=$hostState;Values=$values}
}

function Get-WelaLdapPlan {
    param($Snapshot, [ValidateSet('Preserve','Diagnostic','MdiCleanup')][string]$Mode='Preserve', [hashtable]$Thresholds=@{})
    if ($Mode -ne 'Diagnostic' -and $Thresholds.Count) { throw 'Thresholds require Diagnostic mode.' }
    foreach ($id in $Thresholds.Keys) {
        if ($id -notin @('SearchTime','Expensive','Inefficient') -or $Thresholds[$id] -is [bool] -or
            $Thresholds[$id] -isnot [ValueType] -or [double]$Thresholds[$id] -lt 1 -or [double]$Thresholds[$id] -gt 2147483647 -or
            [double]$Thresholds[$id] -ne [int]$Thresholds[$id]) { throw "Invalid positive DWORD threshold: $id" }
    }
    $rows = foreach ($entry in $Snapshot.Values) {
        $desired = $null; $operation = 'Preserve'
        if ($Mode -eq 'MdiCleanup') { $operation='Remove' }
        elseif ($Mode -eq 'Diagnostic') {
            if ($entry.Definition.Id -eq 'FieldEngineering') { $operation='Set'; $desired=5 }
            elseif ($Thresholds.ContainsKey($entry.Definition.Id)) { $operation='Set'; $desired=[int]$Thresholds[$entry.Definition.Id] }
        }
        [pscustomobject]@{Definition=$entry.Definition;Before=$entry.State;Operation=$operation;Desired=$desired}
    }
    [pscustomobject]@{
        Mode=$Mode;Host=$Snapshot.Host;Controls=@($rows)
        Guidance='MDI no longer requires 1644. Diagnostic mode is an explicit troubleshooting/detection choice; MdiCleanup explicitly removes the four listed legacy values. Preserve makes no changes.'
        Volume='Field Engineering level 5 can also generate other Directory Service events. Measure volume in a bounded window before wider rollout.'
        VerificationScope='Registry policy only; 1644 generation, thresholds in practice, volume and forwarding are not established.'
    }
}

function Test-WelaLdapDesired {
    param($Snapshot,$Plan)
    if ($Snapshot.Host.Status -ne 'Applicable') { return $false }
    foreach ($row in $Plan.Controls) {
        $actual = @($Snapshot.Values | Where-Object { $_.Definition.Id -eq $row.Definition.Id })
        if ($actual.Count -ne 1) { return $false }
        $state=$actual[0].State
        if ($row.Operation -eq 'Set' -and (-not $state.ValueExists -or $state.Type -ne 'DWord' -or $state.Value -ne $row.Desired)) { return $false }
        if ($row.Operation -eq 'Remove' -and $state.ValueExists) { return $false }
        if ($row.Operation -eq 'Preserve' -and -not (Test-WelaLdapValueEqual $state $row.Before)) { return $false }
    }
    return $true
}

function Test-WelaLdapValueEqual {
    param($Left,$Right)
    # Creating an absent parent for another selected value must not appear as value drift.
    return $Left.ValueExists -eq $Right.ValueExists -and $Left.Type -ceq $Right.Type -and
        (ConvertTo-Json $Left.Value -Compress) -ceq (ConvertTo-Json $Right.Value -Compress)
}

function Set-WelaLdapDiagnostics {
    param($Context,$Plan)
    $state = @{Plan=$Plan;Expected=$null}
    $read = {
        param($state)
        $current = Get-WelaLdapSnapshot
        if ($current.Host.Status -ne 'Applicable') { throw "LDAP diagnostics unavailable: $($current.Host.Diagnostic)" }
        $current
    }
    $test = {
        param($snapshot,$state)
        if (-not $state.Expected) { $state.Expected=$snapshot }
        Test-WelaLdapDesired $snapshot $state.Plan
    }
    $apply = {
        param($state)
        $fresh=Get-WelaLdapSnapshot
        if ((ConvertTo-Json $fresh -Depth 12 -Compress) -cne (ConvertTo-Json $state.Expected -Depth 12 -Compress)) { throw 'LDAP state changed after the pre-change journal; no write performed.' }
        # Plan is independently checked against the current pre-change state too.
        foreach ($row in $state.Plan.Controls) {
            $before=@($fresh.Values | Where-Object { $_.Definition.Id -eq $row.Definition.Id })[0].State
            if (-not (Test-WelaLdapValueEqual $before $row.Before)) { throw 'LDAP plan is stale; review a fresh plan.' }
            if ($before.ValueExists -and $before.Type -ne 'DWord') { throw "Unknown registry type for $($row.Definition.Name); preserved without mutation." }
        }
        # Configure thresholds before enabling verbose logging. Cleanup disables it first.
        $ordered = if ($state.Plan.Mode -eq 'Diagnostic') { @($state.Plan.Controls | Sort-Object { $_.Definition.Id -eq 'FieldEngineering' }) } else { @($state.Plan.Controls) }
        foreach ($row in $ordered) {
            if ($row.Operation -eq 'Preserve') { continue }
            $before=Get-WelaRegistryState -Path $row.Definition.Path -Name $row.Definition.Name
            if (-not (Test-WelaLdapValueEqual $before $row.Before)) { throw "LDAP value changed before writing $($row.Definition.Name); remaining changes stopped." }
            if ($row.Operation -eq 'Remove') {
                if ($before.ValueExists) { Remove-ItemProperty -LiteralPath $row.Definition.Path -Name $row.Definition.Name -ErrorAction Stop }
            } elseif (-not $before.ValueExists -or $before.Type -ne 'DWord' -or $before.Value -ne $row.Desired) {
                New-WelaRegistryKey -Path $row.Definition.Path
                Set-ItemProperty -LiteralPath $row.Definition.Path -Name $row.Definition.Name -Value $row.Desired -Type DWord -ErrorAction Stop
            }
            $after=Get-WelaRegistryState -Path $row.Definition.Path -Name $row.Definition.Name
            if (($row.Operation -eq 'Remove' -and $after.ValueExists) -or
                ($row.Operation -eq 'Set' -and (-not $after.ValueExists -or $after.Type -ne 'DWord' -or $after.Value -ne $row.Desired))) {
                throw "LDAP value readback failed for $($row.Definition.Name); remaining changes stopped."
            }
        }
    }
    Invoke-WelaConfigurationControl -Context $Context -Id 'LdapDiagnostics/LocalDC' -Kind RegistrySet -Target 'NTDS diagnostics/parameters (four named values only)' -Desired $Plan `
        -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Apply the explicitly selected LDAP diagnostic mode and listed values.'
}

function Invoke-WelaLdapCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',
        [ValidateSet('Preserve','Diagnostic','MdiCleanup')][string]$Mode='Preserve', [hashtable]$Thresholds=@{},
        [switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    $snapshot=Get-WelaLdapSnapshot
    $plan=Get-WelaLdapPlan -Snapshot $snapshot -Mode $Mode -Thresholds $Thresholds
    $report=[pscustomobject]@{ExitCode=$(if ($snapshot.Host.Status -eq 'Unknown') {1} else {0});Scope='ldap-1644-diagnostics';Plan=$plan;Snapshot=$snapshot}
    if ($Action -eq 'Configure' -and $Mode -ne 'Preserve') {
        if ($snapshot.Host.Status -ne 'Applicable') { throw "LDAP configuration blocked: $($snapshot.Host.Diagnostic)" }
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaLdapDiagnostics -Context $context -Plan $plan
        $report=Complete-WelaConfiguration -Context $context -SuccessMessage 'Selected LDAP registry changes verified; event generation and forwarding remain unverified.'
        $report.Scope='ldap-1644-diagnostics'
        $report | Add-Member NoteProperty Plan $plan
    }
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    Write-Host $plan.Guidance
    Write-Host $plan.Volume
    $report
}
