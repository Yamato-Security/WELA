# Explicit native audit policy controls. Read-only unless Configure is selected.
function Get-WelaNotificationHost {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [pscustomobject]@{Status='NotApplicable';Diagnostic='Windows required.'} }
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell for the native policy registry view.' }
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if (($os.ProductType -eq 1 -and $computer.DomainRole -notin @(0,1)) -or
            ($os.ProductType -eq 2 -and $computer.DomainRole -notin @(4,5)) -or
            ($os.ProductType -eq 3 -and $computer.DomainRole -notin @(2,3)) -or $os.ProductType -notin @(1,2,3)) { throw 'Unknown or conflicting Windows role observations.' }
        $build=[int]$os.BuildNumber
        $supported=($os.ProductType -eq 1 -and $build -in @(22000,22621,22631,26100,26200)) -or
            ($os.ProductType -in @(2,3) -and $build -in @(20348,26100))
        [pscustomobject]@{Status=$(if ($supported) {'Supported'} else {'Unknown'});Build=$build;ProductType=[int]$os.ProductType;DomainRole=[int]$computer.DomainRole;Caption=[string]$os.Caption;Diagnostic='Reviewed Windows 11 / Server 2022 and 2025 host families; individual controls have additional gates.'}
    } catch { [pscustomobject]@{Status='Unknown';Diagnostic=$_.Exception.Message} }
}

function Get-WelaNotificationDefinitions {
    @(
        [pscustomobject]@{Id='OneSettings';Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';Name='EnableOneSettingsAuditing';Channel='Microsoft-Windows-Privacy-Auditing/Operational';Source='CIS Windows 11 Enterprise / Windows Server 2022 v4.0.0, 18.10.16.5';DocumentedDefault='Disabled (source reference; not a clean-host observation)'}
        [pscustomobject]@{Id='SecurityWarning';Path='HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security';Name='WarningLevel';Channel='Security';Source='CIS Windows 11 Enterprise v4.0.0 18.5.13 / Windows Server 2022 v4.0.0 18.5.12';DocumentedDefault='0 percent (source reference; not a clean-host observation)'}
    )
}

function Get-WelaOneSettingsDefinitionEvidence {
    $path=Join-Path $env:windir 'PolicyDefinitions/DataCollection.admx'
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create($path,$settings)
    try {
        $doc=New-Object Xml.XmlDocument; $doc.XmlResolver=$null; $doc.Load($reader)
        $policies=@($doc.SelectNodes("//*[local-name()='policy']") | Where-Object {
            $_.GetAttribute('name') -eq 'EnableOneSettingsAuditing' -and $_.GetAttribute('class') -eq 'Machine' -and
            $_.GetAttribute('key') -eq 'Software\Policies\Microsoft\Windows\DataCollection' -and $_.GetAttribute('valueName') -eq 'EnableOneSettingsAuditing'
        })
        if ($policies.Count -ne 1) { throw 'Exact OneSettings machine policy mapping is absent or ambiguous.' }
        $enabled=$policies[0].SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
        if (-not $enabled -or $enabled.GetAttribute('value') -ne '1') { throw 'OneSettings enabled DWORD definition is not 1.' }
        [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash;Mapping='EnableOneSettingsAuditing DWORD 1'}
    } finally { $reader.Dispose() }
}

function Get-WelaNotificationSnapshot {
    param($Definition)
    $hostState=Get-WelaNotificationHost
    $result=[pscustomobject]@{Host=$hostState;Status=$hostState.Status;Policy=$null;Channel=$null;DefinitionEvidence=$null;WarningGeneration='Not applicable to this control';Diagnostic=$hostState.Diagnostic}
    if ($hostState.Status -ne 'Supported') { return $result }
    try {
        if ($Definition.Id -eq 'OneSettings') {
            # CIS Server 2022 explicitly includes this control. The client CSP alone
            # does not establish Server 2025 support; leave that family unverified.
            if ($hostState.ProductType -ne 1 -and $hostState.Build -ne 20348) { throw 'OneSettings on this server release lacks reviewed source support; no policy will be created.' }
            $result.DefinitionEvidence=Get-WelaOneSettingsDefinitionEvidence
        }
        $result.Policy=Get-WelaRegistryState -Path $Definition.Path -Name $Definition.Name
        $result.Channel=Get-WelaNativeChannel -Name $Definition.Channel
        if ($result.Policy.ValueExists -and $result.Policy.Type -ne 'DWord') { throw 'Existing policy value has an unexpected registry type; preserved for manual review.' }
        if ($Definition.Id -eq 'OneSettings') {
            if ($result.Policy.ValueExists -and $result.Policy.Value -notin @(0,1)) { throw 'Unknown OneSettings DWORD value; preserved for manual review.' }
            if (-not (Test-WelaNativeChannelSnapshot $result.Channel)) { throw 'Privacy-Auditing channel metadata is absent or unreadable; event logging prerequisites are not established.' }
            $result.Diagnostic='Registry policy and native channel observed; OneSettings event generation and forwarding remain unverified.'
        } else {
            $result.WarningGeneration=switch ($result.Channel.LogMode) {
                'Circular' {'Not expected: overwrite mode suppresses this warning'}
                'Retain' {'Conditional: retained log mode; threshold event still requires lab validation'}
                'AutoBackup' {'Unknown: automatic archive rollover behavior requires lab validation'}
                default {'Unknown: Security log retention mode unreadable'}
            }
            $result.Diagnostic='Threshold compliance is independent of warning generation, disk space, archive retention and forwarding health.'
        }
    } catch { $result.Status='Unknown'; $result.Diagnostic=$_.Exception.Message }
    return $result
}

function Test-WelaNotificationValueEqual {
    param($First,$Second)
    return $First.ValueExists -eq $Second.ValueExists -and $First.Type -ceq $Second.Type -and
        (ConvertTo-Json $First.Value -Compress) -ceq (ConvertTo-Json $Second.Value -Compress)
}

function Get-WelaNotificationPlan {
    param([ValidateSet('OneSettings','SecurityWarning')][string[]]$Control=@('OneSettings','SecurityWarning'),[ValidateRange(1,90)][int]$WarningPercent=90)
    foreach ($definition in Get-WelaNotificationDefinitions) {
        if ($definition.Id -notin $Control) { continue }
        $snapshot=Get-WelaNotificationSnapshot $definition
        $desired=if ($definition.Id -eq 'OneSettings') {1} else {$WarningPercent}
        # Threshold is an upper bound: preserve an existing earlier warning.
        if ($definition.Id -eq 'SecurityWarning' -and $snapshot.Policy.ValueExists -and $snapshot.Policy.Type -eq 'DWord' -and
            $snapshot.Policy.Value -ge 1 -and $snapshot.Policy.Value -le $WarningPercent) { $desired=[int]$snapshot.Policy.Value }
        $matches=$snapshot.Status -eq 'Supported' -and $snapshot.Policy.ValueExists -and $snapshot.Policy.Type -eq 'DWord' -and $snapshot.Policy.Value -eq $desired
        [pscustomobject]@{Definition=$definition;Before=$snapshot;Desired=$desired;Status=$(if ($snapshot.Status -ne 'Supported') {$snapshot.Status} elseif ($matches) {'PolicyMatches'} else {'ChangeRequired'});ThresholdMaximum=$WarningPercent}
    }
}

function Set-WelaNotificationControls {
    param($Context,[array]$Plan)
    foreach ($entry in $Plan) {
        $state=@{Entry=$entry;Initial=$true;JournalState=$null}
        $read={
            param($state)
            $current=Get-WelaNotificationSnapshot $state.Entry.Definition
            if ($current.Status -ne 'Supported') { throw "Control prerequisites unavailable: $($current.Diagnostic)" }
            if ($state.Initial) {
                if ((ConvertTo-Json $current.Host -Compress) -cne (ConvertTo-Json $state.Entry.Before.Host -Compress) -or
                    -not (Test-WelaNotificationValueEqual $current.Policy $state.Entry.Before.Policy)) { throw 'Notification plan is stale; review a fresh plan.' }
                $state.JournalState=$current; $state.Initial=$false
            }
            return $current
        }
        $test={param($current,$state) $current.Policy.ValueExists -and $current.Policy.Type -eq 'DWord' -and $current.Policy.Value -eq $state.Entry.Desired}
        $apply={
            param($state)
            $fresh=Get-WelaNotificationSnapshot $state.Entry.Definition
            if ($fresh.Status -ne 'Supported' -or
                (ConvertTo-Json $fresh.Host -Compress) -cne (ConvertTo-Json $state.JournalState.Host -Compress) -or
                (ConvertTo-Json $fresh.DefinitionEvidence -Compress) -cne (ConvertTo-Json $state.JournalState.DefinitionEvidence -Compress) -or
                -not (Test-WelaNotificationValueEqual $fresh.Policy $state.JournalState.Policy)) { throw 'Notification state changed after journaling; write refused.' }
            New-WelaRegistryKey -Path $state.Entry.Definition.Path
            $value=Get-WelaRegistryState -Path $state.Entry.Definition.Path -Name $state.Entry.Definition.Name
            if (-not (Test-WelaNotificationValueEqual $value $fresh.Policy)) { throw 'Notification registry value changed immediately before writing.' }
            Set-ItemProperty -LiteralPath $state.Entry.Definition.Path -Name $state.Entry.Definition.Name -Value $state.Entry.Desired -Type DWord -ErrorAction Stop
        }
        Invoke-WelaConfigurationControl -Context $Context -Id "AuditNotifications/$($entry.Definition.Id)" -Kind Registry -Target @{Path=$entry.Definition.Path;Name=$entry.Definition.Name} -Desired @{Type='DWord';Value=$entry.Desired} -Read $read -Compliant $test -Apply $apply -CallbackState $state
    }
}

function Invoke-WelaNotificationCommand {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',
        [ValidateSet('OneSettings','SecurityWarning')][string[]]$Control,
        [ValidateRange(1,90)][int]$WarningPercent=90,[switch]$EnablePrivacyChannel,
        [switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if ($Action -eq 'Configure' -and -not $Control) { throw 'Configure requires an explicit NotificationControl selection.' }
    if (-not $Control) { $Control=@('OneSettings','SecurityWarning') }
    if ($EnablePrivacyChannel -and 'OneSettings' -notin $Control) { throw 'EnablePrivacyChannel requires the OneSettings control.' }
    if ($DryRun -and $Action -ne 'Configure') { throw 'DryRun requires Configure.' }
    $plan=@(Get-WelaNotificationPlan -Control $Control -WarningPercent $WarningPercent)
    $channelPlan=@()
    if ($EnablePrivacyChannel) {
        $one=@($plan | Where-Object {$_.Definition.Id -eq 'OneSettings'})[0]
        if ($one.Before.Status -ne 'Supported') { throw "Privacy channel configuration unavailable: $($one.Before.Diagnostic)" }
        # WELA's technical minimum only; CIS does not prescribe a channel size here.
        $profile=[pscustomobject]@{controls=@([pscustomobject]@{channel=$one.Definition.Channel;enabled=$true;sourceExampleBytes=65536;readerSid=$null})}
        $channelPlan=@(Get-WelaNativeChannelPlan -Profile $profile)
    }
    $report=[pscustomobject]@{Scope='audit-notifications';ExitCode=$(if (@($plan | Where-Object Status -eq 'Unknown').Count) {1} else {0})}
    if ($Action -eq 'Configure') {
        $context=New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaNotificationControls $context $plan
        if ($EnablePrivacyChannel) {
            $policy=@($context.Results | Where-Object Id -eq 'AuditNotifications/OneSettings')[0]
            if ($policy.Status -in @('AlreadyCompliant','Applied') -or ($DryRun -and $policy.Status -eq 'Skipped' -and $policy.Diagnostic -like 'Dry run:*')) {
                # Recheck the complete producer prerequisites before any channel action.
                $fresh=Get-WelaNotificationSnapshot $one.Definition
                if ($fresh.Status -ne 'Supported') { throw 'Privacy channel prerequisites changed after policy configuration.' }
                Set-WelaNativeChannelControls -Context $context -Plan $channelPlan -Profile 'audit-notifications'
            }
        }
        $report=Complete-WelaConfiguration -Context $context -SuccessMessage 'Selected registry/channel settings verified; generated warnings/events and forwarding remain unverified.'
        $report.Scope='audit-notifications'
    }
    $report | Add-Member NoteProperty Action $Action
    $report | Add-Member NoteProperty Plan $plan
    $report | Add-Member NoteProperty PrivacyChannelPlan $channelPlan
    $report | Add-Member NoteProperty Current @(Get-WelaNotificationPlan -Control $Control -WarningPercent $WarningPercent)
    $report | Add-Member NoteProperty EventGeneration 'Not verified; no Sigma eligibility increase. Sysmon is out of scope.'
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    $report
}
