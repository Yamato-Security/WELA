# Optional audit-only SMB policies. Requires Configuration.ps1; compatible with PowerShell 5.1.
function Get-WelaSmbAuditDefinitions {
    foreach ($component in @('LanmanServer', 'LanmanWorkstation')) {
        $peer = if ($component -eq 'LanmanServer') { 'Client' } else { 'Server' }
        foreach ($name in @("Audit${peer}DoesNotSupportEncryption", "Audit${peer}DoesNotSupportSigning", 'AuditInsecureGuestLogon')) {
            [pscustomobject]@{ Component = $component; Name = $name; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\$component"; Admx = "$component.admx"; PolicyName = "Pol_$name"; DesiredValue = 1; DesiredType = 'DWord' }
        }
    }
}

function Get-WelaSmbAuditHost {
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell to read and write the native policy registry view.' }
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property ProductType, BuildNumber, Version, Caption -ErrorAction Stop
        if (-not $os -or [string]$os.BuildNumber -notmatch '^\d+$' -or $os.ProductType -notin @(1, 2, 3)) { throw 'OS build or product type is unknown.' }
        $build = [int]$os.BuildNumber
        $state = if ($build -lt 26100) { 'NotApplicable' }
            elseif (($os.ProductType -eq 1 -and $build -in @(26100, 26200)) -or ($os.ProductType -in @(2, 3) -and $build -eq 26100)) { 'Candidate' }
            else { 'Unknown' }
        [pscustomobject]@{ Status = $state; Build = $build; ProductType = [int]$os.ProductType; Caption = [string]$os.Caption; Version = [string]$os.Version; Diagnostic = $(if ($state -eq 'NotApplicable') { 'These six audit switches require Windows 11 24H2/25H2 or Server 2025; older releases, including Server 2022, are not configured.' } elseif ($state -eq 'Unknown') { 'This OS build has not been reviewed; no policies will be created.' } else { 'Build is eligible; each local ADMX mapping is checked separately.' }) }
    } catch { [pscustomobject]@{ Status = 'Unknown'; Build = $null; ProductType = $null; Caption = $null; Version = $null; Diagnostic = $_.Exception.Message } }
}

function Read-WelaSmbAuditAdmx {
    param([string]$Path)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    } finally { $reader.Dispose() }
}

function Get-WelaSmbAuditCapability {
    param($Definition, $HostState)
    $path = Join-Path (Join-Path $env:windir 'PolicyDefinitions') $Definition.Admx
    $result = [pscustomobject]@{ Status = $HostState.Status; Host = $HostState; AdmxPath = $path; AdmxSha256 = $null; SupportedOn = $null; Diagnostic = $HostState.Diagnostic }
    if ($HostState.Status -ne 'Candidate') { return $result }
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) { throw "Local policy definition is missing: $path" }
        $document = Read-WelaSmbAuditAdmx -Path $path
        $policies = @($document.SelectNodes("//*[local-name()='policy']") | Where-Object {
            $_.GetAttribute('name') -eq $Definition.PolicyName -and $_.GetAttribute('class') -eq 'Machine' -and
            $_.GetAttribute('key') -eq ($Definition.Path -replace '^HKLM:\\', '') -and $_.GetAttribute('valueName') -eq $Definition.Name
        })
        if ($policies.Count -ne 1) { throw 'Exact machine ADMX policy/key/value mapping is missing or ambiguous.' }
        $enabled = $policies[0].SelectSingleNode("./*[local-name()='enabledValue']/*[local-name()='decimal']")
        if (-not $enabled -or $enabled.GetAttribute('value') -ne '1') { throw 'ADMX does not define the requested enabled DWORD value 1.' }
        $supported = $policies[0].SelectSingleNode("./*[local-name()='supportedOn']")
        if ($supported) { $result.SupportedOn = $supported.GetAttribute('ref') }
        $result.AdmxSha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        $result.Status = 'Supported'
        $result.Diagnostic = 'Reviewed host build and exact local machine ADMX mapping found. Runtime observation and event validation are separate.'
    } catch { $result.Status = 'Unknown'; $result.Diagnostic = $_.Exception.Message }
    return $result
}

function Get-WelaSmbAuditRuntime {
    param($Definition)
    $command = if ($Definition.Component -eq 'LanmanServer') { 'Get-SmbServerConfiguration' } else { 'Get-SmbClientConfiguration' }
    $result = [pscustomobject]@{ Command = $command; Property = $Definition.Name; Status = 'NotExposed'; Value = $null; Diagnostic = '' }
    try {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            $result.Diagnostic = 'Runtime cmdlet is unavailable; registry-only verification cannot establish effective auditing.'
            return $result
        }
        $configuration = & $command -ErrorAction Stop
        if (-not $configuration) { throw 'Runtime cmdlet returned no configuration.' }
        $property = $configuration.PSObject.Properties[$Definition.Name]
        if ($null -eq $property) {
            $result.Diagnostic = 'This runtime object does not expose the audit property; registry-only verification cannot establish effective auditing.'
            return $result
        }
        if ($property.Value -isnot [bool]) { throw 'Runtime audit property is not a Boolean.' }
        $result.Status = 'Observed'; $result.Value = $property.Value
        $result.Diagnostic = if ($property.Value) {
            'Runtime audit Boolean is True; generated or collected events have not been verified.'
        } else {
            'Runtime audit Boolean is False; enabled auditing is not currently observed. The cause and activation timing are unknown; a policy refresh or restart is not assumed to resolve this.'
        }
    } catch { $result.Status = 'Unknown'; $result.Diagnostic = $_.Exception.Message }
    return $result
}

function Get-WelaSmbAuditState {
    param($Definition)
    $capability = Get-WelaSmbAuditCapability -Definition $Definition -HostState (Get-WelaSmbAuditHost)
    $policy = $null; $runtime = $null
    if ($capability.Status -eq 'Supported') {
        $policy = Get-WelaRegistryState -Path $Definition.Path -Name $Definition.Name
        $runtime = Get-WelaSmbAuditRuntime -Definition $Definition
    }
    $policyConfigured = $capability.Status -eq 'Supported' -and $policy.ValueExists -and $policy.Type -eq 'DWord' -and $policy.Value -eq 1
    $runtimeState = if ($capability.Status -eq 'NotApplicable') { 'NotApplicable' }
        elseif ($runtime -and $runtime.Status -eq 'Observed' -and $runtime.Value) { 'Active' }
        elseif ($runtime -and $runtime.Status -eq 'Observed' -and $policyConfigured) { 'PendingVerification' }
        elseif ($runtime -and $runtime.Status -eq 'Observed') { 'NotActive' }
        else { 'Unknown' }
    [pscustomobject]@{
        Capability = $capability; Policy = $policy; Runtime = $runtime
        PolicyRegistryConfigured = [bool]$policyConfigured; RuntimeState = $runtimeState
        VerificationScope = $(if ($runtimeState -eq 'Active') { 'Policy registry and runtime audit flag observed separately; event generation not established' }
            elseif ($runtimeState -eq 'PendingVerification') { 'Policy registry configured; runtime verification pending (observed False)' }
            else { 'Policy registry only; effective auditing not established' })
    }
}

function Test-WelaSmbAuditCompliance {
    param($Snapshot)
    # The mutation requests a policy DWORD, not synchronous runtime activation.
    # Runtime evidence stays separate; read errors still fail in the read callback.
    return $Snapshot.Capability.Status -eq 'Supported' -and $Snapshot.Policy.ValueExists -and
        $Snapshot.Policy.Type -eq 'DWord' -and $Snapshot.Policy.Value -eq 1
}

function Get-WelaSmbAuditPlan {
    foreach ($definition in Get-WelaSmbAuditDefinitions) {
        $state = $null
        try {
            $state = Get-WelaSmbAuditState -Definition $definition
            $status = if ($state.Capability.Status -ne 'Supported') { $state.Capability.Status }
                elseif ($state.Runtime.Status -eq 'Unknown') { 'Unknown' }
                elseif (Test-WelaSmbAuditCompliance $state) { 'PolicyConfigured' } else { 'ChangeRequired' }
            $diagnostic = if ($state.Capability.Status -ne 'Supported') { $state.Capability.Diagnostic } else { $state.Runtime.Diagnostic }
            [pscustomobject]@{ Definition = $definition; Status = $status; Before = $state; Diagnostic = $diagnostic }
        } catch { [pscustomobject]@{ Definition = $definition; Status = 'Unknown'; Before = $state; Diagnostic = $_.Exception.Message } }
    }
}

function Set-WelaSmbAuditControls {
    param($Context, [array]$Plan)
    foreach ($entry in $Plan) {
        $definition = $entry.Definition
        $id = "SmbAudit/$($definition.Component)/$($definition.Name)"
        if ($entry.Status -in @('NotApplicable', 'Unknown')) {
            $Context.Results.Add([pscustomobject]@{ Id = $id; Kind = 'SmbAudit'; Target = @{ Path = $definition.Path; Name = $definition.Name }; Desired = @{ Value = 1; Type = 'DWord' }; Before = $entry.Before; After = $entry.Before; Status = $(if ($entry.Status -eq 'NotApplicable') { 'Skipped' } else { 'Failed' }); Diagnostic = "$($entry.Status): $($entry.Diagnostic)" })
            continue
        }
        $callback = @{ Definition = $definition; Observed = $null }
        $read = {
            param($state)
            $snapshot = Get-WelaSmbAuditState -Definition $state.Definition
            if ($snapshot.Capability.Status -ne 'Supported') { throw "SMB policy capability changed: $($snapshot.Capability.Diagnostic)" }
            if ($snapshot.Runtime.Status -eq 'Unknown') { throw "Runtime observation failed: $($snapshot.Runtime.Diagnostic)" }
            $state.Observed = $snapshot
            return $snapshot
        }
        $test = { param($snapshot) Test-WelaSmbAuditCompliance $snapshot }
        $apply = {
            param($state)
            $fresh = Get-WelaSmbAuditState -Definition $state.Definition
            if ($fresh.Capability.Status -ne 'Supported' -or $fresh.Runtime.Status -eq 'Unknown') { throw 'Capability/runtime could no longer be read; no policy was written.' }
            foreach ($field in @('KeyExists', 'ValueExists', 'Value', 'Type')) {
                if ($fresh.Policy.$field -ne $state.Observed.Policy.$field) { throw 'Policy changed after the recovery snapshot; review policy and retry.' }
            }
            New-WelaRegistryKey -Path $state.Definition.Path
            Set-ItemProperty -LiteralPath $state.Definition.Path -Name $state.Definition.Name -Type DWord -Value 1 -ErrorAction Stop
            'Audit policy DWORD written. Runtime activation is observed separately; its cause/timing, event generation/collection and policy persistence remain unverified.'
        }
        Invoke-WelaConfigurationControl -Context $Context -Id $id -Kind SmbAudit -Target @{ Path = $definition.Path; Name = $definition.Name } `
            -Desired @{ Value = 1; Type = 'DWord' } -Read $read -Compliant $test -Apply $apply -CallbackState $callback `
            -Description 'Set this supported SMB audit policy to DWORD 1 without changing security requirements.'
    }
}

function Invoke-WelaSmbAuditCommand {
    param([ValidateSet('Audit', 'Plan', 'Configure')][string]$Action = 'Audit', [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($env:OS -ne 'Windows_NT') { throw 'SMB auditing requires Windows.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun applies only to SmbAction Configure; Audit and Plan are read-only.' }
    $plan = @(Get-WelaSmbAuditPlan)
    if ($Action -eq 'Configure') {
        $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaSmbAuditControls -Context $context -Plan $plan
        $report = Complete-WelaConfiguration -Context $context -Scope 'smb-audit-policies-only' `
            -SuccessMessage 'SMB policy registry values verified. Runtime activation and event generation are reported separately.'
        $runtimeSummary = [ordered]@{ Active = 0; PendingVerification = 0; NotActive = 0; Unknown = 0; NotApplicable = 0 }
        foreach ($row in $report.Results) {
            # A failed final read can leave an earlier snapshot in After. Do not
            # promote that stale observation to a successful runtime summary.
            $snapshot = if ($row.Status -eq 'Failed') { $null } elseif ($row.After) { $row.After } else { $row.Before }
            $runtimeState = if ($snapshot -and $snapshot.RuntimeState) { $snapshot.RuntimeState } else { 'Unknown' }
            $runtimeSummary[$runtimeState]++
        }
        $report | Add-Member NoteProperty VerificationScope 'Policy registry write/read-back verification; runtime activation and event generation are separate observations.'
        $report | Add-Member NoteProperty RuntimeVerification ([pscustomobject]$runtimeSummary)
        Write-Host "SMB runtime observations: $($runtimeSummary.Active) active, $($runtimeSummary.PendingVerification) pending verification, $($runtimeSummary.NotActive) not active, $($runtimeSummary.Unknown) unknown, $($runtimeSummary.NotApplicable) not applicable. Pending means observed False despite policy DWORD 1; the cause and activation timing are unknown. No refresh or restart was performed." -ForegroundColor Yellow
        if ($ResultsPath) {
            try { $report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
            catch { $report.ExitCode = 1; Write-Host "[Failed] Writing SMB results: $_" -ForegroundColor Red }
        }
        return $report
    }
    $report = [pscustomobject]@{ Scope = 'smb-audit-policies-only'; Action = $Action; Controls = $plan; ExitCode = $(if (@($plan | Where-Object Status -eq Unknown).Count) { 1 } else { 0 }) }
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    return $report
}
