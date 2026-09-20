# Execution helpers for configure. Compatible with Windows PowerShell 5.1.
function Invoke-WelaNative {
    param([string]$FilePath, [string[]]$Arguments)
    # Windows PowerShell sends native stderr through the error stream. Collect it
    # without treating stderr alone as failure; the process exit code is decisive.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $null = Get-Command $FilePath -ErrorAction Stop
    $global:LASTEXITCODE = $null
    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $global:LASTEXITCODE # Capture immediately, before invoking anything else.
    $diagnostic = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed (exit: $exitCode). $diagnostic"
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = $output; Diagnostic = $diagnostic }
}

function New-WelaConfigurationContext {
    param([switch]$Auto, [switch]$DryRun, [string]$BackupPath)
    if (-not $DryRun) {
        if (-not $BackupPath) {
            $BackupPath = Join-Path $script:ScriptRoot ("wela-backup-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N'))
        }
        # Refuse reuse: a prior run's recovery evidence must never be overwritten.
        $null = New-Item -ItemType Directory -Path $BackupPath -ErrorAction Stop
        $BackupPath = (Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path
    }
    [pscustomobject]@{
        Auto = [bool]$Auto; DryRun = [bool]$DryRun; BackupPath = $BackupPath
        Results = New-Object 'System.Collections.Generic.List[object]'
        Checks = New-Object 'System.Collections.Generic.List[object]'
    }
}

function Assert-WelaConfigurationProfileGuard {
    param($Context)
    if ($Context.PSObject.Properties['CustomProfileGuard']) {
        $guard = $Context.CustomProfileGuard
        Assert-WelaCustomProfileSource $guard.Source
        $actual = Get-WelaHostContext
        if ($actual.Role -ne $guard.Role -or $actual.Build -ne $guard.Build) { throw 'Custom profile target role/build changed; no further configuration is authorized.' }
    }
}

function Invoke-WelaConfigurationControl {
    param($Context, [string]$Id, [string]$Kind, $Target, $Desired,
          [scriptblock]$Read, [scriptblock]$Compliant, [scriptblock]$Apply,
          [string]$Description = '', [scriptblock]$PreserveWhen, $CallbackState)
    $result = [pscustomobject][ordered]@{
        Id = $Id; Kind = $Kind; Target = $Target; Desired = $Desired
        Before = $null; After = $null; Status = 'Failed'; Diagnostic = ''
    }
    try {
        Assert-WelaConfigurationProfileGuard $Context
        $result.Before = & $Read $CallbackState
        $preserveReason = if ($PreserveWhen) { & $PreserveWhen $result.Before } else { $null }
        if ($preserveReason) {
            $result.Status = 'Skipped'; $result.After = $result.Before; $result.Diagnostic = [string]$preserveReason
        } elseif (& $Compliant $result.Before $CallbackState) {
            $result.Status = 'AlreadyCompliant'
            $result.After = $result.Before
        } elseif ($Context.DryRun) {
            $result.Status = 'Skipped'; $result.Diagnostic = 'Dry run: change required; no write or restart performed.'
        } else {
            $proceed = $Context.Auto
            if (-not $proceed) {
                $response = Read-Host "$Id : $Description Apply this change? (Y/n)"
                $proceed = ($response -eq '' -or $response -match '^[Yy]$')
            }
            if (-not $proceed) {
                $result.Status = 'Skipped'; $result.Diagnostic = 'Declined by operator.'
            } else {
                # Persist the exact pre-change value before any mutation. A journal
                # failure stops this control, including service restarts.
                $entry = [ordered]@{
                    Version = 1; ComputerName = $env:COMPUTERNAME
                    RecordedUtc = [DateTime]::UtcNow.ToString('o')
                    Id = $Id; Kind = $Kind; Target = $Target
                    Before = $result.Before; Desired = $Desired
                }
                if ($Context.PSObject.Properties['CustomProfileGuard']) { $entry.CustomProfileSource = $Context.CustomProfileGuard.Source }
                $entry | ConvertTo-Json -Depth 12 -Compress |
                    Add-Content -LiteralPath (Join-Path $Context.BackupPath 'before.jsonl') -Encoding UTF8 -ErrorAction Stop
                Assert-WelaConfigurationProfileGuard $Context
                $applied = @(& $Apply $CallbackState)
                $result.Diagnostic = ($applied | ForEach-Object {
                    if ($_.PSObject.Properties['Diagnostic']) { $_.Diagnostic } else { $_.ToString() }
                }) -join [Environment]::NewLine
                Assert-WelaConfigurationProfileGuard $Context
                $result.After = & $Read $CallbackState
                if (-not (& $Compliant $result.After $CallbackState)) {
                    throw "Post-apply verification did not match the requested state. $($result.Diagnostic)"
                }
                $result.Status = 'Applied'
            }
        }
        if ($result.Status -in @('Applied', 'AlreadyCompliant')) {
            $Context.Checks.Add([pscustomobject]@{ Result = $result; Read = $Read; Compliant = $Compliant; CallbackState = $CallbackState })
        }
    } catch {
        $result.Status = 'Failed'; $result.Diagnostic = $_.ToString()
    }
    $Context.Results.Add($result)
    $color = if ($result.Status -eq 'Failed') { 'Red' } elseif ($result.Status -eq 'Skipped') { 'Yellow' } else { 'Green' }
    Write-Host "[$($result.Status)] $Id $($result.Diagnostic)" -ForegroundColor $color
}

function Complete-WelaConfiguration {
    param($Context, [string]$ResultsPath, $Plan,
          [ValidateSet("native-windows-configuration", "advanced-audit-policy-only", "advanced-audit-policy-and-precedence", "firewall-text-logging-only", "event-log-size-and-mode-only", "smb-audit-policies-only", "native-channel-settings-only", "wmi-namespace-sacl-only", "ad-object-sacl-only", "windows-powershell-transcription-policy-only", "wef-source-configuration-only", "wec-collector-subscriptions-only", "audit-integrity-local-policy-only")]
          [string]$Scope = "native-windows-configuration",
          [string]$SuccessMessage = 'Configuration completed; all requested controls verified.')
    if ($Context.PSObject.Properties['CustomProfileGuard']) {
        try { Assert-WelaConfigurationProfileGuard $Context }
        catch { $Context.Results.Add([pscustomobject]@{Id='CustomProfile/FinalValidation';Kind='ProfileSource';Target=$Context.CustomProfileGuard.Source;Desired='Unchanged file and target';Before=$null;After=$null;Status='Failed';Diagnostic=$_.ToString()}) }
    }
    # A second read detects a value that was compliant earlier but changed during
    # this run. It does not establish whether GPO or another writer caused drift.
    foreach ($check in $Context.Checks) {
        try {
            Assert-WelaConfigurationProfileGuard $Context
            $check.Result.After = & $check.Read $check.CallbackState
            if (-not (& $check.Compliant $check.Result.After $check.CallbackState)) {
                $check.Result.Status = 'Overridden'
                $check.Result.Diagnostic = 'State was compliant earlier but changed before the final check; cause unknown.'
            }
        } catch {
            $check.Result.Status = 'Failed'
            $check.Result.Diagnostic = "Final verification failed: $_"
        }
    }
    $failed = @($Context.Results | Where-Object { $_.Status -in @('Failed', 'Overridden') }).Count
    $skipped = @($Context.Results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $report = [pscustomobject][ordered]@{
        ExitCode = $(if ($failed) { 1 } else { 0 }); DryRun = $Context.DryRun
        BackupPath = $Context.BackupPath; Failed = $failed; Skipped = $skipped; Scope = $Scope
        Results = @($Context.Results.ToArray())
    }
    if ($Plan) {
        $report | Add-Member NoteProperty Profile $Plan.profile
        $report | Add-Member NoteProperty Version $Plan.version
        $report | Add-Member NoteProperty Role $Plan.role
        $report | Add-Member NoteProperty Build $Plan.build
        $report | Add-Member NoteProperty SchemaSha256 $Plan.schemaSha256
        $report | Add-Member NoteProperty Provenance $Plan.provenance
        $report | Add-Member NoteProperty ProfileScope $Plan.scope
        if ($Plan.PSObject.Properties['CustomProfileSource']) { $report | Add-Member NoteProperty CustomProfileSource $Plan.CustomProfileSource }
    }
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode = 1; Write-Host "[Failed] Writing results: $_" -ForegroundColor Red }
    }
    if ($report.ExitCode) { Write-Host "Configuration incomplete: $failed failed or overridden control(s). Review results and recovery journal." -ForegroundColor Red }
    elseif ($Context.DryRun) { Write-Host 'Dry run completed. No Windows configuration was changed.' -ForegroundColor Cyan }
    elseif ($skipped) { Write-Host "Configuration completed with $skipped skipped control(s)." -ForegroundColor Yellow }
    else { Write-Host $SuccessMessage -ForegroundColor Green }
    return $report
}

function Set-WelaEventLogControl {
    param($Context, [string]$Log, [string]$Property, $Desired)
    $state = @{ Log = $Log; Property = $Property; Desired = $Desired }
    # Explicit callback state preserves values for the final recheck without
    # GetNewClosure's dynamic-module scope, which hides script-local helpers in 5.1.
    $read = { param($state) (Get-WinEvent -ListLog $state.Log -ErrorAction Stop).($state.Property) }
    $test = {
        param($value, $state)
        if ($state.Property -eq 'MaximumSizeInBytes') { return $value -ge $state.Desired }
        return $value -eq $state.Desired
    }
    $apply = {
        param($state)
        $argument = if ($state.Property -eq 'MaximumSizeInBytes') { "/ms:$($state.Desired)" } else { '/e:true' }
        Invoke-WelaNative -FilePath 'wevtutil.exe' -Arguments @('sl', $state.Log, $argument)
    }
    Invoke-WelaConfigurationControl -Context $Context -Id "EventLog/$Log/$Property" -Kind EventLog `
        -Target @{ Log = $Log; Property = $Property } -Desired $Desired -Read $read -Compliant $test -Apply $apply -CallbackState $state
}

function Get-WelaRegistryState {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        return [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Value = $null; Type = $null }
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ KeyExists = $true; ValueExists = $false; Value = $null; Type = $null }
    }
    [pscustomobject]@{
        KeyExists = $true; ValueExists = $true
        Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        Type = $key.GetValueKind($Name).ToString()
    }
}

function New-WelaRegistryKey {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -ErrorAction Stop) { return }
    $separator = $Path.TrimEnd('\').LastIndexOf('\')
    if ($separator -lt 1) { throw "Registry root is unavailable: $Path" }
    $parent = $Path.Substring(0, $separator)
    # Registry New-Item without Force requires its immediate parent. Build only
    # missing ancestors; never run New-Item -Force against an existing key.
    New-WelaRegistryKey -Path $parent
    $null = New-Item -Path $Path -ErrorAction Stop
}

function Set-WelaRegistryControl {
    param($Context, [string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [scriptblock]$PreserveWhen)
    $state = @{ Path = $Path; Name = $Name; Value = $Value; Type = $Type; PreserveWhen = $PreserveWhen }
    $read = { param($state) Get-WelaRegistryState -Path $state.Path -Name $state.Name }
    $test = { param($value, $state) $value.ValueExists -and $value.Value -eq $state.Value -and $value.Type -eq $state.Type }
    $apply = {
        param($state)
        New-WelaRegistryKey -Path $state.Path
        if ($state.PreserveWhen) {
            # Recheck after the prompt and journal, immediately before the value write.
            $fresh = Get-WelaRegistryState -Path $state.Path -Name $state.Name
            $preserveReason = & $state.PreserveWhen $fresh
            if ($preserveReason) { throw "Refused registry write after state changed: $preserveReason" }
        }
        Set-ItemProperty -LiteralPath $state.Path -Name $state.Name -Value $state.Value -Type $state.Type -ErrorAction Stop
    }
    Invoke-WelaConfigurationControl -Context $Context -Id "Registry/$Path/$Name" -Kind Registry `
        -Target @{ Path = $Path; Name = $Name } -Desired @{ Value = $Value; Type = $Type } `
        -Read $read -Compliant $test -Apply $apply -PreserveWhen $PreserveWhen -CallbackState $state
}

function Initialize-WelaConfigurationAuditApi {
    if ('Wela.ConfigurationAuditApi' -as [type]) { return }
    # Querying the Windows API avoids localized auditpol /get CSV (six columns;
    # unlike /backup output, it has no numeric Setting Value column).
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Wela {
    public static class ConfigurationAuditApi {
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation {
            public Guid Subcategory;
            public UInt32 Information;
            public Guid Category;
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            [In] Guid[] subcategories, UInt32 count, out IntPtr policy);
        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);
        public static UInt32 Query(Guid subcategory) {
            IntPtr buffer = IntPtr.Zero;
            if (!AuditQuerySystemPolicy(new Guid[] { subcategory }, 1, out buffer)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                if (buffer == IntPtr.Zero) throw new InvalidOperationException("Audit policy query returned no buffer.");
                AuditPolicyInformation policy = (AuditPolicyInformation)Marshal.PtrToStructure(buffer, typeof(AuditPolicyInformation));
                if (policy.Subcategory != subcategory) throw new InvalidOperationException("Audit policy query returned a different subcategory.");
                return policy.Information;
            } finally {
                if (buffer != IntPtr.Zero) AuditFree(buffer);
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-WelaNativeAuditPolicy {
    param([string]$Guid)
    Initialize-WelaConfigurationAuditApi
    return [Wela.ConfigurationAuditApi]::Query([guid]$Guid)
}

function Get-WelaAuditPolicyMask {
    param([string]$Guid)
    $flags = Get-WelaNativeAuditPolicy -Guid $Guid
    if ($flags -notin @(0, 1, 2, 3, 4)) { throw "Unexpected audit policy flags $flags for $Guid." }
    # POLICY_AUDIT_EVENT_NONE is 4; the success/failure mask is zero.
    return [int]($flags -band 3)
}

function Set-WelaAuditPolicyControl {
    param($Context, $Policy, [ValidateRange(0, 3)][int]$Mask = 3,
          [ValidateSet('exact', 'minimum')][string]$Mode = 'exact', [switch]$RequirePrecedence)
    $guid = $Policy.GUID
    $state = @{ Guid = $guid; Mask = $Mask; Mode = $Mode; RequirePrecedence = [bool]$RequirePrecedence }
    $read = { param($state) Get-WelaAuditPolicyMask -Guid $state.Guid }
    $test = {
        param($value, $state)
        if ($state.Mode -eq 'minimum') { return ($value -band $state.Mask) -eq $state.Mask }
        return $value -eq $state.Mask
    }
    $apply = {
        param($state)
        if ($state.RequirePrecedence) {
            $precedence = Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
            if (-not $precedence.ValueExists -or $precedence.Type -ne 'DWord' -or $precedence.Value -ne 1) {
                throw 'Audit precedence changed before the write; subcategory policy was not changed.'
            }
        }
        $arguments = @('/set', "/subcategory:{$($state.Guid)}")
        if ($state.Mode -eq 'minimum') {
            # Only enable required flags: never disable another writer's added flag.
            if ($state.Mask -band 1) { $arguments += '/success:enable' }
            if ($state.Mask -band 2) { $arguments += '/failure:enable' }
        } else {
            $success = if ($state.Mask -band 1) { 'enable' } else { 'disable' }
            $failure = if ($state.Mask -band 2) { 'enable' } else { 'disable' }
            $arguments += "/success:$success", "/failure:$failure"
        }
        Invoke-WelaNative -FilePath 'auditpol.exe' -Arguments $arguments
    }
    Invoke-WelaConfigurationControl -Context $Context -Id "AuditPolicy/$($Policy.Name)" -Kind AuditPolicy `
        -Target @{ Guid = $guid } -Desired @{ Mask = $Mask; Mode = $Mode } -Read $read -Compliant $test -Apply $apply -CallbackState $state
}

function Set-WelaProfileAuditControls {
    param($Context, $Plan)
    if ($Plan.PSObject.Properties['CustomProfileSource']) {
        $Context | Add-Member NoteProperty CustomProfileGuard ([pscustomobject]@{Source=$Plan.CustomProfileSource;Role=$Plan.role;Build=$Plan.build}) -Force
        Assert-WelaConfigurationProfileGuard $Context
    }
    # The caller must complete Assert-WelaAuditProfileTarget before any mutations.
    $selected = @($Plan.policies | Where-Object { $_.mode -in @('exact', 'minimum') -or ($_.mode -eq 'optional' -and $Plan.includeOptional) })
    if ($selected.Count -eq 0) { return }
    Set-WelaAuditPrecedenceControl -Context $Context
    $precedence = $Context.Results[$Context.Results.Count - 1]
    foreach ($policy in $Plan.policies) {
        if ($policy.mode -notin @('exact', 'minimum') -and -not ($policy.mode -eq 'optional' -and $Plan.includeOptional)) { continue }
        if ($precedence.Status -eq 'Failed' -or ($precedence.Status -eq 'Skipped' -and -not $Context.DryRun)) {
            $Context.Results.Add([pscustomobject]@{ Id = "AuditPolicy/$($policy.id)"; Kind = 'AuditPolicy'; Target = @{ Guid = $policy.guid }; Desired = $policy.requiredMask; Before = $null; After = $null; Status = 'Skipped'; Diagnostic = 'Audit precedence was not verified; dependent policy was not changed.' })
            continue
        }
        $mode = if ($policy.mode -eq 'minimum') { 'minimum' } else { 'exact' }
        Set-WelaAuditPolicyControl -Context $Context -Policy @{ GUID = $policy.guid; Name = $policy.id } -Mask $policy.requiredMask -Mode $mode -RequirePrecedence
        $row = $Context.Results[$Context.Results.Count - 1]
        $row | Add-Member NoteProperty Profile $Plan.profile
        $row | Add-Member NoteProperty Version $Plan.version
        $row | Add-Member NoteProperty SchemaSha256 $Plan.schemaSha256
        $row | Add-Member NoteProperty Role $Plan.role
        $row | Add-Member NoteProperty Build $Plan.build
        $row | Add-Member NoteProperty Mode $policy.mode
        $row | Add-Member NoteProperty Prerequisites $policy.prerequisites
        $row | Add-Member NoteProperty Evidence $policy.evidence
        $row | Add-Member NoteProperty SourceIds $policy.sourceIds
        $row | Add-Member NoteProperty Note $policy.note
    }
}

function Get-WelaAuditPrecedenceSource {
    # Normalize each documented RSoP schema separately. Cached evidence does not
    # prove the current registry writer, even when the represented value is known.
    $targetKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $targetName = 'SCENoApplyLegacyAuditPolicy'
    $matches = @()
    foreach ($class in @('RSOP_RegistryPolicySetting', 'RSOP_SecuritySettingNumeric', 'RSOP_RegistryValue')) {
        try {
            $records = @(Get-CimInstance -Namespace 'root\RSOP\Computer' -ClassName $class -ErrorAction Stop)
            foreach ($record in $records) {
                $key = ''; $name = ''; $raw = $null; $reported = $null; $known = $false
                if ($class -eq 'RSOP_RegistryPolicySetting') {
                    if ($record.PSObject.Properties['deleted'] -and $record.deleted -eq $true) { continue }
                    if ($record.PSObject.Properties['registryKey']) { $key = [string]$record.registryKey }
                    if ($record.PSObject.Properties['valueName']) { $name = [string]$record.valueName }
                    if ($record.PSObject.Properties['value']) { $raw = $record.value }
                    # REG_DWORD is exactly four little-endian bytes. Other types,
                    # arrays and lengths remain unknown rather than being coerced.
                    if ($record.PSObject.Properties['valueType'] -and ($record.valueType -is [int] -or $record.valueType -is [uint32] -or $record.valueType -is [long]) -and $record.valueType -eq 4 -and $raw -is [byte[]] -and $raw.Length -eq 4) {
                        if ($raw[1] -eq 0 -and $raw[2] -eq 0 -and $raw[3] -eq 0 -and $raw[0] -in @(0, 1)) {
                            $reported = [uint32]$raw[0]; $known = $true
                        }
                    }
                } elseif ($class -eq 'RSOP_SecuritySettingNumeric') {
                    if ($record.PSObject.Properties['KeyName']) { $key = [string]$record.KeyName }
                    if ($record.PSObject.Properties['Setting']) { $raw = $record.Setting }
                    if (($raw -is [int] -or $raw -is [uint32] -or $raw -is [long]) -and $raw -in @(0, 1)) {
                        $reported = [uint32]$raw; $known = $true
                    }
                    # This security schema identifies settings by name; accept the
                    # exact policy name as well as a matching full registry path.
                    if ($key -eq $targetName) { $key = "$targetKey\$targetName" }
                } else {
                    if ($record.PSObject.Properties['Path']) { $key = [string]$record.Path }
                    if ($record.PSObject.Properties['Data']) { $raw = $record.Data }
                    # Security-option registry values expose Type/Data, not Value.
                    # Only canonical decimal strings 0/1 of REG_DWORD are decoded.
                    if ($record.PSObject.Properties['Type'] -and ($record.Type -is [int] -or $record.Type -is [uint32] -or $record.Type -is [long]) -and $record.Type -eq 4 -and $raw -is [string] -and $raw -cin @('0', '1')) {
                        $reported = [uint32]$raw; $known = $true
                    }
                }
                $key = $key -replace '^(MACHINE|HKEY_LOCAL_MACHINE|HKLM)\\', ''
                $matchingTarget = if ($class -eq 'RSOP_RegistryPolicySetting') { $key -eq $targetKey -and $name -eq $targetName } else { $key -eq "$targetKey\$targetName" }
                if (-not $matchingTarget) { continue }
                $matches += [pscustomobject]@{
                    SourceClass = $class
                    GpoId = $(if ($record.PSObject.Properties['GPOID']) { $record.GPOID } else { $null })
                    Precedence = $(if ($record.PSObject.Properties['precedence']) { $record.precedence } else { [uint32]::MaxValue })
                    ReportedValue = $(if ($known) { $reported } else { $raw })
                    ValueRecognized = $known
                }
            }
        } catch { }
    }
    $ordered = @($matches | Sort-Object Precedence)
    $policy = $ordered | Select-Object -First 1
    $gpo = if ($policy) { $policy.GpoId } else { $null }
    $value = if ($policy) { $policy.ReportedValue } else { $null }
    [pscustomobject]@{
        GpoId = $gpo; ReportedValue = $value
        SourceClass = $(if ($policy) { $policy.SourceClass } else { $null })
        ConflictsWithRequiredValue = if ($policy -and $policy.ValueRecognized) { $value -ne 1 } else { $null }
        Matches = $ordered
        Description = if ($gpo) { "Last-applied RSoP GPO evidence: $gpo (may be stale; current registry writer unknown; see Matches for all observations)" } else { 'Unknown (no matching RSoP source; local, GPO or MDM ownership is not established)' }
    }
}

function Get-WelaAuditPrecedenceState {
    param([switch]$Offline)
    $registry = $null; $status = 'Unknown'; $diagnostic = 'Offline plan; live precedence was not read.'
    $source = $null
    if (-not $Offline) {
        $source = Get-WelaAuditPrecedenceSource
        try {
            $registry = Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy
            $status = if (-not $registry.ValueExists) { 'Not configured' }
                      elseif ($registry.Type -ne 'DWord' -or $registry.Value -notin @(0, 1)) { 'Unknown' }
                      elseif ($registry.Value -eq 1) { 'Enabled' } else { 'Disabled' }
            $diagnostic = 'Observed registry state only; effective audit masks are read separately. GPO/MDM can change this value after verification.'
        } catch { $diagnostic = $_.ToString() }
    }
    [pscustomobject]@{ Name = 'SCENoApplyLegacyAuditPolicy'; RequiredValue = 1; RequiredType = 'DWord'; State = $status; Registry = $registry; PolicySource = $source; Diagnostic = $diagnostic }
}

function Set-WelaAuditPrecedenceControl {
    param($Context)
    Set-WelaRegistryControl -Context $Context -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1
    $row = $Context.Results[$Context.Results.Count - 1]
    $source = Get-WelaAuditPrecedenceSource
    $row | Add-Member NoteProperty PolicySource $source
    $row | Add-Member NoteProperty VerificationScope 'Current registry value and per-subcategory effective masks; no Group Policy refresh was performed.'
    if ($source.ConflictsWithRequiredValue) {
        $row.Diagnostic += ' Last-applied RSoP reports a different value; reconcile that GPO and verify again after policy refresh.'
        Write-Host $row.Diagnostic -ForegroundColor DarkYellow
    }
    Write-Host "Audit precedence policy source: $($source.Description)"
}

function Set-WelaCertificateAuditControl {
    param($Context)
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    try {
        if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) {
            $Context.Results.Add([pscustomobject]@{ Id = 'ADCS/AuditFilter'; Kind = 'CertificateService'; Target = $root; Desired = 127; Before = $null; After = $null; Status = 'Skipped'; Diagnostic = 'No configured local CA.' })
            return
        }
        $caName = (Get-ItemProperty -LiteralPath $root -Name Active -ErrorAction Stop).Active
        if (-not $caName) { throw 'CA configuration has no active CA name.' }
        $path = Join-Path $root $caName
        $state = @{ Path = $path }
        $read = {
            param($state)
            [pscustomobject]@{
                Registry = Get-WelaRegistryState -Path $state.Path -Name AuditFilter
                ServiceStatus = (Get-Service -Name CertSvc -ErrorAction Stop).Status.ToString()
            }
        }
        $test = { param($value) $value.Registry.ValueExists -and $value.Registry.Value -eq 127 -and $value.Registry.Type -eq 'DWord' -and $value.ServiceStatus -eq 'Running' }
        $apply = {
            $state = Get-Service -Name CertSvc -ErrorAction Stop
            if ($state.Status -ne 'Running') { throw 'CertSvc is not running; refusing to start a previously stopped CA. Start it deliberately before retrying.' }
            Invoke-WelaNative -FilePath 'certutil.exe' -Arguments @('-setreg', 'CA\AuditFilter', '127')
            Restart-Service -Name CertSvc -Force -ErrorAction Stop
            $service = Get-Service -Name CertSvc -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
        }
        Invoke-WelaConfigurationControl -Context $Context -Id 'ADCS/AuditFilter' -Kind CertificateService `
            -Target @{ Path = $path; Name = 'AuditFilter'; Service = 'CertSvc' } -Desired 127 `
            -Read $read -Compliant $test -Apply $apply -Description 'Set AuditFilter=127 and restart Certificate Services.' -CallbackState $state
    } catch {
        $Context.Results.Add([pscustomobject]@{ Id = 'ADCS/AuditFilter'; Kind = 'CertificateService'; Target = $root; Desired = 127; Before = $null; After = $null; Status = 'Failed'; Diagnostic = $_.ToString() })
    }
}

function Set-WelaNtlmConfigurationControl {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        $Context,
        [ValidateSet('Outgoing', 'Domain')][string]$Scope,
        [ValidateSet('PreserveOrAudit', 'Audit', 'Deny')][string]$Mode = 'PreserveOrAudit'
    )
    $path = if ($Scope -eq 'Outgoing') { 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' } else { 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' }
    $name = if ($Scope -eq 'Outgoing') { 'RestrictSendingNTLMTraffic' } else { 'AuditNTLMInDomain' }
    $desired = if ($Scope -eq 'Domain') { 7 } elseif ($Mode -eq 'Deny') { 2 } else { 1 }
    $id = "Registry/$path/$name"
    $state = $null
    $skipReason = ''
    $status = 'Skipped'
    try {
        $state = if ($Scope -eq 'Outgoing') { Get-WelaOutgoingNtlmState } else { Get-WelaDomainNtlmState }
        Write-Host "$Scope NTLM: $($state.Description)"
        if ($Scope -eq 'Outgoing') { Write-Host "Policy source: $($state.PolicySource)" }
        if ($Scope -eq 'Domain' -and -not $state.Applicable) {
            if ($state.Description -notlike 'Not applicable*') { throw "Domain NTLM applicability is unknown: $($state.Description)" }
            $skipReason = $state.Description
        } elseif (-not $state.Readable) {
            throw "$Scope NTLM current state could not be read: $($state.Description)"
        } elseif ($Scope -eq 'Outgoing' -and $Mode -eq 'PreserveOrAudit' -and $state.Type -eq 'DWord' -and $state.Value -eq 2) {
            $skipReason = 'Preserved existing Deny all enforcement (2); use -OutgoingNtlmMode Audit to explicitly replace it.'
        } elseif ($Scope -eq 'Outgoing' -and $Mode -eq 'PreserveOrAudit' -and $null -ne $state.Type -and ($state.Type -ne 'DWord' -or $state.Value -notin @(0, 1, 2))) {
            $skipReason = "Preserved unknown outgoing NTLM value/type ($($state.Value)/$($state.Type)); select an explicit mode after policy review."
        }
        if (-not $skipReason) {
            if ($Scope -eq 'Outgoing' -and $Mode -eq 'Deny') {
                Write-Warning 'Explicit Deny mode can break NTLM authentication. This is enforcement, not audit-only configuration.'
            }
            if (-not $PSCmdlet.ShouldProcess($id, "Set $Scope NTLM policy to $desired")) {
                $skipReason = 'ShouldProcess declined the NTLM change.'
            } else {
                # Shared runner owns prompts, dry-run suppression, exact registry
                # before-state journal, type/value read-back and final drift check.
                $preserve = $null
                if ($Scope -eq 'Outgoing' -and $Mode -eq 'PreserveOrAudit') {
                    $preserve = {
                        param($snapshot)
                        if ($snapshot.ValueExists -and $snapshot.Type -eq 'DWord' -and $snapshot.Value -eq 2) {
                            return 'Preserved newly observed Deny all enforcement (2); explicit Audit mode is required to replace it.'
                        }
                        if ($snapshot.ValueExists -and ($snapshot.Type -ne 'DWord' -or $snapshot.Value -notin @(0, 1, 2))) {
                            return "Preserved newly observed unknown outgoing NTLM value/type ($($snapshot.Value)/$($snapshot.Type))."
                        }
                    }
                }
                Set-WelaRegistryControl -Context $Context -Path $path -Name $name -Value $desired -PreserveWhen $preserve
                return
            }
        }
    } catch {
        $status = 'Failed'
        $skipReason = $_.ToString()
    }
    $Context.Results.Add([pscustomobject][ordered]@{
        Id = $id; Kind = 'Registry'; Target = @{ Path = $path; Name = $name }
        Desired = @{ Value = $desired; Type = 'DWord' }; Before = $state; After = $state
        Status = $status; Diagnostic = $skipReason
    })
    $color = if ($status -eq 'Failed') { 'Red' } else { 'Yellow' }
    Write-Host "[$status] $id $skipReason" -ForegroundColor $color
}
