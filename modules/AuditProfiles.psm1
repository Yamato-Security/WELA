# Requires Windows PowerShell 5.1 or PowerShell 7. No Windows dependency for schema/planning.
Set-StrictMode -Version 2.0

function Get-WelaProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Import-WelaAuditProfiles {
    [CmdletBinding()]
    param([string]$Path = (Join-Path $PSScriptRoot '../config/audit_profiles.json'))
    $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($data.schemaVersion -ne 1) { throw 'Unsupported audit profile schema version.' }
    $roles = @('Client', 'MemberServer', 'DomainController', 'ADCS')
    $ids = @{}; $guids = @{}; $profileIds = @{}
    foreach ($policy in $data.catalog) {
        if (-not $policy.id -or $ids.ContainsKey($policy.id)) { throw "Duplicate or empty policy id: $($policy.id)" }
        if ($policy.guid -notmatch '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$' -or $guids.ContainsKey($policy.guid)) { throw "Invalid or duplicate GUID: $($policy.guid)" }
        if (@($policy.roles).Count -eq 0 -or @($policy.roles | Where-Object { $_ -notin $roles }).Count) { throw "Invalid policy roles: $($policy.id)" }
        $ids[$policy.id] = $true; $guids[$policy.guid] = $true
    }
    foreach ($profile in $data.profiles) {
        if (-not $profile.id -or $profileIds.ContainsKey($profile.id)) { throw "Duplicate or empty profile id: $($profile.id)" }
        $profileIds[$profile.id] = $true
        if ($profile.omitted -ne 'unchanged' -or $profile.scope -ne 'advanced-audit-policy-only' -or -not $profile.version) { throw "Invalid profile metadata: $($profile.id)" }
        if (@($profile.sourceIds).Count -eq 0) { throw "Missing profile provenance: $($profile.id)" }
        foreach ($source in $profile.sourceIds) {
            if (-not $data.sources.PSObject.Properties[$source]) { throw "Unknown profile source: $source" }
        }
        if (@($profile.appliesTo).Count -eq 0) { throw "Missing applicability: $($profile.id)" }
        foreach ($range in $profile.appliesTo) {
            if (@($range.roles).Count -eq 0 -or @($range.roles | Where-Object { $_ -notin $roles }).Count -or $range.minBuild -lt 0 -or $range.maxBuild -lt $range.minBuild) { throw "Invalid applicability: $($profile.id)" }
        }
        $sets = @($profile.controls)
        foreach ($override in $profile.roleOverrides.PSObject.Properties) {
            if ($override.Name -notin $roles) { throw "Unknown role override: $($override.Name)" }
            $sets += $override.Value
        }
        foreach ($set in $sets) {
            foreach ($property in $set.PSObject.Properties) {
                if (-not $ids.ContainsKey($property.Name)) { throw "Unknown audit policy: $($property.Name)" }
                $control = $property.Value
                foreach ($sourceId in @(Get-WelaProperty $control 'sourceIds' @())) {
                    if (-not $data.sources.PSObject.Properties[$sourceId]) { throw "Unknown control source: $sourceId" }
                }
                if ($control.mode -notin @('exact', 'minimum', 'unchanged', 'not-configured', 'optional', 'not-applicable')) { throw "Invalid mode: $($control.mode)" }
                $hasMask = $null -ne $control.PSObject.Properties['mask']
                if ($control.mode -in @('exact', 'minimum', 'optional')) {
                    if (-not $hasMask -or $control.mask -isnot [ValueType] -or $control.mask -is [bool] -or $control.mask -notin @(0, 1, 2, 3) -or [double]$control.mask -ne [int]$control.mask) { throw "Invalid mask: $($property.Name)" }
                } elseif ($hasMask) { throw "Non-setting mode cannot have a mask: $($property.Name)" }
            }
        }
    }
    return $data
}

function Format-WelaAuditMask {
    param($Mask)
    if ($null -eq $Mask) { return 'Unknown' }
    switch ([int]$Mask) { 0 { 'No Auditing' } 1 { 'Success' } 2 { 'Failure' } 3 { 'Success and Failure' } default { throw "Invalid mask: $Mask" } }
}

function Get-WelaAuditProfilePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][ValidateSet('Client', 'MemberServer', 'DomainController', 'ADCS')][string]$Role,
        [Parameter(Mandatory)][ValidateRange(1, 999999)][int]$Build,
        [hashtable]$Current = @{}, [switch]$IncludeOptional,
        [string]$Path = (Join-Path $PSScriptRoot '../config/audit_profiles.json')
    )
    $data = Import-WelaAuditProfiles -Path $Path
    $selected = @($data.profiles | Where-Object { $_.id -eq $Profile })
    if ($selected.Count -ne 1) { throw "Unknown audit profile '$Profile'. Use -Cmd profiles to list profiles." }
    $selected = $selected[0]
    $matches = @($selected.appliesTo | Where-Object { $Role -in $_.roles -and $Build -ge $_.minBuild -and $Build -le $_.maxBuild })
    if ($matches.Count -eq 0) { throw "Profile '$Profile' does not support role '$Role', build '$Build'." }
    foreach ($value in $Current.Values) {
        if ($null -ne $value -and ($value -is [bool] -or $value -notin @(0, 1, 2, 3))) { throw "Invalid effective audit mask: $value" }
    }
    $controls = @{}
    foreach ($property in $selected.controls.PSObject.Properties) { $controls[$property.Name] = $property.Value }
    $override = Get-WelaProperty $selected.roleOverrides $Role
    if ($override) { foreach ($property in $override.PSObject.Properties) { $controls[$property.Name] = $property.Value } }
    $rows = foreach ($policy in $data.catalog) {
        $control = $controls[$policy.id]
        $mode = if ($control) { $control.mode } else { 'unchanged' }
        if ($Role -notin $policy.roles) { $mode = 'not-applicable' }
        $mask = Get-WelaProperty $control 'mask'
        $currentMask = if ($Current.ContainsKey($policy.guid)) { $Current[$policy.guid] } else { $null }
        $desired = $null; $action = 'Preserve'; $compliance = 'Not assessed'
        if ($mode -eq 'not-applicable') { $action = 'Not applicable'; $mask = $null }
        elseif ($mode -eq 'optional' -and -not $IncludeOptional) { $action = 'Optional (not selected)' }
        elseif ($mode -in @('exact', 'minimum', 'optional')) {
            if ($null -eq $currentMask) { $action = 'Unknown'; $compliance = 'Unknown' }
            else {
                $desired = if ($mode -eq 'minimum') { [int]$currentMask -bor [int]$mask } else { [int]$mask }
                $action = if ($currentMask -eq $desired) { 'No change' } else { 'Set' }
                $compliance = if ($action -eq 'No change') { 'Compliant' } else { 'Drift' }
            }
        }
        [pscustomobject][ordered]@{
            id = $policy.id; guid = $policy.guid; category = $policy.category; mode = $mode
            requiredMask = $mask; currentMask = $currentMask; targetMask = $desired
            recommendation = if ($mode -in @('exact', 'minimum', 'optional')) { "$(Format-WelaAuditMask $mask) [$mode]" } else { $mode }
            action = $action; compliance = $compliance; prerequisites = $policy.prerequisites
            note = Get-WelaProperty $control 'note' ''; evidence = Get-WelaProperty $control 'evidence' ''
            sourceIds = @(@($selected.sourceIds) + @(Get-WelaProperty $control 'sourceIds' @()) | Select-Object -Unique)
        }
    }
    $sourceIds = @($rows | ForEach-Object { $_.sourceIds } | Select-Object -Unique)
    $sources = foreach ($id in $sourceIds) { [pscustomobject]@{ id = $id; source = $data.sources.$id } }
    [pscustomobject][ordered]@{
        schemaVersion = 1; profile = $selected.id; version = $selected.version
        scope = $selected.scope; role = $Role; build = $Build; includeOptional = [bool]$IncludeOptional
        referenceOnly = [bool](Get-WelaProperty $selected 'referenceOnly' $false)
        generatedUtc = [DateTime]::UtcNow.ToString('o'); schemaSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        note = Get-WelaProperty $selected 'note' ''; provenance = @($sources); policies = @($rows)
    }
}

function Get-WelaEffectiveAuditPolicy {
    [CmdletBinding()]
    param()
    # auditpol /get /r has localized text and no numeric mask column. Query the native API instead.
    if (-not ('Wela.AuditProfiles.NativePolicy' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Wela.AuditProfiles {
    public static class NativePolicy {
        [StructLayout(LayoutKind.Sequential)]
        private struct PolicyInformation {
            public Guid Subcategory;
            public UInt32 Information;
            public Guid Category;
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] Guid[] subcategories,
            UInt32 count, out IntPtr information);
        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);
        public static Dictionary<string, int> Read(Guid[] subcategories) {
            IntPtr buffer = IntPtr.Zero;
            try {
                if (!AuditQuerySystemPolicy(subcategories, (UInt32)subcategories.Length, out buffer))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "AuditQuerySystemPolicy failed");
                if (buffer == IntPtr.Zero) throw new InvalidOperationException("Audit policy API returned a null buffer.");
                int size = Marshal.SizeOf(typeof(PolicyInformation));
                var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < subcategories.Length; i++) {
                    var policy = (PolicyInformation)Marshal.PtrToStructure(IntPtr.Add(buffer, i * size), typeof(PolicyInformation));
                    // POLICY_AUDIT_EVENT_NONE = 4; success/failure are bits 1 and 2.
                    if (policy.Information > 4U) throw new InvalidOperationException("Unrecognized native audit flags.");
                    result.Add(policy.Subcategory.ToString().ToUpperInvariant(), (int)(policy.Information & 3U));
                }
                return result;
            } finally { if (buffer != IntPtr.Zero) AuditFree(buffer); }
        }
    }
}
'@ -ErrorAction Stop
    }
    $catalog = (Import-WelaAuditProfiles).catalog
    [guid[]]$guids = @($catalog | ForEach-Object { [guid]$_.guid })
    $native = [Wela.AuditProfiles.NativePolicy]::Read($guids)
    $current = @{}
    foreach ($policy in $catalog) {
        if (-not $native.ContainsKey($policy.guid)) { throw "Audit policy API omitted $($policy.id)." }
        $current[$policy.guid] = $native[$policy.guid]
    }
    return $current
}

function Set-WelaEffectiveAuditPolicy {
    param([ValidatePattern('^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$')][string]$Guid, [ValidateRange(0, 3)][int]$Mask)
    $success = if ($Mask -band 1) { 'enable' } else { 'disable' }
    $failure = if ($Mask -band 2) { 'enable' } else { 'disable' }
    $output = & auditpol.exe /set "/subcategory:{$Guid}" "/success:$success" "/failure:$failure" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed ($LASTEXITCODE): $($output -join ' ')" }
}

function Get-WelaHostContext {
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$os.ProductType -notin @(1, 2, 3) -or [int]$system.DomainRole -notin @(0, 1, 2, 3, 4, 5) -or [int]$os.BuildNumber -le 0) { throw 'Cannot determine a valid Windows role/build.' }
    if (([int]$os.ProductType -eq 1 -and [int]$system.DomainRole -notin @(0, 1)) -or
        ([int]$os.ProductType -eq 2 -and [int]$system.DomainRole -notin @(4, 5)) -or
        ([int]$os.ProductType -eq 3 -and [int]$system.DomainRole -notin @(2, 3))) { throw 'Windows ProductType and DomainRole disagree.' }
    $role = if ([int]$os.ProductType -eq 1) { 'Client' }
        elseif ([int]$system.DomainRole -in @(4, 5)) { 'DomainController' }
        elseif (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration') { 'ADCS' }
        else { 'MemberServer' }
    [pscustomobject]@{ Role = $role; Build = [int]$os.BuildNumber }
}

function Assert-WelaAuditProfileTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Current)
    if ($Plan.referenceOnly) { throw 'Windows defaults are a reference, not an apply/restore profile.' }
    if ($Context.Role -ne $Plan.role -or $Context.Build -ne $Plan.build) { throw 'Plan role/build does not match the actual Windows host.' }
    if ($Current -isnot [hashtable]) { throw 'Effective policy reader did not return a GUID-to-mask map.' }
    $selected = @($Plan.policies | Where-Object { $_.mode -in @('exact', 'minimum') -or ($_.mode -eq 'optional' -and $Plan.includeOptional) })
    foreach ($policy in $selected) {
        if (-not $Current.ContainsKey($policy.guid) -or $null -eq $Current[$policy.guid] -or $Current[$policy.guid] -notin @(0, 1, 2, 3)) { throw "Cannot apply with unknown current policy: $($policy.id). No policies changed." }
    }
}

function Invoke-WelaAuditProfilePlan {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Plan,
        [scriptblock]$ReadPolicy = { Get-WelaEffectiveAuditPolicy },
        [scriptblock]$WritePolicy = { param($Guid, $Mask) Set-WelaEffectiveAuditPolicy -Guid $Guid -Mask $Mask },
        [scriptblock]$ReadContext = { Get-WelaHostContext }
    )
    $hostContext = & $ReadContext
    $before = & $ReadPolicy
    Assert-WelaAuditProfileTarget -Plan $Plan -Context $hostContext -Current $before
    $selected = @($Plan.policies | Where-Object { $_.mode -in @('exact', 'minimum') -or ($_.mode -eq 'optional' -and $Plan.includeOptional) })
    $results = foreach ($policy in $selected) {
        $initial = $before[$policy.guid]; $effective = $initial; $errorText = $null
        $target = if ($policy.mode -eq 'minimum') { [int]$initial -bor [int]$policy.requiredMask } else { [int]$policy.requiredMask }
        $status = 'No change'
        if ($initial -ne $target) {
            if ($PSCmdlet.ShouldProcess($policy.id, "Set audit policy to $(Format-WelaAuditMask $target)")) {
                try {
                    & $WritePolicy $policy.guid $target | Out-Null
                    $verified = & $ReadPolicy
                    $effective = if ($verified.ContainsKey($policy.guid)) { $verified[$policy.guid] } else { $null }
                    if ($effective -ne $target) { throw 'Effective policy does not match the requested mask (GPO or command failure).' }
                    $status = 'Applied'
                } catch { $status = 'Failed'; $errorText = $_.Exception.Message; $effective = $null }
            } else { $status = 'Skipped' }
        }
        [pscustomobject]@{
            id = $policy.id; guid = $policy.guid; mode = $policy.mode
            beforeMask = $initial; targetMask = $target; effectiveMask = $effective; status = $status; error = $errorText
            prerequisites = $policy.prerequisites; evidence = $policy.evidence; sourceIds = @($policy.sourceIds)
        }
    }
    [pscustomobject]@{
        profile = $Plan.profile; version = $Plan.version; scope = $Plan.scope; role = $Plan.role; build = $Plan.build
        schemaSha256 = $Plan.schemaSha256; provenance = $Plan.provenance
        success = (@($results | Where-Object { $_.status -eq 'Failed' }).Count -eq 0)
        results = @($results)
    }
}

Export-ModuleMember -Function Import-WelaAuditProfiles, Format-WelaAuditMask, Get-WelaAuditProfilePlan, Get-WelaEffectiveAuditPolicy, Set-WelaEffectiveAuditPolicy, Get-WelaHostContext, Assert-WelaAuditProfileTarget, Invoke-WelaAuditProfilePlan
