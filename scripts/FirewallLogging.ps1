# Built-in firewall text logs only. Dot-sourced beside Configuration.ps1 (PowerShell 5.1+).
function ConvertTo-WelaFirewallLoggingSnapshot {
    param($Profile)
    foreach ($property in @('Name', 'LogAllowed', 'LogBlocked', 'LogMaxSizeKilobytes', 'LogFileName')) {
        if ($null -eq $Profile.$property) { throw "Firewall profile is missing $property." }
    }
    if ([string]$Profile.LogAllowed -notin @('True', 'False', 'NotConfigured') -or
        [string]$Profile.LogBlocked -notin @('True', 'False', 'NotConfigured')) {
        throw 'Unrecognized firewall logging switch value.'
    }
    $size = [uint64]$Profile.LogMaxSizeKilobytes
    [pscustomobject][ordered]@{
        Name = [string]$Profile.Name; LogAllowed = [string]$Profile.LogAllowed
        LogBlocked = [string]$Profile.LogBlocked; LogMaxSizeKilobytes = $size
        LogFileName = [string]$Profile.LogFileName; Enabled = [string]$Profile.Enabled
    }
}

function Test-WelaFirewallServiceAcl {
    param([array]$Rules, [string]$ServiceSid, [switch]$Directory)
    # Group deny ACEs cannot be discounted without the complete service token.
    if (@($Rules | Where-Object AccessControlType -eq Deny).Count) { return $false }
    $required = [int][Security.AccessControl.FileSystemRights]::Modify
    $selfRights = 0; $childRights = 0
    foreach ($rule in $Rules) {
        if ($rule.IdentityReference.Value -ne $ServiceSid -or $rule.AccessControlType -ne 'Allow') { continue }
        if (-not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
            $selfRights = $selfRights -bor [int]$rule.FileSystemRights
        }
        if ($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) {
            $childRights = $childRights -bor [int]$rule.FileSystemRights
        }
    }
    return ($selfRights -band $required) -eq $required -and (-not $Directory -or ($childRights -band $required) -eq $required)
}

function Get-WelaFirewallLogAccess {
    param([string]$Path)
    $result = [pscustomobject]@{ State = 'Unknown'; Path = $Path; Service = 'mpssvc'; ServiceAccount = $null; ServiceStatus = $null; Diagnostic = '' }
    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path)
        if ($expanded -notmatch '^[A-Za-z]:\\' -or $expanded -match '%' -or $expanded.Substring(2).Contains(':')) {
            throw 'Log path must resolve to an absolute local drive path without environment placeholders or alternate data streams.'
        }
        $result.Path = $expanded
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='mpssvc'" -ErrorAction Stop
        if (-not $service) { throw 'Firewall service could not be read.' }
        $result.ServiceAccount = [string]$service.StartName
        $result.ServiceStatus = [string]$service.State
        if ($service.StartName -notin @('NT AUTHORITY\LocalService', 'NT AUTHORITY\Local Service')) {
            throw 'Firewall service account differs from the documented LocalService configuration; effective token access is unknown.'
        }
        $sidType = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\mpssvc' -Name ServiceSidType -ErrorAction Stop).ServiceSidType
        if ($sidType -notin @(1, 3)) { throw 'Firewall service SID is not enabled; effective token access is unknown.' }
        $sid = (New-Object Security.Principal.NTAccount('NT SERVICE', 'mpssvc')).Translate([Security.Principal.SecurityIdentifier]).Value
        $parent = Split-Path -Path $expanded -Parent
        if (-not (Test-Path -LiteralPath $parent -PathType Container -ErrorAction Stop)) {
            $result.State = 'Blocked'; throw 'Log directory is missing. Provision its service permissions explicitly before configuring logging.'
        }
        # Never follow a directory junction to an unreviewed destination.
        $ancestor = $parent
        while ($ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point prevents a conservative ACL check: $ancestor" }
            $next = Split-Path -Path $ancestor -Parent
            if ($next -eq $ancestor) { break }
            $ancestor = $next
        }
        $paths = @([pscustomobject]@{ Path = $parent; Directory = $true })
        if (Test-Path -LiteralPath $expanded -ErrorAction Stop) {
            $file = Get-Item -LiteralPath $expanded -Force -ErrorAction Stop
            if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Log target is a directory or reparse point.' }
            $paths += [pscustomobject]@{ Path = $expanded; Directory = $false }
        }
        foreach ($target in $paths) {
            $acl = Get-Acl -LiteralPath $target.Path -ErrorAction Stop
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            if (-not (Test-WelaFirewallServiceAcl -Rules $rules -ServiceSid $sid -Directory:$target.Directory)) {
                throw "No unambiguous mpssvc Modify grant at $($target.Path), including directory file inheritance. Deny ACEs or group-based access require effective-token review."
            }
        }
        if ($service.State -ne 'Running') { $result.State = 'Blocked'; throw 'Firewall service is not running. WELA will not start it or change firewall enforcement.' }
        $result.State = 'VerifiedExplicitGrant'
        $result.Diagnostic = 'Static ACL check found mpssvc Modify rights on the directory and existing file, including file inheritance. Actual log creation and rotation still require traffic validation.'
    } catch { $result.Diagnostic = $_.Exception.Message }
    return $result
}

function Get-WelaFirewallLoggingState {
    param([ValidateSet('Domain', 'Private', 'Public')][string]$Name)
    $effectiveProfiles = @(Get-NetFirewallProfile -Name $Name -PolicyStore ActiveStore -ErrorAction Stop)
    $localProfiles = @(Get-NetFirewallProfile -Name $Name -PolicyStore PersistentStore -ErrorAction Stop)
    if ($effectiveProfiles.Count -ne 1 -or $localProfiles.Count -ne 1 -or $effectiveProfiles[0].Name -ne $Name -or $localProfiles[0].Name -ne $Name) {
        throw "Expected exactly one $Name profile from each firewall policy store."
    }
    $effective = ConvertTo-WelaFirewallLoggingSnapshot $effectiveProfiles[0]
    $local = ConvertTo-WelaFirewallLoggingSnapshot $localProfiles[0]
    $differences = @('LogAllowed', 'LogBlocked', 'LogMaxSizeKilobytes', 'LogFileName' | Where-Object { $effective.$_ -ne $local.$_ })
    [pscustomobject]@{
        Effective = $effective; Local = $local; DifferentFromLocal = $differences
        PolicySource = 'ActiveStore is resultant policy; PersistentStore is local policy. Differences can reflect GPO/MDM. The current policy writer and future persistence are not established.'
        Access = Get-WelaFirewallLogAccess -Path $effective.LogFileName
    }
}

function Get-WelaFirewallLoggingPlan {
    param([ValidateSet('Preserve', 'CisV4')][string]$PathMode = 'Preserve',
          [ValidateRange(16384, 32767)][int]$MinimumSizeKiB = 16384)
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $before = $null; $desired = $null
        try {
            $before = Get-WelaFirewallLoggingState -Name $name
            $path = if ($PathMode -eq 'CisV4') { '%SystemRoot%\System32\LogFiles\Firewall\' + $name.ToLowerInvariant() + 'fw.log' } else { $before.Effective.LogFileName }
            $desired = [pscustomobject]@{ LogAllowed = 'True'; LogBlocked = 'True'; MinimumSizeKiB = $MinimumSizeKiB; LogFileName = $path; PathMode = $PathMode }
            $access = if ($path -eq $before.Effective.LogFileName) { $before.Access } else { Get-WelaFirewallLogAccess -Path $path }
            $status = if ($access.State -ne 'VerifiedExplicitGrant') { $access.State }
                elseif (Test-WelaFirewallLoggingCompliance -Snapshot $before -Desired $desired) { 'Compliant' } else { 'ChangeRequired' }
            [pscustomobject]@{ Name = $name; Status = $status; Before = $before; Desired = $desired; TargetAccess = $access; Diagnostic = $access.Diagnostic }
        } catch {
            [pscustomobject]@{ Name = $name; Status = 'Unknown'; Before = $before; Desired = $desired; TargetAccess = $null; Diagnostic = $_.Exception.Message }
        }
    }
}

function Test-WelaFirewallLoggingCompliance {
    param($Snapshot, $Desired)
    $pathMatches = [Environment]::ExpandEnvironmentVariables($Snapshot.Effective.LogFileName) -eq [Environment]::ExpandEnvironmentVariables($Desired.LogFileName)
    return $Snapshot.Access.State -eq 'VerifiedExplicitGrant' -and $Snapshot.Effective.LogAllowed -eq 'True' -and
        $Snapshot.Effective.LogBlocked -eq 'True' -and $Snapshot.Effective.LogMaxSizeKilobytes -ge $Desired.MinimumSizeKiB -and $pathMatches
}

function Set-WelaFirewallLoggingControls {
    param($Context, [array]$Plan)
    foreach ($entry in $Plan) {
        $id = "FirewallTextLog/$($entry.Name)"
        if ($entry.Status -in @('Unknown', 'Blocked')) {
            $Context.Results.Add([pscustomobject]@{ Id = $id; Kind = 'FirewallTextLog'; Target = $entry.Name; Desired = $entry.Desired; Before = $entry.Before; After = $null; Status = 'Failed'; Diagnostic = "Logging prerequisite $($entry.Status): $($entry.Diagnostic)" })
            continue
        }
        $callback = @{ Name = $entry.Name; Desired = $entry.Desired; Observed = $null }
        $read = {
            param($state)
            $snapshot = Get-WelaFirewallLoggingState -Name $state.Name
            if ($state.Desired.PathMode -eq 'Preserve' -and
                [Environment]::ExpandEnvironmentVariables($snapshot.Effective.LogFileName) -ne [Environment]::ExpandEnvironmentVariables($state.Desired.LogFileName)) {
                throw 'Effective firewall log path changed after planning; rerun the plan to assess and preserve the current destination.'
            }
            $targetAccess = if ($state.Desired.PathMode -eq 'Preserve' -or $snapshot.Effective.LogFileName -eq $state.Desired.LogFileName) {
                $snapshot.Access
            } else { Get-WelaFirewallLogAccess -Path $state.Desired.LogFileName }
            if ($targetAccess.State -ne 'VerifiedExplicitGrant') { throw "Log path access is $($targetAccess.State): $($targetAccess.Diagnostic)" }
            $state.Observed = $snapshot
            return $snapshot
        }
        $test = { param($snapshot, $state) Test-WelaFirewallLoggingCompliance -Snapshot $snapshot -Desired $state.Desired }
        $apply = {
            param($state)
            # Refuse races after a prompt/journal rather than overwrite an operator's changes.
            $fresh = Get-WelaFirewallLoggingState -Name $state.Name
            foreach ($store in @('Effective', 'Local')) {
                foreach ($property in @('LogAllowed', 'LogBlocked', 'LogMaxSizeKilobytes', 'LogFileName')) {
                    if ($fresh.$store.$property -ne $state.Observed.$store.$property) { throw "Firewall $store $property changed after the recovery snapshot; retry after reviewing policy." }
                }
            }
            if ($state.Desired.PathMode -eq 'Preserve' -and $fresh.Access.State -ne 'VerifiedExplicitGrant') {
                throw "Effective log path access is $($fresh.Access.State): $($fresh.Access.Diagnostic)"
            }
            $targetPath = if ($state.Desired.PathMode -eq 'Preserve') { $fresh.Effective.LogFileName } else { $state.Desired.LogFileName }
            $access = Get-WelaFirewallLogAccess -Path $targetPath
            if ($access.State -ne 'VerifiedExplicitGrant') { throw "Log path access is $($access.State): $($access.Diagnostic)" }
            $size = [Math]::Max([double]$state.Desired.MinimumSizeKiB, [Math]::Max([double]$fresh.Effective.LogMaxSizeKilobytes, [double]$fresh.Local.LogMaxSizeKilobytes))
            $parameters = @{ Name = $state.Name; PolicyStore = 'PersistentStore'; LogAllowed = 'True'; LogBlocked = 'True'; LogMaxSizeKilobytes = [uint64]$size; ErrorAction = 'Stop' }
            if ($state.Desired.PathMode -eq 'CisV4') { $parameters.LogFileName = $state.Desired.LogFileName }
            Set-NetFirewallProfile @parameters
            'Local logging settings were written. Effective ActiveStore read-back follows; GPO/MDM may override local values now or later.'
        }
        Invoke-WelaConfigurationControl -Context $Context -Id $id -Kind FirewallTextLog -Target @{ Name = $entry.Name; PolicyStore = 'PersistentStore' } `
            -Desired $entry.Desired -Read $read -Compliant $test -Apply $apply -CallbackState $callback `
            -Description 'Enable allowed/dropped text logging and its minimum size; preserve enforcement and rules.'
    }
}

function Invoke-WelaFirewallLoggingCommand {
    param([ValidateSet('Audit', 'Plan', 'Configure')][string]$Action = 'Audit',
          [ValidateSet('Preserve', 'CisV4')][string]$PathMode = 'Preserve',
          [ValidateRange(16384, 32767)][int]$MinimumSizeKiB = 16384,
          [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($env:OS -ne 'Windows_NT') { throw 'Firewall text logging requires Windows and the NetSecurity module.' }
    if ($DryRun -and $Action -ne 'Configure') { throw '-DryRun applies only to FirewallAction Configure; Audit and Plan are read-only.' }
    $plan = @(Get-WelaFirewallLoggingPlan -PathMode $PathMode -MinimumSizeKiB $MinimumSizeKiB)
    if ($Action -eq 'Configure') {
        $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaFirewallLoggingControls -Context $context -Plan $plan
        return Complete-WelaConfiguration -Context $context -ResultsPath $ResultsPath -Scope 'firewall-text-logging-only'
    }
    $report = [pscustomobject]@{ Scope = 'firewall-text-logging-only'; Action = $Action; PathMode = $PathMode; MinimumSizeKiB = $MinimumSizeKiB; Profiles = $plan; ExitCode = $(if (@($plan | Where-Object Status -in @('Unknown', 'Blocked')).Count) { 1 } else { 0 }) }
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    return $report
}
