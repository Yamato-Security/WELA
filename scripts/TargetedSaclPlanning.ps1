# Read-only companion planning for the existing configure-sacl targets.
# Never loads offline hives, enables privileges, changes audit policy or writes ACLs.
function Expand-WelaSaclProfilePath {
    param([string]$Path)
    foreach ($token in [regex]::Matches($Path, '%([^%]+)%')) {
        if ($token.Groups[1].Value -notin @('SystemDrive', 'SystemRoot', 'windir')) { throw 'Profile path contains a user-specific or unknown variable; operator values must not be substituted.' }
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not $expanded -or $expanded -match '%[^%]+%' -or $expanded -notmatch '^(?:[A-Za-z]:\\|\\\\)') { throw 'Profile path is empty, unresolved or not absolute.' }
    return $expanded
}

function Get-WelaSaclUserInventory {
    $users = New-Object 'System.Collections.Generic.List[object]'
    $diagnostics = New-Object 'System.Collections.Generic.List[string]'
    $loaded = @{}
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop)) {
            if ($key.PSChildName -match '^S-1-\d+(-\d+)+$') { $loaded[$key.PSChildName] = $true }
        }
    } catch { $diagnostics.Add("Loaded-hive inventory failed: $($_.Exception.Message)") }
    $profileRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $profileRoot -ErrorAction Stop)) {
            $sid = $key.PSChildName
            if ($sid -notmatch '^S-1-\d+(-\d+)+$') {
                $diagnostics.Add("Unresolved ProfileList entry: $sid (including backup/temporary profiles).")
                continue
            }
            $path = $null; $message = ''
            try {
                $profileKey = Get-Item -LiteralPath $key.PSPath -ErrorAction Stop
                $rawPath = [string]$profileKey.GetValue('ProfileImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $path = Expand-WelaSaclProfilePath $rawPath
            } catch {
                $path = $null; $message = "Profile path unavailable: $($_.Exception.Message)"
                $diagnostics.Add("$sid : $message")
            }
            $users.Add([pscustomobject]@{ Sid = $sid; ProfilePath = $path; HiveLoaded = $loaded.ContainsKey($sid); Diagnostic = $message })
            $loaded.Remove($sid)
        }
        $profileListKey = Get-Item -LiteralPath $profileRoot -ErrorAction Stop
        $default = Expand-WelaSaclProfilePath ([string]$profileListKey.GetValue('Default', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
        $users.Add([pscustomobject]@{ Sid = 'Default'; ProfilePath = $default; HiveLoaded = $false; Diagnostic = 'Future-user template; hive is not loaded by planning.' })
    } catch { $diagnostics.Add("Profile inventory incomplete: $($_.Exception.Message)") }
    foreach ($sid in $loaded.Keys) {
        $diagnostics.Add("Loaded hive $sid has no matching ProfileList entry; user file paths are unknown.")
        $users.Add([pscustomobject]@{ Sid = $sid; ProfilePath = $null; HiveLoaded = $true; Diagnostic = 'Loaded hive has no matching ProfileList entry; user file paths are unknown.' })
    }
    [pscustomobject]@{ Users = @($users.ToArray()); Diagnostics = @($diagnostics.ToArray()); Complete = ($diagnostics.Count -eq 0) }
}

function Resolve-WelaSaclUserFile {
    param($User, [string]$RelativePath)
    # Resolve another user's known folders only from that user's loaded hive.
    # Expanding the operator's APPDATA here would silently credit the wrong path.
    $RelativePath = $RelativePath.Replace('\\', '\')
    if (-not $User.HiveLoaded) { return [pscustomobject]@{ Path = $null; State = 'UnloadedHive'; Diagnostic = 'Known-folder redirection cannot be read without loading the user hive; no hive was loaded.' } }
    if (-not $User.ProfilePath) { return [pscustomobject]@{ Path = $null; State = 'UnresolvedUserPath'; Diagnostic = 'Profile path is unavailable.' } }
    try {
        # Match complete known-folder roots, not an arbitrary directory named
        # Startup. Keep the configured suffix rather than substituting an app.
        $parts = @($RelativePath -split '\\')
        if ($RelativePath -match '[<>:"/|?*\x00-\x1F]' -or $RelativePath -match '%[^%]+%' -or
            @($parts | Where-Object { -not $_ -or $_ -in @('.', '..') -or $_ -match '[ .]$' }).Count) {
            throw 'User target contains unsupported or ambiguous path components.'
        }
        $startupRoot = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        $appDataRoot = 'AppData\Roaming'
        if ($RelativePath -ieq $startupRoot) {
            $folder = 'Startup'; $suffix = ''
        } elseif ($RelativePath.StartsWith($startupRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $folder = 'Startup'; $suffix = $RelativePath.Substring($startupRoot.Length + 1)
        } elseif ($RelativePath.StartsWith($appDataRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $folder = 'AppData'; $suffix = $RelativePath.Substring($appDataRoot.Length + 1)
        } else { throw 'User target must be the Startup known folder or a child of the supported AppData\Roaming known-folder root.' }
        $keyPath = "Registry::HKEY_USERS\$($User.Sid)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
        # DoNotExpandEnvironmentNames is essential when reading another user's hive.
        $raw = [string]$key.GetValue($folder, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (-not $raw) { throw "Known-folder value '$folder' is absent." }
        $resolved = [regex]::Replace($raw, '(?i)%USERPROFILE%', [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $User.ProfilePath })
        if ($resolved -match '%[^%]+%' -or $resolved -notmatch '^(?:[A-Za-z]:\\|\\\\)') { throw 'Known-folder path contains unresolved user variables or is not absolute.' }
        if ($suffix) { $resolved = $resolved.TrimEnd('\') + '\' + $suffix }
        $expected = $User.ProfilePath.TrimEnd('\') + '\' + $RelativePath
        $state = if ($resolved -ine $expected) { 'Redirected' } else { 'Resolved' }
        [pscustomobject]@{ Path = $resolved; State = $state; Diagnostic = 'Resolved from this user hive; remote paths are reported without network access.' }
    } catch { [pscustomobject]@{ Path = $null; State = 'UnresolvedUserPath'; Diagnostic = $_.Exception.Message } }
}

function Get-WelaSaclTargetObservation {
    param([string]$Path, [string]$Kind)
    if (-not $Path -or $Path -match '%[^%]+%') { return [pscustomobject]@{ PathState = 'Unknown'; SaclReadState = 'Unknown'; Diagnostic = 'Target path is unresolved.' } }
    if ($Path.StartsWith('\\')) { return [pscustomobject]@{ PathState = 'RemoteNotInspected'; SaclReadState = 'Unknown'; Diagnostic = 'Network/redirected target requires assessment on the file server; planning does not authenticate to remote paths.' } }
    try {
        if ($Kind -eq 'FileSystem') {
            if ($Path -notmatch '^([A-Za-z]):\\') { return [pscustomobject]@{ PathState = 'Unknown'; SaclReadState = 'Unknown'; Diagnostic = 'Only absolute local drive paths are inspected.' } }
            $drive = Get-PSDrive -Name $Matches[1] -PSProvider FileSystem -ErrorAction Stop
            if ([string]$drive.DisplayRoot -like '\\*' -or [string]$drive.Root -like '\\*') {
                return [pscustomobject]@{ PathState = 'RemoteNotInspected'; SaclReadState = 'Unknown'; Diagnostic = 'Mapped network drive is not inspected; no target path access was attempted.' }
            }
            $parts = @($Path.Substring(3) -split '\\' | Where-Object { $_ -ne '' })
            if (@($parts | Where-Object { $_ -in @('.', '..') }).Count) { return [pscustomobject]@{ PathState = 'Unknown'; SaclReadState = 'Unknown'; Diagnostic = 'Dot segments require explicit path review before inspection.' } }
            $checked = $Path.Substring(0, 3)
            # Inspect each ancestor before resolving the next component. A leaf-only
            # check can follow a junction/symlink into a remote share first.
            for ($index = 0; $index -le $parts.Count; $index++) {
                $item = Get-Item -LiteralPath $checked -Force -ErrorAction Stop
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    return [pscustomobject]@{ PathState = 'ReparsePoint'; SaclReadState = 'Unknown'; Diagnostic = "Reparse component '$checked' requires separate assessment; descendants and SACL were not inspected." }
                }
                if ($index -lt $parts.Count) { $checked = $checked.TrimEnd('\') + '\' + $parts[$index] }
            }
        } else { $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    } catch {
        $state = if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { 'Missing' } else { 'Inaccessible' }
        return [pscustomobject]@{ PathState = $state; SaclReadState = 'Unknown'; Diagnostic = $_.Exception.Message }
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -Audit -ErrorAction Stop
        [pscustomobject]@{ PathState = 'Exists'; SaclReadState = 'Readable'; SaclProtected = $acl.AreAuditRulesProtected; Diagnostic = 'SACL can be read. ACE coverage, descendant inheritance and event generation have not been validated.' }
    } catch { [pscustomobject]@{ PathState = 'Exists'; SaclReadState = 'Inaccessible'; Diagnostic = $_.Exception.Message } }
}

function Get-WelaTargetedSaclPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AuditPlan,
        [ValidateSet('Plan', 'Skip')][string]$Mode = 'Plan',
        [switch]$Live,
        [string]$TargetsPath = (Join-Path $PSScriptRoot '../config/audit_sacl_targets.json')
    )
    $definitions = Get-Content -LiteralPath $TargetsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $policyRows = @($AuditPlan.policies | Where-Object { $_.id -in @('File System', 'Registry', 'Handle Manipulation') })
    $inventory = [pscustomobject]@{ Users = @(); Diagnostics = @('Offline plan: user identities, hives and redirected folders are unknown.'); Complete = $false }
    if ($Live -and $Mode -eq 'Plan') { $inventory = Get-WelaSaclUserInventory }
    $users = @($inventory.Users)
    if ($users.Count -eq 0) {
        $users = @([pscustomobject]@{ Sid = '<all-users>'; ProfilePath = '<profile>'; HiveLoaded = $false; Diagnostic = 'User inventory is unavailable; all-user coverage is unknown.' })
    }
    $targets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($section in @('registry', 'files', 'user_registry', 'user_files')) {
        $kind = if ($section -match 'registry') { 'Registry' } else { 'FileSystem' }
        $policyName = if ($kind -eq 'Registry') { 'Registry' } else { 'File System' }
        $policy = @($policyRows | Where-Object id -eq $policyName)[0]
        foreach ($target in @($definitions.$section)) {
            $instances = if ($section -like 'user_*') { $users } else { @([pscustomobject]@{ Sid = $null }) }
            foreach ($user in $instances) {
                $resolution = 'Resolved'; $detail = ''; $path = $null
                if ($section -eq 'user_registry') {
                    $path = "Registry::HKEY_USERS\$($user.Sid)\$(([string]$target.key).Replace('\\', '\'))"
                    if (-not $user.HiveLoaded) { $resolution = 'UnloadedHive'; $detail = 'User hive not loaded; planning never mounts NTUSER.DAT.' }
                } elseif ($section -eq 'user_files') {
                    $path = "$($user.ProfilePath)\$(([string]$target.relpath).Replace('\\', '\'))"
                    if ($Live -and $Mode -eq 'Plan') {
                        $resolved = Resolve-WelaSaclUserFile -User $user -RelativePath $target.relpath
                        $resolution = $resolved.State; $detail = $resolved.Diagnostic
                        if ($resolved.Path) { $path = $resolved.Path }
                    } else { $resolution = 'Unknown'; $detail = 'User folder redirection is unknown.' }
                } else {
                    $path = ([string]$target.path).Replace('\\', '\')
                    if ($Live) { $path = [Environment]::ExpandEnvironmentVariables($path) }
                }
                $observation = [pscustomobject]@{ PathState = 'Unknown'; SaclReadState = 'Unknown'; Diagnostic = $detail }
                if ($Mode -eq 'Skip') { $observation = [pscustomobject]@{ PathState = 'Skipped'; SaclReadState = 'Unknown'; Diagnostic = 'Operator skipped target assessment; telemetry prerequisite remains unverified.' } }
                elseif ($Live -and $resolution -in @('Resolved', 'Redirected')) { $observation = Get-WelaSaclTargetObservation -Path $path -Kind $kind }
                elseif ($Live) { $observation = [pscustomobject]@{ PathState = $resolution; SaclReadState = 'Unknown'; Diagnostic = $detail } }
                $selected = $policy.mode -in @('exact', 'minimum') -or ($policy.mode -eq 'optional' -and $AuditPlan.includeOptional)
                $gap = if ($Mode -eq 'Skip') { 'SACL assessment explicitly skipped.' }
                       elseif (-not $selected) { 'Profile leaves this object policy unchanged or optional; its effective setting and target SACL are still required.' }
                       elseif ($policy.requiredMask -eq 0) { 'Profile requests No Auditing for this object policy.' }
                       else { 'Object policy alone does not establish target SACL coverage; match a benign operation to actual Security event XML.' }
                $targets.Add([pscustomobject][ordered]@{
                    Origin = 'WELA existing targeted SACL definitions (companion targets, not a baseline requirement)'
                    Scope = $section; UserSid = if ($user) { $user.Sid } else { $null }; Path = $path; Kind = $kind
                    PrincipalSid = 'S-1-1-0'; AuditFlags = @('Success', 'Failure'); Rights = @($target.rights)
                    Inheritance = if ($target.inherit) { if ($kind -eq 'Registry') { 'ContainerInherit' } else { 'ContainerInherit, ObjectInherit (directories only)' } } else { 'None' }
                    Propagation = 'None'; Policy = $policyName; PolicyMode = $policy.mode; PolicySelected = [bool]$selected
                    RequiredPolicyMask = $policy.requiredMask; EffectivePolicyMask = $policy.currentMask
                    Resolution = $resolution; Observation = $observation; GenerationReadiness = 'Conditional'; TelemetryGap = $gap
                })
            }
        }
    }
    # Appendix B screenshots specify Authenticated Users / Success. Keep this
    # distinct from WELA's wider Everyone / Success+Failure companion targets.
    $wef = @($AuditPlan.provenance | Where-Object id -eq 'ms-wef').Count -gt 0
    if ($wef) {
        foreach ($name in @('Run', 'RunOnce')) {
            $original = @($targets | Where-Object { $_.Scope -eq 'registry' -and $_.Path -ieq "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\$name" })[0]
            $row = $original.PSObject.Copy()
            $row.Origin = 'Microsoft WEF Appendix B (screenshot audit entries only)'
            $row.PrincipalSid = 'S-1-5-11'; $row.AuditFlags = @('Success')
            $row.Rights = if ($name -eq 'Run') { @('SetValue', 'CreateSubKey') } else { @('SetValue', 'CreateSubKey', 'Delete') }
            $targets.Add($row)
        }
    }
    [pscustomobject][ordered]@{
        SchemaVersion = 1; Mode = $Mode; Scope = 'read-only-targeted-sacl-prerequisites'; LiveObservation = [bool]$Live
        DefinitionSha256 = (Get-FileHash -LiteralPath $TargetsPath -Algorithm SHA256).Hash
        ObjectPolicies = $policyRows; UserInventory = $inventory; Targets = @($targets.ToArray())
        GenerationReadiness = 'Conditional'; UsableRuleCredit = 0
        TelemetryGap = if ($Mode -eq 'Skip') { 'Target SACL assessment was explicitly skipped; object-policy success does not close this gap.' } else { 'Target SACL matching and benign Security event XML validation remain required. No Sigma uplift is claimed.' }
        Guidance = 'Read-only companion plan. Existing configure-sacl is a separate, broader opt-in workflow; it applies all WELA targets and its own three object policies, not the selected profile. Review its scope before use. No hives are loaded and no permissions are changed by this plan.'
        Sources = @(
            'https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection#appendix-b---recommended-minimum-registry-system-acl-policy',
            'https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding'
        )
    }
}
