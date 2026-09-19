# Optional Windows PowerShell 5.1 transcription. Text files, not EVTX coverage.
function Get-WelaTranscriptRegistryValue {
    param([ValidateSet('LocalMachine', 'CurrentUser')][string]$Hive = 'LocalMachine',
          [ValidateSet('Registry64', 'Registry32')][string]$View = 'Registry64',
          [string]$SubKey = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', [string]$Name)
    $base = $null; $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$Hive, [Microsoft.Win32.RegistryView]::$View)
        $key = $base.OpenSubKey($SubKey, $false)
        $exists = $null -ne $key -and $key.GetValueNames() -contains $Name
        [pscustomobject]@{ KeyExists = $null -ne $key; ValueExists = [bool]$exists;
            Value = $(if ($exists) { $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null });
            Type = $(if ($exists) { $key.GetValueKind($Name).ToString() } else { $null }) }
    } finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
}

function Set-WelaTranscriptRegistryValue {
    param([ValidateSet('EnableTranscripting', 'OutputDirectory')][string]$Name, $Value,
          [ValidateSet('DWord', 'String')][string]$Type)
    $base = $null; $key = $null
    try {
        # SOFTWARE\Policies is shared by Registry32/Registry64 on supported Windows.
        # Do not create a literal Wow6432Node policy subtree.
        $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Registry32 }
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $key = $base.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription')
        $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::$Type)
    } finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
}

function Get-WelaTranscriptCapability {
    $result = [pscustomobject]@{ Status = 'Unknown'; TargetEngine = 'Windows PowerShell 5.1'; EngineVersion = $null;
        WelaHostEdition = [string]$PSVersionTable.PSEdition; WelaHostVersion = $PSVersionTable.PSVersion.ToString(); Views = @(); Diagnostic = '' }
    try {
        if ($env:OS -ne 'Windows_NT') { throw 'This command requires Windows; PowerShell 7 on non-Windows cannot configure Windows PowerShell policy.' }
        $result.Views = if ([Environment]::Is64BitOperatingSystem) { @('Registry64', 'Registry32') } else { @('Registry32') }
        $engine = Get-WelaTranscriptRegistryValue -View $result.Views[0] -SubKey 'SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' -Name PowerShellVersion
        if (-not $engine.ValueExists -or $engine.Type -ne 'String' -or [string]$engine.Value -notmatch '^5\.1(?:\.|$)') { throw 'Installed Windows PowerShell 5.1 engine could not be confirmed from its registry version.' }
        $result.EngineVersion = [string]$engine.Value
        $executable = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf -ErrorAction Stop)) { throw 'Native Windows PowerShell executable is missing.' }
        $result.Status = 'Supported'
        $result.Diagnostic = 'Windows PowerShell 5.1 policy only. PowerShell 7 has separate policy/configuration; its sessions are not assessed or configured.'
    } catch { $result.Diagnostic = $_.Exception.Message }
    return $result
}

function Get-WelaTranscriptPolicy {
    param([string[]]$Views)
    foreach ($view in $Views) {
        $machine = [ordered]@{}; $user = [ordered]@{}
        foreach ($name in @('EnableTranscripting', 'OutputDirectory', 'EnableInvocationHeader')) {
            $machine[$name] = Get-WelaTranscriptRegistryValue -View $view -Name $name
            $user[$name] = Get-WelaTranscriptRegistryValue -Hive CurrentUser -View $view -Name $name
        }
        [pscustomobject]@{ View = $view; Machine = [pscustomobject]$machine; CurrentUser = [pscustomobject]$user }
    }
}

function Test-WelaTranscriptSharedPolicy {
    param([array]$Policy)
    if (-not $Policy.Count) { throw 'No registry view was observed.' }
    if ($Policy.Count -gt 1) {
        foreach ($hive in @('Machine', 'CurrentUser')) {
            foreach ($name in @('EnableTranscripting', 'OutputDirectory', 'EnableInvocationHeader')) {
                foreach ($field in @('KeyExists', 'ValueExists', 'Type', 'Value')) {
                    if ((ConvertTo-Json -InputObject $Policy[0].$hive.$name.$field -Compress) -cne
                        (ConvertTo-Json -InputObject $Policy[1].$hive.$name.$field -Compress)) { throw "Shared policy views differ: $hive/$name/$field. No architecture coverage is assumed." }
                }
            }
        }
    }
}

function Test-WelaTranscriptDirectoryPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[*?%\x00-\x1f]' -or
        $Path -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\:]+\\[^\\:]+(?:\\|$))' -or
        $Path -match '(?:^|\\)\.\.?($|\\)' -or $Path.Substring(2).Contains(':')) {
        throw 'Supply a literal absolute drive or UNC directory, without wildcards, environment variables, device paths, alternate streams or dot segments.'
    }
}

function Get-WelaTranscriptAclObservation {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access')
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $entries = @(); $risks = @(); $unknown = @()
    if ($null -eq $sd.DiscretionaryAcl) { $risks += 'Null DACL permits unrestricted access.' }
    elseif ($sd.DiscretionaryAcl.Count -eq 0) { $risks += 'Empty DACL permits no transcript writers.' }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback) { $unknown += 'Uninterpreted or conditional access ACE; authorization needs deployment review.'; continue }
        $sid = $ace.SecurityIdentifier.Value
        $mask = [int64]$ace.AccessMask; $flags = [int]$ace.AceFlags
        $entries += [pscustomobject]@{ Sid = $sid; RightsMask = $mask; AceFlags = $flags; Type = $ace.AceQualifier.ToString() }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        $broad = $sid -in @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-2', 'S-1-5-4')
        if (-not $broad) { continue }
        # Conservative grant inspection, not a token/group/deny-aware AccessCheck.
        # GenericRead/GenericAll and ReadData/ListDirectory expose transcript data/names.
        if ($mask -band 2415919105) { $risks += "Broad principal $sid has a read/list grant; other users' transcripts may be exposed." }
        # File-inheritable write/append, delete, change-permissions/owner, or generic write/all.
        if (($mask -band 1343029312) -or (($flags -band 1) -and ($mask -band 6))) {
            $risks += "Broad principal $sid has a modification grant; existing transcripts may be alterable."
        }
    }
    [pscustomobject]@{ Sddl = $sddl; Owner = [string]$sd.Owner; Entries = $entries; Risks = $risks; Unknown = $unknown;
        Assessment = 'Conservative ACL observations only; effective writer/collector access and authorized group membership require deployment validation.' }
}

function Get-WelaTranscriptDestination {
    param([string]$Path)
    $result = [pscustomobject]@{ RequestedPath = $Path; Path = $null; Status = 'Unknown'; ConfigureAllowed = $false;
        IsUnc = $Path.StartsWith('\\'); CreationTimeUtc = $null; Attributes = $null; Acl = $null;
        ShareAuthorization = 'NotApplicable'; WriterAuthorization = 'Unknown'; CollectorAuthorization = 'Unknown'; Diagnostic = '' }
    try {
        Test-WelaTranscriptDirectoryPath $Path
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item -isnot [IO.DirectoryInfo]) { throw 'Transcript destination must be an existing filesystem directory.' }
        $result.Path = $item.FullName
        $result.CreationTimeUtc = $item.CreationTimeUtc.ToString('o')
        $result.Attributes = [int]$item.Attributes
        # Refuse local or UNC path components that are observed reparse points.
        $ancestor = $item
        while ($null -ne $ancestor) {
            if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse-point destination component requires separate review: $($ancestor.FullName)." }
            $ancestor = $ancestor.Parent
        }
        $result.Acl = Get-WelaTranscriptAclObservation $result.Path
        if ($result.Acl.Risks.Count) { $result.Status = 'Blocked'; throw ($result.Acl.Risks -join ' ') }
        if ($result.Acl.Unknown.Count) { throw ($result.Acl.Unknown -join ' ') }
        $result.Status = 'Observed'; $result.ConfigureAllowed = $true
        $result.Diagnostic = 'Directory and DACL observed without identified broad access grants. This does not prove effective access, protected child files, append-only storage, retention or collection; review the deployment before Configure.'
        if ($result.IsUnc) {
            $result.ShareAuthorization = 'Unknown'
            $result.Diagnostic += ' UNC share permissions, remote identities and server-side quotas are not evaluated.'
        }
    } catch { $result.Diagnostic = $_.Exception.Message }
    return $result
}

function Get-WelaTranscriptState {
    param([string]$OutputDirectory)
    $capability = Get-WelaTranscriptCapability
    if ($capability.Status -ne 'Supported') { throw $capability.Diagnostic }
    $policy = @(Get-WelaTranscriptPolicy $capability.Views)
    Test-WelaTranscriptSharedPolicy $policy
    $observedPath = $OutputDirectory
    if (-not $observedPath -and $policy[0].Machine.OutputDirectory.ValueExists -and $policy[0].Machine.OutputDirectory.Type -eq 'String') {
        $observedPath = [string]$policy[0].Machine.OutputDirectory.Value
    }
    $destination = if ($observedPath) { Get-WelaTranscriptDestination $observedPath } else {
        [pscustomobject]@{ RequestedPath = $null; Path = $null; Status = 'Unknown'; ConfigureAllowed = $false;
            Diagnostic = 'No explicit machine output directory was observed; per-user defaults/current-user policy and destination authorization are not established.' }
    }
    [pscustomobject]@{ Capability = $capability; Policy = $policy; Destination = $destination;
        TranscriptGeneration = 'Unverified'; PowerShell7Sessions = 'NotAssessed'; Retention = 'Unknown'; Collection = 'Unknown' }
}

function Test-WelaTranscriptConfigured {
    param($Snapshot, [string]$OutputDirectory)
    if (-not $Snapshot.Destination.ConfigureAllowed) { return $false }
    foreach ($view in $Snapshot.Policy) {
        if (-not $view.Machine.EnableTranscripting.ValueExists -or $view.Machine.EnableTranscripting.Type -ne 'DWord' -or
            $view.Machine.EnableTranscripting.Value -ne 1 -or -not $view.Machine.OutputDirectory.ValueExists -or
            $view.Machine.OutputDirectory.Type -ne 'String' -or [string]$view.Machine.OutputDirectory.Value -cne $OutputDirectory) { return $false }
    }
    return $Snapshot.Policy.Count -gt 0
}

function Set-WelaTranscriptControl {
    param($Context, [string]$OutputDirectory)
    $state = @{ OutputDirectory = $OutputDirectory; Observed = $null; PreservedHeader = $null }
    $read = { param($state)
        $snapshot = Get-WelaTranscriptState $state.OutputDirectory
        if (-not $snapshot.Destination.ConfigureAllowed) { throw "Transcript destination cannot be configured: $($snapshot.Destination.Diagnostic)" }
        if ($null -ne $state.PreservedHeader -and
            ($snapshot.Policy[0].Machine.EnableInvocationHeader | Select-Object ValueExists, Type, Value | ConvertTo-Json -Compress) -cne $state.PreservedHeader) {
            throw 'Invocation-header preference changed during configuration; no header change was requested.'
        }
        $state.Observed = $snapshot
        return $snapshot
    }
    $test = { param($snapshot, $state) Test-WelaTranscriptConfigured $snapshot $state.OutputDirectory }
    $apply = { param($state)
        $before = $state.Observed
        $fresh = Get-WelaTranscriptState $state.OutputDirectory
        if (-not $fresh.Destination.ConfigureAllowed -or
            ($fresh.Policy | ConvertTo-Json -Depth 10 -Compress) -cne ($before.Policy | ConvertTo-Json -Depth 10 -Compress) -or
            ($fresh.Destination | ConvertTo-Json -Depth 10 -Compress) -cne ($before.Destination | ConvertTo-Json -Depth 10 -Compress)) {
            throw 'Policy or destination changed after the recovery snapshot; no write was sent. Review and retry.'
        }
        $state.PreservedHeader = $before.Policy[0].Machine.EnableInvocationHeader | Select-Object ValueExists, Type, Value | ConvertTo-Json -Compress
        # Establish the reviewed location before enabling new-session transcription.
        if (-not $before.Policy[0].Machine.OutputDirectory.ValueExists -or $before.Policy[0].Machine.OutputDirectory.Type -ne 'String' -or
            [string]$before.Policy[0].Machine.OutputDirectory.Value -cne $state.OutputDirectory) {
            Set-WelaTranscriptRegistryValue -Name OutputDirectory -Value $state.OutputDirectory -Type String
        }
        $location = Get-WelaTranscriptRegistryValue -View $before.Capability.Views[0] -Name OutputDirectory
        if (-not $location.ValueExists -or $location.Type -ne 'String' -or [string]$location.Value -cne $state.OutputDirectory) {
            throw 'OutputDirectory write did not verify; EnableTranscripting was not changed.'
        }
        if (-not $before.Policy[0].Machine.EnableTranscripting.ValueExists -or $before.Policy[0].Machine.EnableTranscripting.Type -ne 'DWord' -or
            $before.Policy[0].Machine.EnableTranscripting.Value -ne 1) {
            Set-WelaTranscriptRegistryValue -Name EnableTranscripting -Value 1 -Type DWord
        }
        'Windows PowerShell machine transcription policy written. New-session transcript generation, writer/collector authorization and collection remain unverified. No invocation-header, ACL, share, quota or retention setting was changed.'
    }
    Invoke-WelaConfigurationControl -Context $Context -Id 'PowerShellTranscription/CisV4L2' -Kind PowerShellTranscription `
        -Target @{ Hive = 'LocalMachine'; SubKey = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; OutputDirectory = $OutputDirectory } `
        -Desired @{ EnableTranscripting = @{ Type = 'DWord'; Value = 1 }; OutputDirectory = @{ Type = 'String'; Value = $OutputDirectory }; EnableInvocationHeader = 'Preserve' } `
        -Read $read -Compliant $test -Apply $apply -CallbackState $state `
        -Description 'Enable CIS Level 2 Windows PowerShell transcription using this explicitly reviewed destination. Transcript text can contain sensitive input/output.'
}

function Invoke-WelaTranscriptCommand {
    param([ValidateSet('Audit', 'Plan', 'Configure')][string]$Action = 'Audit', [string]$OutputDirectory,
          [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ($DryRun -and $Action -ne 'Configure') { throw 'DryRun applies only to transcription Configure.' }
    if ($Action -in @('Plan', 'Configure') -and -not $OutputDirectory) { throw 'Transcription Plan/Configure requires an explicit -TranscriptDirectory to review.' }
    if ($Action -eq 'Configure') {
        $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaTranscriptControl $context $OutputDirectory
        $report = Complete-WelaConfiguration -Context $context -Scope 'windows-powershell-transcription-policy-only' `
            -SuccessMessage 'Windows PowerShell transcription policy verified; transcript generation and destination authorization/collection remain separate checks.'
    } else {
        $snapshot = $null; $diagnostic = ''; $status = 'Unknown'
        try {
            $snapshot = Get-WelaTranscriptState $OutputDirectory
            $targetPath = if ($OutputDirectory) { $OutputDirectory } else { [string]$snapshot.Policy[0].Machine.OutputDirectory.Value }
            $status = if (-not $snapshot.Destination.ConfigureAllowed) { $snapshot.Destination.Status }
                elseif (Test-WelaTranscriptConfigured $snapshot $targetPath) { 'PolicyConfigured' } else { 'ChangeRequired' }
            $diagnostic = $snapshot.Destination.Diagnostic
        } catch { $diagnostic = $_.Exception.Message }
        $report = [pscustomobject]@{ Scope = 'windows-powershell-transcription-policy-only';
            ExitCode = $(if ($status -in @('Unknown', 'Blocked')) { 1 } else { 0 });
            Results = @([pscustomobject]@{ Status = $status; DesiredDirectory = $OutputDirectory; Before = $snapshot; Diagnostic = $diagnostic }) }
    }
    $report | Add-Member NoteProperty Action $Action
    $report | Add-Member NoteProperty Benchmark 'CIS Windows 11 Enterprise / Windows Server 2022 v4.0.0, 18.10.87.2, Level 2 only; this is not a complete CIS assessment.'
    $report | Add-Member NoteProperty VerificationScope 'Windows PowerShell 5.1 machine registry policy and destination observations only. Existing sessions, other identities, PowerShell 7 sessions, transcript generation, quota/retention and central collection are unverified.'
    $report | Add-Member NoteProperty Telemetry @{ Format = 'Text transcript files'; EventIds = @(); SigmaEvtxCredit = 0; RelationTo4103And4104 = 'Separate output; no automatic EVTX rule applicability or coverage uplift.' }
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    return $report
}
