# Native AppLocker observations and a deliberately narrow local audit-only import.
function ConvertFrom-WelaAppLockerXml {
    param([Parameter(Mandatory)][string]$Xml, [switch]$ForImport)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 10485760
    $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($Xml)), $settings)
    try {
        $doc = New-Object Xml.XmlDocument; $doc.XmlResolver = $null
        $doc.Load($reader)
    } finally { $reader.Dispose() }
    if ($doc.DocumentElement.LocalName -cne 'AppLockerPolicy' -or $doc.DocumentElement.NamespaceURI -or $doc.DocumentElement.GetAttribute('Version') -ne '1') { throw 'Expected unqualified AppLockerPolicy Version=1.' }
    $collections = New-Object 'System.Collections.Generic.List[object]'
    $types = @{}; $ids = @{}
    foreach ($node in @($doc.DocumentElement.ChildNodes | Where-Object NodeType -eq Element)) {
        if ($node.LocalName -ne 'RuleCollection') { throw "Unsupported AppLocker policy element: $($node.LocalName)" }
        $type = $node.GetAttribute('Type'); $mode = $node.GetAttribute('EnforcementMode')
        if ($type -notin @('Exe', 'Dll', 'Msi', 'Script', 'Appx') -or $types.ContainsKey($type)) { throw "Unknown/duplicate rule collection: $type" }
        if ($mode -notin @('Enabled', 'AuditOnly', 'NotConfigured')) { throw "Unknown enforcement mode: $mode" }
        $types[$type] = $true
        $rules = @($node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -in @('FilePathRule', 'FilePublisherRule', 'FileHashRule') })
        if ($ForImport) {
            if ($mode -ne 'AuditOnly' -or -not $rules.Count) { throw 'Every imported collection must explicitly be AuditOnly and contain rules.' }
            if (@($node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -notin @('FilePathRule', 'FilePublisherRule', 'FileHashRule') }).Count) { throw 'Policy extensions/unknown rule elements are not accepted for import.' }
            foreach ($rule in $rules) {
                $guid = [guid]::Empty
                if (-not [guid]::TryParse($rule.GetAttribute('Id'), [ref]$guid) -or $ids.ContainsKey($guid.ToString())) { throw 'Rule IDs must be valid and globally unique.' }
                $ids[$guid.ToString()] = $true
                if ($rule.GetAttribute('Action') -notin @('Allow', 'Deny') -or $rule.GetAttribute('UserOrGroupSid') -notmatch '^S-1-\d+(-\d+)+$' -or -not $rule.GetAttribute('Name')) { throw 'Invalid rule action, SID or name.' }
                if (@($rule.SelectNodes('./Conditions')).Count -ne 1 -or -not $rule.SelectSingleNode('./Conditions/*')) { throw 'Each rule must have conditions.' }
                # Reject hidden extension nodes and namespaces; Windows validates the
                # complete native rule schema before applying the prepared snapshot.
                if (@($rule.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -notin @('Conditions', 'Exceptions') }).Count) { throw 'Unknown rule child element.' }
            }
        }
        $collections.Add([pscustomobject]@{ Type=$type; EnforcementMode=$mode; RuleCount=$rules.Count; PotentialEnforcement=($mode -eq 'Enabled' -or ($mode -eq 'NotConfigured' -and $rules.Count -gt 0)); Xml=$node.OuterXml })
    }
    if ($ForImport -and -not $collections.Count) { throw 'An empty policy cannot supply AppLocker generation prerequisites.' }
    if ($ForImport -and @($doc.SelectNodes('//*') | Where-Object { $_.NamespaceURI -or @($_.Attributes | Where-Object { $_.NamespaceURI }).Count }).Count) { throw 'Namespaced policy elements/attributes are not accepted for import.' }
    [pscustomobject]@{ Xml=$doc.OuterXml; Collections=@($collections.ToArray()); TotalRules=(@($collections.ToArray() | Measure-Object RuleCount -Sum)[0].Sum); HasEnforcement=(@($collections.ToArray() | Where-Object PotentialEnforcement).Count -gt 0) }
}

function Get-WelaAppLockerHost {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property BuildNumber, ProductType, Caption -ErrorAction Stop
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -Property PartOfDomain -ErrorAction Stop
        if (-not $os -or $os.BuildNumber -notmatch '^\d+$' -or $null -eq $computer -or $computer.PartOfDomain -isnot [bool]) { throw 'Host applicability or management state is unknown.' }
        $eligible = ($os.ProductType -eq 1 -and [int]$os.BuildNumber -ge 22000) -or ($os.ProductType -eq 3 -and [int]$os.BuildNumber -ge 14393)
        $state = if ($eligible) { 'Candidate' } else { 'NotApplicable' }
        [pscustomobject]@{ Status=$state; Build=[int]$os.BuildNumber; ProductType=[int]$os.ProductType; Caption=[string]$os.Caption; PartOfDomain=$computer.PartOfDomain; Is64BitProcess=[Environment]::Is64BitProcess; Diagnostic='Native cmdlet/service observations determine capability; no edition-only inference. Import scope is local client/member server.' }
    } catch { [pscustomobject]@{ Status='Unknown'; Diagnostic=$_.Exception.Message } }
}

function Get-WelaAppLockerPolicySnapshot {
    param([ValidateSet('Local', 'Effective')][string]$Scope)
    try {
        if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Status='CmdletUnavailable'; Policy=$null; Diagnostic='Get-AppLockerPolicy is unavailable in this PowerShell session; capability is unverified.' } }
        $arguments = @{ Xml=$true; ErrorAction='Stop' }; $arguments[$Scope] = $true
        $xml = [string](Get-AppLockerPolicy @arguments)
        [pscustomobject]@{ Status='Observed'; Policy=(ConvertFrom-WelaAppLockerXml -Xml $xml); Diagnostic='GP policy only. AppLocker CSP policy is not visible to this cmdlet.' }
    } catch { [pscustomobject]@{ Status='Unknown'; Policy=$null; Diagnostic=$_.Exception.Message } }
}

function Get-WelaAppLockerService {
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction Stop
        if (-not $service) { return [pscustomobject]@{ Status='NotInstalled'; State=$null; StartMode=$null; Diagnostic='Application Identity service was not found.' } }
        [pscustomobject]@{ Status='Observed'; State=[string]$service.State; StartMode=[string]$service.StartMode; Diagnostic='Service state observed; no service changes were made.' }
    } catch { [pscustomobject]@{ Status='Unknown'; State=$null; StartMode=$null; Diagnostic=$_.Exception.Message } }
}

function Get-WelaAppLockerChannels {
    foreach ($name in @('EXE and DLL', 'MSI and Script', 'Packaged app-Execution', 'Packaged app-Deployment')) {
        $channel = "Microsoft-Windows-AppLocker/$name"
        try {
            $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
            if (-not $log -or $log.LogName -ne $channel) { throw 'Channel read did not return the requested channel.' }
            [pscustomobject]@{ Channel=$channel; Status='Observed'; Enabled=[bool]$log.IsEnabled; Diagnostic='Channel enablement is not proof of event generation.' }
        } catch {
            $state = if ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { 'NotInstalled' } else { 'Unknown' }
            [pscustomobject]@{ Channel=$channel; Status=$state; Enabled=$null; Diagnostic=$_.Exception.Message }
        }
    }
}

function Get-WelaAppLockerManagement {
    # These are blockers, not an assertion that CSP policy is absent. The native
    # cmdlets cannot read CSP; import is confined to apparently unmanaged hosts.
    try {
        $present = @()
        foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Enrollments', 'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers')) {
            if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                $present += @(Get-ChildItem -LiteralPath $path -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$' } | ForEach-Object { $_.Name })
            }
        }
        [pscustomobject]@{ Status='Observed'; ManagementEntries=$present; CspPolicyState='Unknown'; Diagnostic='No CSP policy completeness claim. Any observed enrollment/provider blocks local import.' }
    } catch { [pscustomobject]@{ Status='Unknown'; ManagementEntries=@(); CspPolicyState='Unknown'; Diagnostic=$_.Exception.Message } }
}

function Get-WelaAppLockerReadiness {
    $hostState = Get-WelaAppLockerHost
    $local = Get-WelaAppLockerPolicySnapshot Local; $effective = Get-WelaAppLockerPolicySnapshot Effective
    $service = Get-WelaAppLockerService; $channels = @(Get-WelaAppLockerChannels)
    $rows = foreach ($type in @('Exe', 'Dll', 'Msi', 'Script', 'Appx')) {
        $collection = @($effective.Policy.Collections | Where-Object Type -eq $type) | Select-Object -First 1
        $names = switch ($type) { 'Exe' { 'EXE and DLL' } 'Dll' { 'EXE and DLL' } 'Msi' { 'MSI and Script' } 'Script' { 'MSI and Script' } 'Appx' { 'Packaged app-Execution'; 'Packaged app-Deployment' } }
        $logs = @($channels | Where-Object { $_.Channel.Substring('Microsoft-Windows-AppLocker/'.Length) -in $names })
        $state = if ($hostState.Status -eq 'NotApplicable') { 'NotApplicable' }
            elseif ($hostState.Status -ne 'Candidate' -or $effective.Status -ne 'Observed' -or $service.Status -eq 'Unknown') { 'Unknown' }
            elseif (-not $collection -or $collection.RuleCount -eq 0) { 'MissingGpPolicy' }
            elseif ($service.Status -eq 'NotInstalled') { 'NotInstalled' }
            elseif ($service.StartMode -eq 'Disabled' -or $service.State -ne 'Running') { 'ServiceNotRunning' }
            elseif (@($logs | Where-Object Status -ne 'Observed').Count) { 'ChannelUnknown' }
            elseif (@($logs | Where-Object { -not $_.Enabled }).Count) { 'ChannelDisabled' }
            else { 'Conditional' }
        [pscustomobject]@{ Type=$type; EnforcementMode=if ($collection) {$collection.EnforcementMode} else {$null}; RuleCount=if ($collection) {$collection.RuleCount} else {0}; PotentialEnforcement=if ($collection) {$collection.PotentialEnforcement} else {$false}; PrerequisiteState=$state; Channels=$logs; GenerationReadiness='Unverified'; Diagnostic='Local/GP observations only; CSP policies and actual executable/script event XML require separate verification.' }
    }
    [pscustomobject]@{ Scope='native-applocker-readiness'; Host=$hostState; LocalPolicy=$local; EffectiveGpPolicy=$effective; Service=$service; Collections=@($rows); Management=(Get-WelaAppLockerManagement); CspPolicyState='Unknown'; UsableRuleCredit=0; GenerationReadiness='Unverified' }
}

function Get-WelaAppLockerXmlKey {
    param([string]$Xml)
    # Compare policy meaning without treating native XML formatting/attribute
    # ordering as a failed write. Rule IDs are unique, so rule order is immaterial.
    $document = New-Object Xml.XmlDocument; $document.XmlResolver=$null; $document.LoadXml($Xml)
    function Convert-WelaAppLockerNodeKey($Node) {
        $attributes = @($Node.Attributes | Where-Object { -not ($_.LocalName -eq 'Description' -and $_.Value -eq '') } | Sort-Object Name | ForEach-Object { @($_.Name, $_.Value) -join '=' })
        $children = @($Node.ChildNodes | Where-Object NodeType -eq Element | ForEach-Object { Convert-WelaAppLockerNodeKey $_ } | Sort-Object)
        # JSON arrays delimit values so attribute/condition text cannot collide.
        return ConvertTo-Json -InputObject @($Node.LocalName, $attributes, $children) -Depth 20 -Compress
    }
    Convert-WelaAppLockerNodeKey $document.DocumentElement
}

function Test-WelaAppLockerPolicyMatch {
    param($Snapshot, $Desired)
    if ($Snapshot.LocalPolicy.Status -ne 'Observed') { return $false }
    $current = $Snapshot.LocalPolicy.Policy
    if ($current.Collections.Count -ne $Desired.Collections.Count -or $current.HasEnforcement) { return $false }
    foreach ($wanted in $Desired.Collections) {
        $actual = @($current.Collections | Where-Object Type -eq $wanted.Type)
        if ($actual.Count -ne 1 -or (Get-WelaAppLockerXmlKey $actual[0].Xml) -cne (Get-WelaAppLockerXmlKey $wanted.Xml)) { return $false }
    }
    return $true
}

function Assert-WelaAppLockerImportSafe {
    param($Snapshot, $Desired)
    if ($Snapshot.Host.Status -ne 'Candidate' -or -not $Snapshot.Host.Is64BitProcess) { throw 'Local import requires a supported 64-bit Windows client/member-server session.' }
    if ($Snapshot.Host.PartOfDomain -or $Snapshot.Management.Status -ne 'Observed' -or @($Snapshot.Management.ManagementEntries).Count) { throw 'Local import is blocked on domain-joined, managed or unknown-management hosts. Deploy through the existing policy authority.' }
    if ($Snapshot.LocalPolicy.Status -ne 'Observed' -or $Snapshot.EffectiveGpPolicy.Status -ne 'Observed') { throw 'Both local and GP effective policies must be readable.' }
    if ($Snapshot.LocalPolicy.Policy.HasEnforcement -or $Snapshot.EffectiveGpPolicy.Policy.HasEnforcement) { throw 'Existing enforcement (including NotConfigured collections with rules) is preserved; audit-only import is blocked.' }
    if (Test-WelaAppLockerPolicyMatch -Snapshot $Snapshot -Desired $Desired) { return }
    if ($Snapshot.LocalPolicy.Policy.Collections.Count -or $Snapshot.EffectiveGpPolicy.Policy.Collections.Count) { throw 'Existing policy is preserved. Import only initializes an empty local/GP policy; it never replaces a configured policy.' }
}

function New-WelaAppLockerImportReadLock {
    param([string]$Path, [string]$Xml)
    # CreateNew refuses a pre-existing file/link in the backup directory. Native
    # readers generally require that the writer handle has already been closed.
    $writer = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Xml)
        $writer.Write($bytes, 0, $bytes.Length)
        $writer.Flush()
    } finally { $writer.Dispose() }
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
}

function Set-WelaAppLockerAuditPolicy {
    param($Context, $Desired)
    $state = @{ Desired=$Desired; Before=$null; Context=$Context }
    $read = { param($state) $snapshot = Get-WelaAppLockerReadiness; Assert-WelaAppLockerImportSafe $snapshot $state.Desired; $state.Before=$snapshot; return $snapshot }
    $test = { param($snapshot, $state) Test-WelaAppLockerPolicyMatch $snapshot $state.Desired }
    $apply = {
        param($state)
        $fresh = Get-WelaAppLockerReadiness
        Assert-WelaAppLockerImportSafe $fresh $state.Desired
        if ($fresh.LocalPolicy.Policy.Xml -cne $state.Before.LocalPolicy.Policy.Xml -or $fresh.EffectiveGpPolicy.Policy.Xml -cne $state.Before.EffectiveGpPolicy.Policy.Xml) { throw 'AppLocker policy changed after the recovery snapshot; no policy was imported.' }
        if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) { throw 'Set-AppLockerPolicy is unavailable in this session.' }
        # Import the validated in-memory snapshot, not a mutable operator source file.
        $path = Join-Path $state.Context.BackupPath 'appLocker-audit-import.xml'
        if (-not (Get-Command Test-AppLockerPolicy -ErrorAction SilentlyContinue)) { throw 'Test-AppLockerPolicy is unavailable; native schema validation is required before import.' }
        # Deny concurrent modification/deletion of the prepared XML while both
        # native cmdlets consume it; they need only read access.
        $lock = New-WelaAppLockerImportReadLock -Path $path -Xml $state.Desired.Xml
        try {
            # The file can be replaced between writer-close and read-lock-open.
            # Validate the locked bytes against the already reviewed snapshot,
            # since native schema validation alone also accepts enforcing XML.
            $expectedBytes = [Text.Encoding]::UTF8.GetBytes($state.Desired.Xml)
            if ($lock.Length -ne $expectedBytes.Length) { throw 'Prepared AppLocker XML changed before its read lock; no policy was imported.' }
            $hasher = [Security.Cryptography.SHA256]::Create()
            try {
                $expectedHash = [Convert]::ToBase64String($hasher.ComputeHash($expectedBytes))
                $actualHash = [Convert]::ToBase64String($hasher.ComputeHash($lock))
                if ($actualHash -cne $expectedHash) { throw 'Prepared AppLocker XML changed before its read lock; no policy was imported.' }
            } finally { $hasher.Dispose() }
            $validation = @(Test-AppLockerPolicy -XmlPolicy $path -Path "$env:SystemRoot\System32\cmd.exe" -User 'S-1-1-0' -ErrorAction Stop)
            if (-not $validation.Count) { throw 'Native policy validation returned no result; no policy was imported.' }
            $immediate = Get-WelaAppLockerReadiness
            Assert-WelaAppLockerImportSafe $immediate $state.Desired
            if ($immediate.LocalPolicy.Policy.Xml -cne $state.Before.LocalPolicy.Policy.Xml -or $immediate.EffectiveGpPolicy.Policy.Xml -cne $state.Before.EffectiveGpPolicy.Policy.Xml) { throw 'Policy changed during native validation; no policy was imported.' }
            Set-AppLockerPolicy -XmlPolicy $path -Merge -ErrorAction Stop
        } finally { $lock.Dispose() }
        'Audit-only local policy merged. Service, event generation, CSP state and future policy refresh are not configured or verified.'
    }
    Invoke-WelaConfigurationControl -Context $Context -Id 'AppLocker/LocalAuditOnlyPolicy' -Kind AppLocker -Target 'Local GPO' -Desired $Desired `
        -Read $read -Compliant $test -Apply $apply -CallbackState $state -Description 'Initialize empty local AppLocker policy from this operator-supplied audit-only XML; preserve existing policies.'
}

function Invoke-WelaAppLockerCommand {
    param([ValidateSet('Audit','Plan','Import')][string]$Action='Audit', [string]$PolicyPath, [switch]$Auto, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'AppLocker readiness requires Windows.' }
    if ($DryRun -and $Action -ne 'Import') { throw '-DryRun applies only to AppLockerAction Import.' }
    if ($Action -eq 'Import' -and -not $PolicyPath) { throw '-AppLockerPolicyPath is required for Import.' }
    $desired = $null
    if ($PolicyPath) { $desired = ConvertFrom-WelaAppLockerXml -Xml (Get-Content -LiteralPath $PolicyPath -Raw -ErrorAction Stop) -ForImport }
    if ($Action -eq 'Import') {
        $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
        Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
        $report = Complete-WelaConfiguration -Context $context -Scope 'native-windows-configuration' -SuccessMessage 'Requested local audit-only policy verified; AppLocker event generation remains unverified.'
        $report | Add-Member NoteProperty VerificationScope 'Local audit-only policy readback only; no service changes, CSP assessment, event-generation or forwarding verification.'
    } else {
        $assessment = Get-WelaAppLockerReadiness
        $blocker = $null
        if ($desired) { try { Assert-WelaAppLockerImportSafe $assessment $desired } catch { $blocker=$_.Exception.Message } }
        $report = [pscustomobject]@{ Scope='native-applocker-readiness'; Action=$Action; Assessment=$assessment; ProposedAuditPolicy=$desired; ImportBlocker=$blocker; ExitCode=0 }
        if ($assessment.Host.Status -eq 'Unknown' -or $assessment.LocalPolicy.Status -in @('Unknown','CmdletUnavailable') -or $assessment.EffectiveGpPolicy.Status -in @('Unknown','CmdletUnavailable')) { $report.ExitCode=1 }
    }
    if ($ResultsPath) {
        try { $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        catch { $report.ExitCode=1; Write-Host "[Failed] Writing AppLocker results: $_" -ForegroundColor Red }
    }
    return $report
}
