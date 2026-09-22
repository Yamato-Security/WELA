# Read-only local collector correlation. No subscription, policy, service or process changes.
function Assert-WelaEvtxObject {
    param($Value,[string[]]$Fields)
    if ($Value -isnot [pscustomobject] -or @($Value.PSObject.Properties).Count -ne $Fields.Count -or
        @($Value.PSObject.Properties.Name | Where-Object {$_ -cnotin $Fields}).Count) {throw 'Unexpected or incomplete EVTX evidence object.'}
}
function Get-WelaEvtxHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function ConvertFrom-WelaEvtxJson {
    param([string]$Text)
    # Reuse the merged strict JSON lexer/duplicate-key validator, without executing input.
    $null=& (Get-Module AuditProfiles -ErrorAction Stop) {param($value) ConvertFrom-WelaCustomProfileJson $value} $Text
    $arguments=@{InputObject=$Text;ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {$arguments.DateKind='String'}
    ConvertFrom-Json @arguments
}
function ConvertTo-WelaEvtxUtc {
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -ne [DateTimeKind]::Utc) {throw 'Expected an explicit UTC evidence timestamp.'}
        return [DateTimeOffset]$Value
    }
    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$') {throw 'Expected an explicit UTC evidence timestamp.'}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
}
function Resolve-WelaEvtxPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '[\x00-\x1f*?\[\]]') {throw 'EVTX evidence requires exact paths without wildcards or control characters.'}
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $full -match '^[\\/]{2}' -or $full.Substring([IO.Path]::GetPathRoot($full).Length).Contains(':')) {throw 'EVTX evidence requires ordinary local filesystem paths, without remote/device paths or streams.'}
    $full=[IO.Path]::GetFullPath($full);$ancestor=$full
    while ($ancestor) {
        $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction SilentlyContinue
        if ($item -and ([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint)) {throw 'EVTX evidence cannot traverse reparse points.'}
        $parent=[IO.Directory]::GetParent($ancestor);if (-not $parent) {break};$ancestor=$parent.FullName
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed) {throw 'EVTX evidence requires a local fixed drive.'}
    $full
}
function Get-WelaEvtxXmlKey {
    param($Node)
    # Namespace-aware semantic equality; attribute order/prefixes are not event data.
    $attributes=@($Node.Attributes | Where-Object {$_.NamespaceURI -ne 'http://www.w3.org/2000/xmlns/'} | Sort-Object NamespaceURI,LocalName | ForEach-Object {ConvertTo-Json -InputObject @($_.NamespaceURI,$_.LocalName,$_.Value) -Compress})
    $children=@();$text='';$hasElements=@($Node.ChildNodes|Where-Object NodeType -eq Element).Count -gt 0
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq 'Element') {$children+=Get-WelaEvtxXmlKey $child}
        elseif ($child.NodeType -in @('Text','CDATA','SignificantWhitespace')) {$text+=$child.Value}
        elseif ($child.NodeType -eq 'Whitespace') {if(-not $hasElements){$text+=$child.Value}}
        else {throw 'Unsupported event XML node.'}
    }
    ConvertTo-Json -InputObject @($Node.NamespaceURI,$Node.LocalName,$attributes,$text,$children) -Depth 30 -Compress
}
function Read-WelaEvtxEvent {
    param([string]$Xml)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=4194304
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
    try {$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.PreserveWhitespace=$true;$doc.Load($reader)} finally {$reader.Dispose()}
    $ns='http://schemas.microsoft.com/win/2004/08/events/event';$root=$doc.DocumentElement
    if ($root.LocalName -cne 'Event' -or $root.NamespaceURI -cne $ns -or @($root.Attributes|Where-Object NamespaceURI -ne 'http://www.w3.org/2000/xmlns/').Count) {throw 'Unknown event root or attributes.'}
    $parts=@{}
    foreach ($node in $root.ChildNodes) {
        if ($node.NodeType -in @('Whitespace')) {continue}
        if ($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns -or $node.LocalName -cnotin @('System','EventData','RenderingInfo') -or $parts.ContainsKey($node.LocalName)) {throw 'Only one System/EventData and optional RenderingInfo are supported.'}
        $parts[$node.LocalName]=$node
    }
    if (-not $parts.System -or -not $parts.EventData) {throw 'Original System and EventData are required.'}
    $system=@{}
    foreach ($node in $parts.System.ChildNodes) {
        if ($node.NodeType -eq 'Whitespace') {continue}
        if ($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns -or $system.ContainsKey($node.LocalName)) {throw 'Ambiguous event System data.'}
        $system[$node.LocalName]=$node
    }
    if ($system.Computer.InnerText -cnotmatch '^[\p{L}\p{N}][\p{L}\p{N}_.-]{0,254}$') {throw 'Unsupported source computer identity.'}
    $time=ConvertTo-WelaEvtxUtc $system.TimeCreated.GetAttribute('SystemTime')
    [pscustomobject]@{Key=((Get-WelaEvtxXmlKey $parts.System)+'|'+(Get-WelaEvtxXmlKey $parts.EventData));Computer=$system.Computer.InnerText;EventUtc=$time;RecordId=$system.EventRecordID.InnerText;RenderingInfoPresent=[bool]$parts.RenderingInfo}
}
function ConvertTo-WelaEvtxState {
    param($State)
    Assert-WelaEvtxObject $State @('capturedAtUtc','context','hostObservation','auditPolicies','auditPrecedence','commandLineCapture','securityChannelEnabled')
    Assert-WelaEvtxObject $State.context @('computer','role','build','patch','domainJoined','installedRoles')
    Assert-WelaEvtxObject $State.hostObservation @('Status','Build','UBR','Edition','ProductType','DomainRole','DomainJoined','Domain','Architecture','ProcessorArchitecture','InstalledRoles','RolesStatus','Diagnostic')
    foreach ($registry in @($State.auditPrecedence,$State.commandLineCapture)) {
        Assert-WelaEvtxObject $registry @('KeyExists','ValueExists','Value','Type')
        if ($registry.KeyExists -isnot [bool] -or -not $registry.KeyExists -or $registry.ValueExists -isnot [bool]) {throw 'Unknown registry prerequisite presence.'}
    }
    foreach ($value in @($State.context.build,$State.hostObservation.ProductType,$State.hostObservation.DomainRole)) {if ($value -isnot [int] -and $value -isnot [long]) {throw 'Mistyped source role/build identity.'}}
    if ($State.context.role -cnotin @('Client','MemberServer','DomainController','ADCS') -or $State.context.computer -cnotmatch '^[\p{L}\p{N}][\p{L}\p{N}_.-]{0,254}$') {throw 'Unknown source role or computer.'}
    $policies=@{};$catalog=(Import-WelaAuditProfiles).catalog
    foreach ($entry in $State.auditPolicies.PSObject.Properties) {
        if ($entry.Name -notin $catalog.guid -or ($entry.Value -isnot [int] -and $entry.Value -isnot [long]) -or $entry.Value -notin @(0,1,2,3)) {throw 'Unknown or mistyped native audit policy evidence.'}
        $policies[$entry.Name]=$entry.Value
    }
    if ($policies.Count -ne 59) {throw 'A complete 59-subcategory source snapshot is required.'}
    $State.auditPolicies=$policies
    Assert-WelaProbePrerequisites $State
    if (($State.context.role -eq 'Client' -and $State.context.build -notin @(22000,22621,22631,26100,26200)) -or
        ($State.context.role -ne 'Client' -and $State.context.build -notin @(20348,26100)) -or
        ($State.context.role -eq 'DomainController' -and $State.context.installedRoles -contains 'ADCS-Cert-Authority')) {throw 'Source role/build is outside the reviewed native probe scope.'}
    return $State
}
function Import-WelaEvtxProbe {
    param([Parameter(Mandatory)][string]$Path)
    $root=Resolve-WelaEvtxPath $Path
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Probe bundle directory is missing.'}
    $expected=@('manifest.json','before-state.json','process.json','event.xml','after-state.json')
    $items=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($items.Count -ne 5 -or @($items|Where-Object {$_.Name -cnotin $expected -or $_.PSIsContainer -or ([int]$_.Attributes -band [int][IO.FileAttributes]::ReparsePoint)}).Count) {throw 'Expected exactly five regular native probe files.'}
    $files=@{};$utf8=New-Object Text.UTF8Encoding($false,$true)
    foreach ($item in $items) {
        if ($item.Length -gt 4194304) {throw 'Probe artifact exceeds 4 MiB.'}
        $bytes=[IO.File]::ReadAllBytes($item.FullName)
        if ($bytes.Length -gt 4194304) {throw 'Probe artifact grew beyond 4 MiB.'}
        $files[$item.Name]=[pscustomobject]@{Name=$item.Name;Sha256=(Get-WelaEvtxHash $bytes);Text=$utf8.GetString($bytes).TrimStart([char]0xFEFF)}
    }
    $manifest=ConvertFrom-WelaEvtxJson $files['manifest.json'].Text
    Assert-WelaEvtxObject $manifest @('SchemaVersion','Kind','Probe','Action','Status','ExitCode','GeneratedUtc','PolicyChanges','ReadyRuleCredit','Scope','RequiredEvidence','BeforeState','AfterState','Process','Artifacts','Diagnostic','OutputPath')
    foreach ($name in @('SchemaVersion','ExitCode','PolicyChanges','ReadyRuleCredit')) {if ($manifest.$name -isnot [int] -and $manifest.$name -isnot [long]) {throw 'Mistyped probe status.'}}
    if ($manifest.SchemaVersion -ne 1 -or $manifest.Kind -cne 'WelaNativeProbeComponents' -or $manifest.Probe -cne 'security-4688-command-line-v1' -or $manifest.Action -cne 'Run' -or $manifest.Status -cne 'NativeEventObserved' -or $manifest.ExitCode -ne 0 -or $manifest.PolicyChanges -ne 0 -or $manifest.ReadyRuleCredit -ne 0 -or $manifest.Diagnostic -cne '' -or $manifest.Artifacts -isnot [array] -or $manifest.Artifacts.Count -ne 4) {throw 'Only successful native 4688 probe components are accepted; no readiness evidence is inferred.'}
    if ($manifest.Scope -isnot [string] -or [string]::IsNullOrWhiteSpace($manifest.Scope) -or $manifest.OutputPath -isnot [string] -or [string]::IsNullOrWhiteSpace($manifest.OutputPath) -or $manifest.RequiredEvidence -isnot [array] -or ($manifest.RequiredEvidence -join '|') -cne 'Reviewed complete rule and normalization|Backend ingestion|Translated query and successful query result') {throw 'Incomplete source scope or required-evidence metadata.'}
    $seen=@{}
    foreach ($entry in $manifest.Artifacts) {
        Assert-WelaEvtxObject $entry @('path','sha256')
        if ($entry.path -cnotin @('before-state.json','process.json','event.xml','after-state.json') -or $seen.ContainsKey($entry.path) -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $entry.sha256 -cne $files[$entry.path].Sha256) {throw 'Missing, duplicate or mismatched source artifact hash.'}
        $seen[$entry.path]=$true
    }
    $before=ConvertFrom-WelaEvtxJson $files['before-state.json'].Text
    $after=ConvertFrom-WelaEvtxJson $files['after-state.json'].Text
    $process=ConvertFrom-WelaEvtxJson $files['process.json'].Text
    foreach ($pair in @(@($before,$manifest.BeforeState),@($after,$manifest.AfterState),@($process,$manifest.Process))) {
        if ((ConvertTo-Json -InputObject $pair[0] -Depth 20 -Compress) -cne (ConvertTo-Json -InputObject $pair[1] -Depth 20 -Compress)) {throw 'Embedded source metadata differs from its hashed artifact.'}
    }
    $before=ConvertTo-WelaEvtxState $before;$after=ConvertTo-WelaEvtxState $after
    if ((Get-WelaProbeStateKey $before) -cne (Get-WelaProbeStateKey $after)) {throw 'Source context or prerequisites drifted.'}
    Assert-WelaEvtxObject $process @('ProcessId','ParentProcessId','Executable','Arguments','Marker','StartedUtc','CompletedUtc','ExitCode')
    foreach ($name in @('ProcessId','ParentProcessId')) {if (($process.$name -isnot [int] -and $process.$name -isnot [long]) -or $process.$name -lt 1 -or $process.$name -gt [uint32]::MaxValue) {throw 'Invalid probe process identity.'}}
    if (($process.ExitCode -isnot [int] -and $process.ExitCode -isnot [long]) -or $process.ExitCode -ne 0 -or $process.Marker -cnotmatch '^WELA_PROBE_[a-f0-9]{32}$' -or
        $process.Arguments -cne ('/d /c echo '+$process.Marker) -or $process.Executable -notmatch '^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1f]+\\)*System32\\cmd\.exe$') {throw 'Source must describe only the fixed native cmd.exe echo probe.'}
    $generated=ConvertTo-WelaEvtxUtc $manifest.GeneratedUtc;$began=ConvertTo-WelaEvtxUtc $before.capturedAtUtc
    $started=ConvertTo-WelaEvtxUtc $process.StartedUtc;$completed=ConvertTo-WelaEvtxUtc $process.CompletedUtc;$ended=ConvertTo-WelaEvtxUtc $after.capturedAtUtc
    if ($generated -gt $began -or $began -gt $started -or $started -gt $completed -or $completed -gt $ended) {throw 'Source evidence timestamps are out of order.'}
    if (-not (Test-WelaProbeEvent -Xml $files['event.xml'].Text -Process $process -State $before -EndUtc $ended.UtcDateTime)) {throw 'Source event does not match the fixed process and context.'}
    $event=Read-WelaEvtxEvent $files['event.xml'].Text
    [pscustomobject]@{Path=$root;Fingerprint=(@($files.Keys|Sort-Object|ForEach-Object {$_+'='+$files[$_].Sha256})-join ';');Manifest=$manifest;Files=$files;Event=$event}
}
function New-WelaEvtxOutput {
    param([string]$Path,[string]$SourcePath)
    $full=Resolve-WelaEvtxPath $Path
    $comparison=if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    if ($full.Equals($SourcePath,$comparison) -or $full.StartsWith($SourcePath.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar,$comparison)) {throw 'Output must be outside the source bundle.'}
    if (Test-Path -LiteralPath $full) {throw 'EVTX output must be a new directory; existing evidence is never overwritten.'}
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container)) {throw 'Output parent directory must already exist.'}
    $null=New-Item -ItemType Directory -Path $full -ErrorAction Stop
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
        foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    }
    $full
}
function Write-WelaEvtxArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaEvtxPath $Root
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);$path=Join-Path $Root $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush()} finally {$stream.Dispose()}
    $hash=Get-WelaEvtxHash $bytes
    if ($hash -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()) {throw 'EVTX artifact readback differs from the written bytes.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
function Get-WelaEvtxReader {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'EVTX evidence requires native 64-bit Windows.'}
    $hostState=Get-WelaDefaultContext
    if (-not (Test-WelaDefaultContextComplete $hostState)) {throw 'Complete reader host context is unavailable.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$reader=[pscustomobject]@{Sid=$identity.User.Value;Name=$identity.Name;AuthenticationType=$identity.AuthenticationType;ImpersonationLevel=[string]$identity.ImpersonationLevel;Groups=@($identity.Groups | ForEach-Object {$_.Value} | Sort-Object)}} finally {$identity.Dispose()}
    [pscustomobject]@{Computer=[Environment]::MachineName;HostKey=(Get-WelaDefaultContextKey $hostState);Reader=$reader}
}
function Get-WelaEvtxRecoverySources {
    $root=Split-Path $PSScriptRoot -Parent;$sources=[ordered]@{}
    foreach ($path in @('WELA.ps1','scripts/EvtxRecovery.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/NativeValidation.ps1','scripts/ControlApplicability.ps1','modules/AuditProfiles.psm1','config/audit_profiles.json')) {
        $sources[$path]=(Get-FileHash -LiteralPath (Join-Path $root $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Get-WelaEvtxRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Get-WelaEvtxRecoveryHost {
    # An archive reader does not need administrator-only installed-feature inventory.
    $hostState=Get-WelaChannelReadHost
    $consistent=($hostState.ProductType -eq 1 -and $hostState.DomainRole -in @(0,1)) -or
        ($hostState.ProductType -eq 2 -and $hostState.DomainRole -in @(4,5)) -or ($hostState.ProductType -eq 3 -and $hostState.DomainRole -in @(2,3))
    if (-not $consistent -or $hostState.DomainJoined -ne ($hostState.DomainRole -in @(1,3,4,5)) -or
        $hostState.UBR -isnot [int] -or $hostState.UBR -lt 0 -or [string]::IsNullOrWhiteSpace($hostState.Edition) -or [string]::IsNullOrWhiteSpace($hostState.Domain)) {throw 'Incomplete or conflicting actual archive-reader host context.'}
    $hostState
}
function Get-WelaEvtxRecoveryReader {
    # Reuse the source-bound native token statistics adapter, not the legacy
    # metadata-only reader used by event-measurement before output preparation.
    Get-WelaChannelReader
}
function Assert-WelaEvtxQueryStatus {
    param([string]$Path,[object[]]$LogStatus)
    if ($LogStatus.Count -ne 1 -or -not [string]::Equals($LogStatus[0].LogName,$Path,[StringComparison]::OrdinalIgnoreCase) -or $LogStatus[0].StatusCode -isnot [int]) {throw ('Native EVTX query status is incomplete, mismatched or mistyped: '+(ConvertTo-Json -InputObject $LogStatus -Compress))}
    if ($LogStatus[0].StatusCode -ne 0) {throw [ComponentModel.Win32Exception]::new($LogStatus[0].StatusCode)}
}
function Read-WelaEvtxNative {
    param([string]$Path,[switch]$Live,[string]$Query='*')
    $kind=if ($Live) {[System.Diagnostics.Eventing.Reader.PathType]::LogName} else {[System.Diagnostics.Eventing.Reader.PathType]::FilePath}
    $request=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Path,$kind,$Query)
    $request.TolerateQueryErrors=$false
    $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($request);$reader.BatchSize=2
    $events=New-Object 'System.Collections.Generic.List[string]'
    try {
        # Read every exported record, up to two: this probe archive must contain exactly one.
        for ($i=0;$i -lt 2;$i++) {
            $record=$reader.ReadEvent([timespan]::FromSeconds(5))
            if ($null -eq $record) {break}
            try {$xml=$record.ToXml();if ([Text.Encoding]::UTF8.GetByteCount($xml) -gt 4194304) {throw 'Recovered event XML exceeds the four MiB bound.'};$events.Add($xml)} finally {$record.Dispose()}
        }
        $status=@($reader.LogStatus|ForEach-Object {[pscustomobject]@{LogName=$_.LogName;StatusCode=$_.StatusCode}})
        Assert-WelaEvtxQueryStatus -Path $Path -LogStatus $status
        return [pscustomobject]@{Xml=@($events.ToArray());Limit=2;LogStatus=$status}
    } finally {$reader.Dispose()}
}
function Export-WelaEvtxNative {
    param([string]$Query,[string]$Path)
    if (Test-Path -LiteralPath $Path) {throw 'EVTX export never overwrites an existing file.'}
    $session=New-Object System.Diagnostics.Eventing.Reader.EventLogSession
    try {$session.ExportLog('Security',[System.Diagnostics.Eventing.Reader.PathType]::LogName,$Query,$Path,$false)} finally {$session.Dispose()}
}
function Assert-WelaEvtxSingleEvent {
    param($Batch,$Source)
    if (@($Batch.Xml).Count -ne 1) {throw 'Expected exactly one recovered native event; empty or multiple records are unverified.'}
    if ((Read-WelaEvtxEvent $Batch.Xml[0]).Key -cne $Source.Event.Key) {throw 'Recovered event differs from the original source event.'}
}
function Invoke-WelaEvtxRecovery {
    param([ValidateSet('Export','Verify')][string]$Action='Verify',[Parameter(Mandatory)][string]$ProbePath,[string]$ArchivePath,[Parameter(Mandatory)][string]$OutputPath)
    $ErrorActionPreference='Stop'
    if (($Action -eq 'Export' -and $ArchivePath) -or ($Action -eq 'Verify' -and -not $ArchivePath)) {throw 'Export creates probe.evtx in a new output directory; Verify requires ArchivePath.'}
    $sources=Get-WelaEvtxRecoverySources;$sourceKey=Get-WelaEvtxRecoveryKey $sources
    $source=Import-WelaEvtxProbe $ProbePath
    if ($Action -eq 'Verify') {
        $archive=Resolve-WelaEvtxPath $ArchivePath
        $file=Get-Item -LiteralPath $archive -ErrorAction Stop
        if ($file -isnot [IO.FileInfo] -or $file.Extension -ine '.evtx' -or $file.Length -lt 1 -or $file.Length -gt 16777216) {throw 'Expected a local .evtx probe archive of 1 byte..16 MiB.'}
    }
    $output=New-WelaEvtxOutput $OutputPath $source.Path
    if ($Action -eq 'Export') {$archive=Join-Path $output 'probe.evtx'}
    $report=[pscustomobject][ordered]@{Kind='WelaNativeEvtxRecovery';SchemaVersion=2;Action=$Action;Status='Unverified';ExitCode=1;StartedUtc=[datetime]::UtcNow.ToString('o');CompletedUtc=$null;SourceBundlePath=$source.Path;SourceFingerprint=$source.Fingerprint;SourceComputer=$source.Event.Computer;ArchivePath=$archive;ArchiveSha256=$null;ArchiveBytes=$null;ReaderHostBefore=$null;ReaderHostAfter=$null;ReaderBefore=$null;ReaderAfter=$null;ReaderStable=$false;ReaderInterval='After output/source preparation, immediately before event access through archive hashing/native query and source-file verification; final host/policy inventory is outside this token interval.';Sources=$sources;FileReadAccess='NotAttempted';NativeQuery='NotAttempted';NativeLogStatus=@();FailureStage=$null;NativeError=$null;ExportQuery=$null;RecoveredEvents=0;Artifacts=@();Diagnostic='';OutputPath=$output;ReadyRuleCredit=0;PolicyChanges=0;Scope='Actual primary-token access to one exact local EVTX probe at observation time. Source producer and archive reader are distinct identities. No archive completeness, duration, other-principal access or Sigma readiness claim.'}
    $lock=$null;$stage='Preparation';$beforeKey=$null
    try {
        $report.ReaderHostBefore=Get-WelaEvtxRecoveryHost;$hostKey=Get-WelaEvtxRecoveryKey $report.ReaderHostBefore
        $report.Artifacts+=Write-WelaEvtxArtifact $output 'source-event.xml' $source.Files['event.xml'].Text
        if ($Action -eq 'Export') {
            $expected=ConvertTo-WelaEvtxState $source.Manifest.BeforeState
            $current=Get-WelaProbeState
            Assert-WelaProbePrerequisites $current
            if ((Get-WelaProbeStateKey $current) -cne (Get-WelaProbeStateKey $expected)) {throw 'Live source host or prerequisites differ from the validated probe context.'}
            if ($source.Event.RecordId -cnotmatch '^[1-9][0-9]{0,18}$') {throw 'Native source record ID must be a positive bounded decimal.'}
            $number=[long]::Parse($source.Event.RecordId,[Globalization.CultureInfo]::InvariantCulture)
            $query="*[System[EventRecordID=$number and EventID=4688 and Provider[@Name='Microsoft-Windows-Security-Auditing']]]"
            $report.ExportQuery=$query
        }
        # ACL setup and native audit-policy preparation can temporarily adjust
        # privileges. Capture the primary token after that work, before event I/O.
        $before=Get-WelaEvtxRecoveryReader;$report.ReaderBefore=$before;$beforeKey=Get-WelaEvtxRecoveryKey $before
        if ($Action -eq 'Export') {
            $stage='LiveSourceQuery'
            Assert-WelaEvtxSingleEvent (Read-WelaEvtxNative -Path Security -Live -Query $query) $source
            if ((Get-WelaEvtxRecoveryKey (Get-WelaEvtxRecoveryReader)) -cne $beforeKey) {throw 'Reader token changed during live source query.'}
            if ((Import-WelaEvtxProbe $ProbePath).Fingerprint -cne $source.Fingerprint) {throw 'Source evidence changed before export.'}
            $stage='Export'
            Export-WelaEvtxNative -Query $query -Path $archive
        }
        $stage='ArchiveFileOpen'
        if ((Get-WelaEvtxRecoveryKey (Get-WelaEvtxRecoveryReader)) -cne $beforeKey) {throw 'Reader token changed before archive access.'}
        $null=Resolve-WelaEvtxPath $archive
        # Keep the exact file open without write/delete sharing throughout hashing and native reopen.
        $lock=New-Object IO.FileStream($archive,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $report.FileReadAccess='Allowed';$stage='ArchiveHash'
        if ($lock.Length -lt 1 -or $lock.Length -gt 16777216) {throw 'Exported probe archive exceeds size bounds.'}
        $report.ArchiveBytes=$lock.Length
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$report.ArchiveSha256=([BitConverter]::ToString($sha.ComputeHash($lock))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
        $stage='ArchiveNativeQuery';$report.NativeQuery='Unverified'
        $batch=Read-WelaEvtxNative -Path $archive
        $report.NativeLogStatus=@($batch.LogStatus)
        $report.RecoveredEvents=@($batch.Xml).Count
        Assert-WelaEvtxSingleEvent $batch $source
        $report.NativeQuery='ExactEventRecovered';$stage='EvidenceVerification'
        $report.Artifacts+=Write-WelaEvtxArtifact $output 'recovered-event.xml' $batch.Xml[0]
        if ((Import-WelaEvtxProbe $ProbePath).Fingerprint -cne $source.Fingerprint) {throw 'Source evidence changed during EVTX verification.'}
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $report.ArchiveSha256) {throw 'Archive path/bytes changed during native readback.'}
        $report.ReaderAfter=Get-WelaEvtxRecoveryReader
        if ((Get-WelaEvtxRecoveryKey $report.ReaderAfter) -cne $beforeKey) {throw 'Reader token changed during EVTX access.'}
        $report.ReaderStable=$true;$stage='FinalContext'
        # Final policy inventory may adjust privileges; it runs after the recorded
        # token interval, with no later native event query or archive export.
        if ($Action -eq 'Export' -and (Get-WelaProbeStateKey (Get-WelaProbeState)) -cne (Get-WelaProbeStateKey $expected)) {throw 'Source host or prerequisites drifted during export.'}
        $report.ReaderHostAfter=Get-WelaEvtxRecoveryHost
        if ((Get-WelaEvtxRecoveryKey $report.ReaderHostAfter) -cne $hostKey) {throw 'Actual archive-reader host changed during recovery.'}
        if ((Get-WelaEvtxRecoveryKey (Get-WelaEvtxRecoverySources)) -cne $sourceKey) {throw 'Recovery implementation changed during observation.'}
        foreach ($artifact in $report.Artifacts) {if ((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256) {throw 'Saved recovery evidence changed before the manifest.'}}
        $report.Status='NativeEventRecovered';$report.ExitCode=0
    } catch {
        $failure=Get-WelaChannelReadFailure $_.Exception
        $report.Diagnostic=$_.Exception.Message;$report.FailureStage=$stage;$report.NativeError=$failure.NativeError
        if ($stage -eq 'ArchiveFileOpen' -and $failure.Status -eq 'Denied') {$report.FileReadAccess='Denied'}
        if ($stage -eq 'ArchiveNativeQuery' -and $failure.Status -eq 'Denied') {$report.NativeQuery='Denied'}
    }
    finally {
        if ($report.ReaderBefore -and -not $report.ReaderAfter) {
            try {$report.ReaderAfter=Get-WelaEvtxRecoveryReader;$report.ReaderStable=(Get-WelaEvtxRecoveryKey $report.ReaderAfter) -ceq $beforeKey}
            catch {$report.Diagnostic+=' Final reader observation failed: '+$_.Exception.Message}
        }
        if ($lock) {$lock.Dispose()}
    }
    $report.CompletedUtc=[datetime]::UtcNow.ToString('o')
    $null=Write-WelaEvtxArtifact $output 'manifest.json' ($report | ConvertTo-Json -Depth 24)
    return $report
}
