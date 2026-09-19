# Read-only local collector correlation. No subscription, policy, service or process changes.
function Assert-WelaArrivalObject {
    param($Value,[string[]]$Fields)
    if ($Value -isnot [pscustomobject] -or @($Value.PSObject.Properties).Count -ne $Fields.Count -or
        @($Value.PSObject.Properties.Name | Where-Object {$_ -cnotin $Fields}).Count) {throw 'Unexpected or incomplete arrival evidence object.'}
}
function Get-WelaArrivalHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function ConvertFrom-WelaArrivalJson {
    param([string]$Text)
    # Reuse the merged strict JSON lexer/duplicate-key validator, without executing input.
    $null=& (Get-Module AuditProfiles -ErrorAction Stop) {param($value) ConvertFrom-WelaCustomProfileJson $value} $Text
    $arguments=@{InputObject=$Text;ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {$arguments.DateKind='String'}
    ConvertFrom-Json @arguments
}
function ConvertTo-WelaArrivalUtc {
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -ne [DateTimeKind]::Utc) {throw 'Expected an explicit UTC evidence timestamp.'}
        return [DateTimeOffset]$Value
    }
    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$') {throw 'Expected an explicit UTC evidence timestamp.'}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
}
function Resolve-WelaArrivalPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '[\x00-\x1f*?\[\]]') {throw 'Arrival evidence requires exact paths without wildcards or control characters.'}
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $full -match '^[\\/]{2}' -or $full.Substring([IO.Path]::GetPathRoot($full).Length).Contains(':')) {throw 'Arrival evidence requires ordinary local filesystem paths, without remote/device paths or streams.'}
    $full=[IO.Path]::GetFullPath($full);$ancestor=$full
    while ($ancestor) {
        $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction SilentlyContinue
        if ($item -and ([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint)) {throw 'Arrival evidence cannot traverse reparse points.'}
        $parent=[IO.Directory]::GetParent($ancestor);if (-not $parent) {break};$ancestor=$parent.FullName
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed) {throw 'Arrival evidence requires a local fixed drive.'}
    $full
}
function Get-WelaArrivalXmlKey {
    param($Node)
    # Namespace-aware semantic equality; attribute order/prefixes are not event data.
    $attributes=@($Node.Attributes | Where-Object {$_.NamespaceURI -ne 'http://www.w3.org/2000/xmlns/'} | Sort-Object NamespaceURI,LocalName | ForEach-Object {ConvertTo-Json -InputObject @($_.NamespaceURI,$_.LocalName,$_.Value) -Compress})
    $children=@();$text='';$hasElements=@($Node.ChildNodes|Where-Object NodeType -eq Element).Count -gt 0
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq 'Element') {$children+=Get-WelaArrivalXmlKey $child}
        elseif ($child.NodeType -in @('Text','CDATA','SignificantWhitespace')) {$text+=$child.Value}
        elseif ($child.NodeType -eq 'Whitespace') {if(-not $hasElements){$text+=$child.Value}}
        else {throw 'Unsupported event XML node.'}
    }
    ConvertTo-Json -InputObject @($Node.NamespaceURI,$Node.LocalName,$attributes,$text,$children) -Depth 30 -Compress
}
function Read-WelaArrivalEvent {
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
    $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime')
    [pscustomobject]@{Key=((Get-WelaArrivalXmlKey $parts.System)+'|'+(Get-WelaArrivalXmlKey $parts.EventData));Computer=$system.Computer.InnerText;EventUtc=$time;RecordId=$system.EventRecordID.InnerText;RenderingInfoPresent=[bool]$parts.RenderingInfo}
}
function ConvertTo-WelaArrivalState {
    param($State)
    Assert-WelaArrivalObject $State @('capturedAtUtc','context','hostObservation','auditPolicies','auditPrecedence','commandLineCapture','securityChannelEnabled')
    Assert-WelaArrivalObject $State.context @('computer','role','build','patch','domainJoined','installedRoles')
    Assert-WelaArrivalObject $State.hostObservation @('Status','Build','UBR','Edition','ProductType','DomainRole','DomainJoined','Domain','Architecture','ProcessorArchitecture','InstalledRoles','RolesStatus','Diagnostic')
    foreach ($registry in @($State.auditPrecedence,$State.commandLineCapture)) {
        Assert-WelaArrivalObject $registry @('KeyExists','ValueExists','Value','Type')
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
function Import-WelaArrivalProbe {
    param([Parameter(Mandatory)][string]$Path)
    $root=Resolve-WelaArrivalPath $Path
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Probe bundle directory is missing.'}
    $expected=@('manifest.json','before-state.json','process.json','event.xml','after-state.json')
    $items=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($items.Count -ne 5 -or @($items|Where-Object {$_.Name -cnotin $expected -or $_.PSIsContainer -or ([int]$_.Attributes -band [int][IO.FileAttributes]::ReparsePoint)}).Count) {throw 'Expected exactly five regular native probe files.'}
    $files=@{};$utf8=New-Object Text.UTF8Encoding($false,$true)
    foreach ($item in $items) {
        if ($item.Length -gt 4194304) {throw 'Probe artifact exceeds 4 MiB.'}
        $bytes=[IO.File]::ReadAllBytes($item.FullName)
        if ($bytes.Length -gt 4194304) {throw 'Probe artifact grew beyond 4 MiB.'}
        $files[$item.Name]=[pscustomobject]@{Name=$item.Name;Sha256=(Get-WelaArrivalHash $bytes);Text=$utf8.GetString($bytes).TrimStart([char]0xFEFF)}
    }
    $manifest=ConvertFrom-WelaArrivalJson $files['manifest.json'].Text
    Assert-WelaArrivalObject $manifest @('SchemaVersion','Kind','Probe','Action','Status','ExitCode','GeneratedUtc','PolicyChanges','ReadyRuleCredit','Scope','RequiredEvidence','BeforeState','AfterState','Process','Artifacts','Diagnostic','OutputPath')
    foreach ($name in @('SchemaVersion','ExitCode','PolicyChanges','ReadyRuleCredit')) {if ($manifest.$name -isnot [int] -and $manifest.$name -isnot [long]) {throw 'Mistyped probe status.'}}
    if ($manifest.SchemaVersion -ne 1 -or $manifest.Kind -cne 'WelaNativeProbeComponents' -or $manifest.Probe -cne 'security-4688-command-line-v1' -or $manifest.Action -cne 'Run' -or $manifest.Status -cne 'NativeEventObserved' -or $manifest.ExitCode -ne 0 -or $manifest.PolicyChanges -ne 0 -or $manifest.ReadyRuleCredit -ne 0 -or $manifest.Diagnostic -cne '' -or $manifest.Artifacts -isnot [array] -or $manifest.Artifacts.Count -ne 4) {throw 'Only successful native 4688 probe components are accepted; no readiness evidence is inferred.'}
    if ($manifest.Scope -isnot [string] -or [string]::IsNullOrWhiteSpace($manifest.Scope) -or $manifest.OutputPath -isnot [string] -or [string]::IsNullOrWhiteSpace($manifest.OutputPath) -or $manifest.RequiredEvidence -isnot [array] -or ($manifest.RequiredEvidence -join '|') -cne 'Reviewed complete rule and normalization|Backend ingestion|Translated query and successful query result') {throw 'Incomplete source scope or required-evidence metadata.'}
    $seen=@{}
    foreach ($entry in $manifest.Artifacts) {
        Assert-WelaArrivalObject $entry @('path','sha256')
        if ($entry.path -cnotin @('before-state.json','process.json','event.xml','after-state.json') -or $seen.ContainsKey($entry.path) -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $entry.sha256 -cne $files[$entry.path].Sha256) {throw 'Missing, duplicate or mismatched source artifact hash.'}
        $seen[$entry.path]=$true
    }
    $before=ConvertFrom-WelaArrivalJson $files['before-state.json'].Text
    $after=ConvertFrom-WelaArrivalJson $files['after-state.json'].Text
    $process=ConvertFrom-WelaArrivalJson $files['process.json'].Text
    foreach ($pair in @(@($before,$manifest.BeforeState),@($after,$manifest.AfterState),@($process,$manifest.Process))) {
        if ((ConvertTo-Json -InputObject $pair[0] -Depth 20 -Compress) -cne (ConvertTo-Json -InputObject $pair[1] -Depth 20 -Compress)) {throw 'Embedded source metadata differs from its hashed artifact.'}
    }
    $before=ConvertTo-WelaArrivalState $before;$after=ConvertTo-WelaArrivalState $after
    if ((Get-WelaProbeStateKey $before) -cne (Get-WelaProbeStateKey $after)) {throw 'Source context or prerequisites drifted.'}
    Assert-WelaArrivalObject $process @('ProcessId','ParentProcessId','Executable','Arguments','Marker','StartedUtc','CompletedUtc','ExitCode')
    foreach ($name in @('ProcessId','ParentProcessId')) {if (($process.$name -isnot [int] -and $process.$name -isnot [long]) -or $process.$name -lt 1 -or $process.$name -gt [uint32]::MaxValue) {throw 'Invalid probe process identity.'}}
    if (($process.ExitCode -isnot [int] -and $process.ExitCode -isnot [long]) -or $process.ExitCode -ne 0 -or $process.Marker -cnotmatch '^WELA_PROBE_[a-f0-9]{32}$' -or
        $process.Arguments -cne ('/d /c echo '+$process.Marker) -or $process.Executable -notmatch '^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1f]+\\)*System32\\cmd\.exe$') {throw 'Source must describe only the fixed native cmd.exe echo probe.'}
    $generated=ConvertTo-WelaArrivalUtc $manifest.GeneratedUtc;$began=ConvertTo-WelaArrivalUtc $before.capturedAtUtc
    $started=ConvertTo-WelaArrivalUtc $process.StartedUtc;$completed=ConvertTo-WelaArrivalUtc $process.CompletedUtc;$ended=ConvertTo-WelaArrivalUtc $after.capturedAtUtc
    if ($generated -gt $began -or $began -gt $started -or $started -gt $completed -or $completed -gt $ended) {throw 'Source evidence timestamps are out of order.'}
    if (-not (Test-WelaProbeEvent -Xml $files['event.xml'].Text -Process $process -State $before -EndUtc $ended.UtcDateTime)) {throw 'Source event does not match the fixed process and context.'}
    $event=Read-WelaArrivalEvent $files['event.xml'].Text
    [pscustomobject]@{Path=$root;Fingerprint=(@($files.Keys|Sort-Object|ForEach-Object {$_+'='+$files[$_].Sha256})-join ';');Manifest=$manifest;Files=$files;Event=$event}
}
function Get-WelaArrivalCollector {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {throw 'WEF arrival queries require 64-bit Windows.'}
    $hostState=Get-WelaDefaultContext
    if (-not (Test-WelaDefaultContextComplete $hostState)) {throw "Complete collector context is unavailable: $($hostState.Diagnostic)"}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$reader=[pscustomobject]@{UserSid=$identity.User.Value;Name=$identity.Name;AuthenticationType=$identity.AuthenticationType;IsSystem=$identity.IsSystem;ImpersonationLevel=[string]$identity.ImpersonationLevel;GroupSids=@($identity.Groups|ForEach-Object {$_.Value}|Sort-Object)}} finally {$identity.Dispose()}
    $log=Get-WinEvent -ListLog ForwardedEvents -ErrorAction Stop
    try {
        if (@($log).Count -ne 1 -or $log.LogName -cne 'ForwardedEvents') {throw 'Exact ForwardedEvents channel configuration is unavailable.'}
        $channel=[pscustomobject]@{Name=$log.LogName;Enabled=[bool]$log.IsEnabled;LogMode=[string]$log.LogMode;MaximumSizeInBytes=[long]$log.MaximumSizeInBytes;SecurityDescriptor=$log.SecurityDescriptor;LogFilePath=$log.LogFilePath}
    } finally {if ($log) {$log.Dispose()}}
    [pscustomobject]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Computer=[Environment]::MachineName;Host=$hostState;Reader=$reader;Channel=$channel}
}
function Get-WelaArrivalCollectorKey {
    param($Context)
    if (-not (Test-WelaDefaultContextComplete $Context.Host) -or [string]::IsNullOrWhiteSpace($Context.Computer) -or $Context.Reader.UserSid -notmatch '^S-1-\d+(-\d+)+$' -or
        $Context.Channel.Name -cne 'ForwardedEvents' -or $Context.Channel.Enabled -isnot [bool] -or -not $Context.Channel.SecurityDescriptor) {throw 'Incomplete collector identity/channel observation.'}
    [ordered]@{Computer=$Context.Computer;Host=(Get-WelaDefaultContextKey $Context.Host);Reader=$Context.Reader;Channel=$Context.Channel}|ConvertTo-Json -Depth 12 -Compress
}
function Read-WelaArrivalEvents {
    param([Parameter(Mandatory)]$SourceEvent,[ValidateRange(1,512)][int]$MaximumEvents=512)
    if ($SourceEvent.Computer -cnotmatch '^[\p{L}\p{N}][\p{L}\p{N}_.-]{0,254}$') {throw 'Unsupported source identity for native query.'}
    $start=$SourceEvent.EventUtc.AddSeconds(-1).UtcDateTime.ToString('o');$end=$SourceEvent.EventUtc.AddSeconds(1).UtcDateTime.ToString('o')
    $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4688 and Computer='$($SourceEvent.Computer)' and TimeCreated[@SystemTime>='$start' and @SystemTime<='$end']]]"
    $records=@();$xml=@();$begin=[DateTime]::UtcNow
    try {
        try {$records=@(Get-WinEvent -LogName ForwardedEvents -FilterXPath $query -MaxEvents $MaximumEvents -ErrorAction Stop)}
        catch {if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {throw}}
        foreach ($record in $records) {$xml+=[string]$record.ToXml()}
        [pscustomobject]@{Channel='ForwardedEvents';Query=$query;StartedUtc=$begin.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');Xml=$xml;Capped=($records.Count -ge $MaximumEvents);MaximumEvents=$MaximumEvents}
    } finally {foreach ($record in $records) {$record.Dispose()}}
}
function New-WelaArrivalOutput {
    param([string]$Path,[string]$SourcePath)
    $full=Resolve-WelaArrivalPath $Path
    $comparison=if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    if ($full.Equals($SourcePath,$comparison) -or $full.StartsWith($SourcePath.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar,$comparison)) {throw 'Output must be outside the source bundle.'}
    if (Test-Path -LiteralPath $full) {throw 'Arrival output must be a new directory; existing evidence is never overwritten.'}
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
function Write-WelaArrivalArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaArrivalPath $Root
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);$path=Join-Path $Root $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush()} finally {$stream.Dispose()}
    $hash=Get-WelaArrivalHash $bytes
    if ($hash -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()) {throw 'Arrival artifact readback differs from the written bytes.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
function Invoke-WelaWefArrival {
    param([Parameter(Mandatory)][string]$ProbePath,[Parameter(Mandatory)][string]$OutputPath)
    $source=Import-WelaArrivalProbe $ProbePath
    $output=New-WelaArrivalOutput -Path $OutputPath -SourcePath $source.Path
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaNativeWefArrival';RecordedUtc=[DateTime]::UtcNow.ToString('o');Status='Unverified';ExitCode=1;SourceBundlePath=$source.Path;SourceFingerprint=$source.Fingerprint;SourceManifest=$source.Manifest;CollectorBefore=$null;CollectorAfter=$null;Query=$null;Candidates=0;ExactMatches=0;Diagnostic='';Artifacts=@();OutputPath=$output;Scope='Exact native probe presence in this local ForwardedEvents channel only';SubscriptionAttribution='Not established';TransmissionLatency='Not measured';ClockSynchronization='Not established';ReadyRuleCredit=0;PolicyChanges=0}
    try {
        $report.Artifacts+=Write-WelaArrivalArtifact $output 'source-event.xml' $source.Files['event.xml'].Text
        $before=Get-WelaArrivalCollector;$report.CollectorBefore=$before;$beforeKey=Get-WelaArrivalCollectorKey $before
        $report.Artifacts+=Write-WelaArrivalArtifact $output 'collector-before.json' ($before|ConvertTo-Json -Depth 16)
        $batch=Read-WelaArrivalEvents -SourceEvent $source.Event
        $report.Query=[pscustomobject]@{Channel=$batch.Channel;XPath=$batch.Query;StartedUtc=$batch.StartedUtc;CompletedUtc=$batch.CompletedUtc;Capped=$batch.Capped;MaximumEvents=$batch.MaximumEvents}
        $report.Candidates=@($batch.Xml).Count
        if ($batch.Capped -isnot [bool] -or $batch.Capped) {throw 'Collector query reached its event cap or completeness is unknown.'}
        $matches=@();foreach ($xml in $batch.Xml) {if ((Read-WelaArrivalEvent $xml).Key -ceq $source.Event.Key) {$matches+=$xml}}
        $report.ExactMatches=$matches.Count
        if ($matches.Count -gt 1) {for ($i=0;$i -lt [Math]::Min(2,$matches.Count);$i++) {$report.Artifacts+=Write-WelaArrivalArtifact $output ('collector-duplicate-'+($i+1)+'.xml') $matches[$i]}}
        if ($matches.Count -eq 1) {$report.Artifacts+=Write-WelaArrivalArtifact $output 'collector-event.xml' $matches[0]}
        $after=Get-WelaArrivalCollector;$report.CollectorAfter=$after
        $report.Artifacts+=Write-WelaArrivalArtifact $output 'collector-after.json' ($after|ConvertTo-Json -Depth 16)
        if ((Get-WelaArrivalCollectorKey $after) -cne $beforeKey) {throw 'Collector host, reader identity or channel configuration drifted during the query.'}
        if ((Import-WelaArrivalProbe $ProbePath).Fingerprint -cne $source.Fingerprint) {throw 'Source evidence changed during collector verification.'}
        if ($matches.Count -ne 1) {throw "Expected one exact original event; observed $($matches.Count). Absence does not prove transport loss, and duplicates do not establish a unique arrival."}
        $report.Status='PresentOnCollector';$report.ExitCode=0
    } catch {$report.Diagnostic=$_.Exception.Message}
    finally {
        if ($report.CollectorBefore -and -not $report.CollectorAfter) {
            try {$report.CollectorAfter=Get-WelaArrivalCollector;$report.Artifacts+=Write-WelaArrivalArtifact $output 'collector-after.json' ($report.CollectorAfter|ConvertTo-Json -Depth 16)}
            catch {$report.Diagnostic+=' Final collector observation failed: '+$_.Exception.Message}
        }
    }
    $null=Write-WelaArrivalArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24)
    return $report
}
