# Bounded local callback-delivery measurement. Product code never generates events or changes logging.
function Get-WelaMeasurementCatalog {
    $path=Join-Path (Split-Path $PSScriptRoot -Parent) 'config/event_measurement.json'
    $data=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $expected=@('Security','System','Application','Microsoft-Windows-DNS-Client/Operational','Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-WinRM/Operational','Microsoft-Windows-PowerShell/Operational')
    if ($data.schemaVersion -ne 1 -or $data.kind -cne 'WelaLocalDeliveryMeasurement' -or ($data.channels -join '|') -cne ($expected -join '|')) {throw 'Unsupported measurement catalog; arbitrary channels cannot be enabled through this command.'}
    [pscustomobject]@{Channels=$expected;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();Source=$data.source;Scope=$data.scope}
}
function Resolve-WelaMeasurementPath {
    param([Parameter(Mandatory)][string]$Path)
    # Validate lexical aliases before Windows/provider canonicalization can trim them.
    foreach ($part in $Path.Split([char[]]@('\','/'))) {
        if ($part -notin @('.','..') -and ($part -match '[. ]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)')) {throw 'Measurement evidence rejects ambiguous path aliases and reserved names.'}
    }
    $full=Resolve-WelaEvtxPath $Path
    foreach ($part in $full.Substring([IO.Path]::GetPathRoot($full).Length).Split([char[]]@('\','/'))) {
        if ($part -match '[. ]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or $part -match '[<>"|]') {throw 'Measurement evidence rejects ambiguous path aliases and reserved names.'}
    }
    # Unlike a missing future output component, denied ancestor metadata is not absence.
    $ancestor=$full
    while ($ancestor) {
        try {
            $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if ([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) {throw 'Measurement evidence cannot traverse reparse points.'}
        } catch [System.Management.Automation.ItemNotFoundException] { }
        $parent=[IO.Directory]::GetParent($ancestor);if (-not $parent) {break};$ancestor=$parent.FullName
    }
    $full
}
function New-WelaMeasurementOutput {
    param([string]$Path)
    $full=Resolve-WelaMeasurementPath $Path
    # No source input is consumed; use the existing new-directory ACL adapter with an unrelated sentinel.
    $root=New-WelaEvtxOutput -Path $full -SourcePath (Join-Path ([IO.Path]::GetPathRoot($full)) ('wela-unused-'+[guid]::NewGuid().ToString('N')))
    if ($env:OS -eq 'Windows_NT') {
        $acl=Get-Acl -LiteralPath $root -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) {throw 'Private evidence directory ACL protection was not applied.'}
        $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.IsInherited -or $rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne 'Allow') {throw 'Unexpected private evidence directory access rule.'}
        }
    }
    $root
}
function Write-WelaMeasurementArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaMeasurementPath $Root
    if ($Name -cnotmatch '^(?:[a-z][a-z0-9-]*\.json|event-[0-9]{4}\.xml|bookmark-[0-9]{4}\.xml)$') {throw 'Unexpected measurement artifact name.'}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream=[IO.File]::Open((Join-Path $Root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    $hash=Get-WelaEvtxHash $bytes
    if ((Get-FileHash -LiteralPath (Join-Path $Root $Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) {throw 'Measurement artifact readback differs.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
function Get-WelaMeasurementState {
    param([string]$Channel)
    $reader=Get-WelaEvtxReader
    # Local IP-helper metadata performs no DNS query. A shared short-name prefix is not identity.
    $network=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $names=@($reader.Computer,$network.HostName)
    if (-not [string]::IsNullOrWhiteSpace($network.DomainName)) {$names+=($network.HostName+'.'+$network.DomainName)}
    if (@($names|Where-Object {$_ -notmatch '^[\p{L}\p{N}][\p{L}\p{N}_.-]{0,254}$'}).Count) {throw 'Exact native local computer names are unavailable.'}
    $reader|Add-Member NoteProperty SourceComputerNames @($names|Sort-Object -Unique)
    $configuration=New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel)
    $session=New-Object System.Diagnostics.Eventing.Reader.EventLogSession
    try {
        $information=$session.GetLogInformation($Channel,[System.Diagnostics.Eventing.Reader.PathType]::LogName)
        if ($configuration.LogName -cne $Channel -or [string]$configuration.LogType -notin @('Administrative','Operational') -or -not $configuration.IsEnabled) {throw 'The exact channel must be registered, enabled and Administrative/Operational.'}
        if ([string]::IsNullOrWhiteSpace($configuration.SecurityDescriptor) -or [string]::IsNullOrWhiteSpace($configuration.LogFilePath) -or $configuration.MaximumSizeInBytes -le 0 -or $null -eq $information.CreationTime -or $null -eq $information.RecordCount -or $null -eq $information.OldestRecordNumber) {throw 'Required channel metadata or log identity is unavailable.'}
        [pscustomobject]@{
            CapturedUtc=[datetime]::UtcNow.ToString('o');Reader=$reader
            Configuration=[pscustomobject]@{Name=$configuration.LogName;Type=[string]$configuration.LogType;Enabled=[bool]$configuration.IsEnabled;Mode=[string]$configuration.LogMode;MaximumBytes=[long]$configuration.MaximumSizeInBytes;RegisteredPath=$configuration.LogFilePath;SecurityDescriptor=$configuration.SecurityDescriptor;Providers=@($configuration.ProviderNames|Sort-Object)}
            Log=[pscustomobject]@{CreatedUtc=$information.CreationTime.ToUniversalTime().ToString('o');OldestRecord=[long]$information.OldestRecordNumber;RecordCount=[long]$information.RecordCount;FileBytes=$information.FileSize;Full=$information.IsLogFull}
        }
    } finally {$configuration.Dispose();$session.Dispose()}
}
function Assert-WelaMeasurementState {
    param($Before,$After)
    foreach ($name in @('Reader','Configuration')) {
        if ((ConvertTo-Json -InputObject $Before.$name -Depth 20 -Compress) -cne (ConvertTo-Json -InputObject $After.$name -Depth 20 -Compress)) {throw "Measurement $name changed during collection/export."}
    }
    if ($Before.Log.CreatedUtc -cne $After.Log.CreatedUtc -or $After.Log.OldestRecord -lt $Before.Log.OldestRecord -or ($Before.Log.RecordCount -gt 0 -and $After.Log.RecordCount -eq 0)) {throw 'Log clear/reset or inconsistent identity was observed.'}
}
function Read-WelaMeasurementXmlDocument {
    param([string]$Text,[int]$Maximum=1048576)
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt $Maximum) {throw 'XML exceeds its evidence limit.'}
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=$Maximum
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Text),$settings)
    try {$document=New-Object Xml.XmlDocument;$document.XmlResolver=$null;$document.PreserveWhitespace=$true;$document.Load($reader)} finally {$reader.Dispose()}
    return ,$document
}
function Get-WelaMeasurementXmlKey {
    param($Node,[int]$Depth=0)
    if ($Depth -ge 64) {throw 'Event XML semantic comparison exceeds the 64-element nesting cap.'}
    # Keep text in its original position relative to element children. UserData can
    # contain mixed content; collecting all text separately would erase payload order.
    $attributes=@($Node.Attributes | Where-Object {$_.NamespaceURI -ne 'http://www.w3.org/2000/xmlns/'} | Sort-Object NamespaceURI,LocalName -CaseSensitive | ForEach-Object {ConvertTo-Json -InputObject @($_.NamespaceURI,$_.LocalName,$_.Value) -Compress})
    $content=New-Object 'System.Collections.Generic.List[string]'
    $text=New-Object Text.StringBuilder
    $hasElements=@($Node.ChildNodes | Where-Object NodeType -eq Element).Count -gt 0
    $mixed=@($Node.ChildNodes | Where-Object {$_.NodeType -in @('Text','CDATA','SignificantWhitespace')}).Count -gt 0
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq 'Element') {
            if ($text.Length) {$content.Add((ConvertTo-Json -InputObject @('Text',$text.ToString()) -Compress));$null=$text.Clear()}
            $content.Add((ConvertTo-Json -InputObject @('Element',(Get-WelaMeasurementXmlKey -Node $child -Depth ($Depth+1))) -Compress))
        } elseif ($child.NodeType -in @('Text','CDATA','SignificantWhitespace')) {$null=$text.Append($child.Value)}
        elseif ($child.NodeType -eq 'Whitespace') {
            # Ignore indentation only for element-only content; mixed/leaf text is data.
            if (-not $hasElements -or $mixed) {$null=$text.Append($child.Value)}
        } else {throw 'Unsupported event XML node.'}
    }
    if ($text.Length) {$content.Add((ConvertTo-Json -InputObject @('Text',$text.ToString()) -Compress))}
    # Child digests keep memory proportional to the bounded XML, rather than
    # repeatedly JSON-escaping each descendant's serialized representation.
    $key=ConvertTo-Json -InputObject @($Node.NamespaceURI,$Node.LocalName,$attributes,@($content.ToArray())) -Depth 30 -Compress
    Get-WelaEvtxHash ([Text.Encoding]::UTF8.GetBytes($key))
}
function Read-WelaMeasurementEvent {
    param([string]$Xml,[string]$Channel,[string[]]$Computer)
    $doc=Read-WelaMeasurementXmlDocument $Xml
    $ns='http://schemas.microsoft.com/win/2004/08/events/event';$root=$doc.DocumentElement
    if ($root.LocalName -cne 'Event' -or $root.NamespaceURI -cne $ns -or @($root.Attributes|Where-Object NamespaceURI -ne 'http://www.w3.org/2000/xmlns/').Count) {throw 'Unexpected event XML root.'}
    $parts=@{}
    foreach ($node in $root.ChildNodes) {
        if ($node.NodeType -eq 'Whitespace') {continue}
        if ($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns -or $node.LocalName -cnotin @('System','EventData','UserData','BinaryEventData','RenderingInfo') -or $parts.ContainsKey($node.LocalName)) {throw 'Unknown or duplicate event XML section.'}
        $parts[$node.LocalName]=$node
    }
    if (-not $parts.System -or @('EventData','UserData','BinaryEventData'|Where-Object {$parts.ContainsKey($_)}).Count -gt 1) {throw 'Ambiguous event payload.'}
    $system=@{}
    foreach ($node in $parts.System.ChildNodes) {
        if ($node.NodeType -eq 'Whitespace') {continue}
        if ($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns -or $system.ContainsKey($node.LocalName)) {throw 'Ambiguous System identity.'}
        $system[$node.LocalName]=$node
    }
    foreach ($name in @('Provider','EventID','Version','TimeCreated','EventRecordID','Channel','Computer')) {if (-not $system.ContainsKey($name)) {throw "Missing native event identity: $name"}}
    [uint64]$record=0;[uint32]$eventId=0;[byte]$version=0
    if (-not [uint64]::TryParse($system.EventRecordID.InnerText,[ref]$record) -or $record -eq 0 -or -not [uint32]::TryParse($system.EventID.InnerText,[ref]$eventId) -or -not [byte]::TryParse($system.Version.InnerText,[ref]$version)) {throw 'Invalid native numeric event identity.'}
    $source=$system.Computer.InnerText
    if ($system.Channel.InnerText -cne $Channel -or $source -notmatch '^[\p{L}\p{N}][\p{L}\p{N}_.-]{0,254}$' -or $source -notin $Computer) {throw 'Event source/channel does not match the actual local reader.'}
    $provider=$system.Provider.GetAttribute('Name');if ([string]::IsNullOrWhiteSpace($provider)) {throw 'Provider name is unavailable.'}
    $keys=@((Get-WelaMeasurementXmlKey $parts.System))
    foreach ($name in @('EventData','UserData','BinaryEventData')) {if ($parts.ContainsKey($name)) {$keys+=$name+'='+(Get-WelaMeasurementXmlKey $parts[$name])}}
    [pscustomobject]@{RecordId=$record.ToString([Globalization.CultureInfo]::InvariantCulture);Channel=$Channel;Computer=$source;Provider=$provider;ProviderGuid=$system.Provider.GetAttribute('Guid');EventId=$eventId;Version=$version;EventUtc=(ConvertTo-WelaEvtxUtc $system.TimeCreated.GetAttribute('SystemTime')).ToString('o');Key=($keys -join '|')}
}
function Assert-WelaMeasurementBookmark {
    param([string]$Xml,$Event)
    $doc=Read-WelaMeasurementXmlDocument -Text $Xml -Maximum 65536
    if ($doc.DocumentElement.LocalName -cne 'BookmarkList') {throw 'Unexpected native bookmark root.'}
    $entries=@($doc.DocumentElement.ChildNodes|Where-Object NodeType -eq Element)
    if ($entries.Count -ne 1 -or $entries[0].LocalName -cne 'Bookmark' -or $entries[0].GetAttribute('Channel') -cne $Event.Channel -or $entries[0].GetAttribute('RecordId') -cne $Event.RecordId) {throw 'Native bookmark does not identify the delivered event.'}
}
function New-WelaMeasurementObserver {
    param([string]$Channel,[int]$Seconds,[int]$MaximumEvents)
    if (-not ('Wela.EventMeasurementV1.Observer' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'EventMeasurementNative.cs') -ErrorAction Stop}
    [Wela.EventMeasurementV1.Observer]::new($Channel,$Seconds,$MaximumEvents)
}
function Get-WelaMeasurementQuery {
    param([string]$Channel,[array]$Events)
    if ($Events.Count -lt 1 -or $Events.Count -gt 1024) {throw 'An EVTX sample requires 1 through 1024 exact record IDs.'}
    $ids=@{};$selects=@()
    foreach ($event in $Events) {if ($event.RecordId -cnotmatch '^[1-9][0-9]{0,19}$' -or $ids.ContainsKey($event.RecordId)) {throw 'Invalid or duplicate sampled record ID.'};$ids[$event.RecordId]=$true}
    $escaped=[Security.SecurityElement]::Escape($Channel)
    for ($offset=0;$offset -lt $Events.Count;$offset+=20) {
        $last=[Math]::Min($offset+19,$Events.Count-1)
        $predicates=@($Events[$offset..$last]|ForEach-Object {'EventRecordID='+$_.RecordId}) -join ' or '
        $selects+='<Select Path="'+$escaped+'">*[System['+$predicates+']]</Select>'
    }
    '<QueryList><Query Id="0" Path="'+$escaped+'">'+($selects -join '')+'</Query></QueryList>'
}
function Export-WelaMeasurementEvtx {
    param([string]$Channel,[string]$Query,[string]$Path)
    $null=Resolve-WelaMeasurementPath $Path
    if (Test-Path -LiteralPath $Path) {throw 'EVTX sample path already exists.'}
    $session=New-Object System.Diagnostics.Eventing.Reader.EventLogSession
    try {$session.ExportLog($Channel,[System.Diagnostics.Eventing.Reader.PathType]::LogName,$Query,$Path,$false)} finally {$session.Dispose()}
}
function Read-WelaMeasurementEvtx {
    param([string]$Path,[int]$MaximumEvents)
    $query=New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Path,[System.Diagnostics.Eventing.Reader.PathType]::FilePath,'*')
    $query.TolerateQueryErrors=$false
    $reader=New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    $result=New-Object 'System.Collections.Generic.List[string]'
    try {
        for ($i=0;$i -le $MaximumEvents;$i++) {
            $event=$reader.ReadEvent([timespan]::FromSeconds(5));if ($null -eq $event) {break}
            try {$xml=$event.ToXml();if ([Text.Encoding]::UTF8.GetByteCount($xml) -gt 1048576) {throw 'Exported event exceeds the XML cap.'};$result.Add($xml)} finally {$event.Dispose()}
        }
    } finally {$reader.Dispose()}
    return ,$result.ToArray()
}
function Confirm-WelaMeasurementEvtx {
    param([string]$Path,[array]$Events,[string]$Channel,[string[]]$Computer)
    $null=Resolve-WelaMeasurementPath $Path
    # Hold a read handle denying writes/deletion throughout native reopen verification.
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -lt 1 -or $file.Length -gt 67108864) {throw 'EVTX export is empty or exceeds the 64 MiB artifact cap.'}
        $bytes=$file.Length;$sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
        $actual=Read-WelaMeasurementEvtx -Path $Path -MaximumEvents $Events.Count
        if (@($actual).Count -ne $Events.Count) {throw 'EVTX reopen contains missing or extra records.'}
        $expected=@{};foreach ($event in $Events) {$expected[$event.RecordId]=$event.Key}
        $seen=@{}
        foreach ($xml in $actual) {
            $event=Read-WelaMeasurementEvent -Xml $xml -Channel $Channel -Computer $Computer
            if ($seen.ContainsKey($event.RecordId) -or -not $expected.ContainsKey($event.RecordId) -or $expected[$event.RecordId] -cne $event.Key) {throw 'EVTX reopen differs from the original delivered event identity or payload.'}
            $seen[$event.RecordId]=$true
        }
        if ($file.Length -ne $bytes) {throw 'EVTX sample changed during verification.'}
        [pscustomobject]@{Status='ExactSampleReopened';Name='sample.evtx';Bytes=$bytes;Sha256=$hash;Records=$seen.Count;ByteMeaning='Logical bytes of this specific native EVTX export, including format overhead; not channel growth, allocation, backend storage or retention capacity.'}
    } finally {$file.Dispose()}
}
function Invoke-WelaEventMeasurement {
    [CmdletBinding()]
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[Parameter(Mandatory)][string]$Channel,[ValidateRange(1,60)][int]$Seconds=10,[ValidateRange(1,1024)][int]$MaximumEvents=256,[string]$OutputPath,[switch]$ExportEvtx)
    $catalog=Get-WelaMeasurementCatalog
    if ($Channel -cnotin $catalog.Channels) {throw 'Select one exact reviewed channel; remote, forwarded, wildcard, Analytic and Debug channels are unsupported.'}
    if ($Action -eq 'Plan' -and ($OutputPath -or $ExportEvtx)) {throw 'OutputPath and ExportEvtx require Run; Plan is read-only.'}
    if ($Action -eq 'Run' -and [string]::IsNullOrWhiteSpace($OutputPath)) {throw 'Run requires a new private output directory.'}
    if ($OutputPath) {$OutputPath=Resolve-WelaMeasurementPath $OutputPath;if(Test-Path -LiteralPath $OutputPath){throw 'Measurement output already exists.'}}
    $result=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaLocalDeliveryMeasurement';Action=$Action;Status='Planned';ExitCode=0;GeneratedUtc=[datetime]::UtcNow.ToString('o');Channel=$Channel;RequestedSeconds=$Seconds;MaximumEvents=$MaximumEvents;MaximumXmlBytes=16777216;MaximumEventXmlBytes=1048576;MaximumEvtxBytes=67108864;CatalogSha256=$catalog.Sha256;OutputPath=$OutputPath;Before=$null;After=$null;Window=$null;ObservedDeliveries=0;ObservedDeliveriesPerSecond=$null;LossAssessment='Unknown: Windows subscription diagnostics and consistency checks cannot prove that all upstream events were generated or delivered.';Evtx=[pscustomobject]@{Status='NotRequested';Bytes=$null};Events=@();Artifacts=@();Diagnostic='';PolicyChanges=0;ReadyRuleCredit=0;Scope='Local callback deliveries during one bounded monotonic window. No producer throughput, backend ingestion, retention-duration, storage-growth or Sigma readiness claim.'}
    $root=$null;$observer=$null
    try {
        $result.Before=Get-WelaMeasurementState $Channel
        if ($Action -eq 'Plan') {return $result}
        $root=New-WelaMeasurementOutput $OutputPath;$result.OutputPath=$root
        $result.Artifacts+=Write-WelaMeasurementArtifact $root 'before-state.json' (ConvertTo-Json -InputObject $result.Before -Depth 20)
        $observer=New-WelaMeasurementObserver -Channel $Channel -Seconds $Seconds -MaximumEvents $MaximumEvents
        $result.Artifacts+=Write-WelaMeasurementArtifact $root 'window-open.json' (ConvertTo-Json -InputObject ([pscustomobject]@{StartedUtc=$observer.StartedUtc;RegistrationSeconds=$observer.RegistrationSeconds;Channel=$Channel;RequestedSeconds=$Seconds;Origin='Future events only; callbacks before the measurement window are excluded.'}))
        $capture=$observer.Complete();$observer.Dispose();$observer=$null
        $result.Window=[pscustomobject]@{StartedUtc=$capture.StartedUtc;CompletedUtc=$capture.CompletedUtc;RegistrationSeconds=$capture.RegistrationSeconds;ElapsedSeconds=$capture.ElapsedSeconds;NativeStatus=$capture.Status;NativeError=$capture.NativeError;BeforeWindowCallbacks=$capture.BeforeWindowCallbacks;OutsideWindowCallbacks=$capture.OutsideWindowCallbacks;XmlUtf8Bytes=$capture.XmlUtf8Bytes;Clock='Stopwatch monotonic; serialized callback processing time, not event TimeCreated';LastBookmark=$null}
        $result.ObservedDeliveries=@($capture.Events).Count
        [uint64]$previous=0;$index=0
        foreach ($delivery in $capture.Events) {
            $index++;$eventName='event-{0:d4}.xml' -f $index;$bookmarkName='bookmark-{0:d4}.xml' -f $index
            $result.Artifacts+=Write-WelaMeasurementArtifact $root $eventName $delivery.Xml
            $result.Artifacts+=Write-WelaMeasurementArtifact $root $bookmarkName $delivery.BookmarkXml
            $event=Read-WelaMeasurementEvent -Xml $delivery.Xml -Channel $Channel -Computer $result.Before.Reader.SourceComputerNames
            Assert-WelaMeasurementBookmark $delivery.BookmarkXml $event
            if ($previous -ne 0 -and [uint64]$event.RecordId -ne $previous+1) {throw 'Delivered record IDs are duplicated, reordered or discontinuous; completeness is unverified.'}
            if ($delivery.ElapsedSeconds -lt 0 -or $delivery.ElapsedSeconds -ge $Seconds) {throw 'Delivery timestamp is outside the monotonic observation window.'}
            $previous=[uint64]$event.RecordId
            $event|Add-Member NoteProperty ObservedElapsedSeconds $delivery.ElapsedSeconds
            $event|Add-Member NoteProperty XmlArtifact $eventName
            $event|Add-Member NoteProperty BookmarkArtifact $bookmarkName
            $result.Events+= $event;$result.Window.LastBookmark=$bookmarkName
        }
        $result.After=Get-WelaMeasurementState $Channel
        $result.Artifacts+=Write-WelaMeasurementArtifact $root 'after-state.json' (ConvertTo-Json -InputObject $result.After -Depth 20)
        Assert-WelaMeasurementState $result.Before $result.After
        if ((Get-WelaMeasurementCatalog).Sha256 -cne $catalog.Sha256) {throw 'Measurement catalog changed during collection.'}
        if ($capture.Status -cne 'WindowComplete' -or $capture.NativeError -ne 0) {throw ($capture.Status+': '+$capture.Diagnostic)}
        if ($capture.ElapsedSeconds -ne $Seconds) {throw 'Native observation window did not complete.'}
        if ($result.Events.Count -eq 0) {
            $result.Status='NoDeliveriesObserved';$result.Evtx.Status=if($ExportEvtx){'NotCreatedNoEvents'}else{'NotRequested'}
            $result.Diagnostic='No deliveries were observed in this window. This does not establish zero producer traffic, capacity or absence of loss.'
        } else {
            if ($ExportEvtx) {
                $result.Evtx.Status='Unverified'
                $query=Get-WelaMeasurementQuery $Channel $result.Events
                $result.Artifacts+=Write-WelaMeasurementArtifact $root 'sample-query.json' (ConvertTo-Json -InputObject ([pscustomobject]@{Channel=$Channel;Query=$query;RecordIds=@($result.Events.RecordId)}))
                Export-WelaMeasurementEvtx -Channel $Channel -Query $query -Path (Join-Path $root 'sample.evtx')
                $verified=Confirm-WelaMeasurementEvtx -Path (Join-Path $root 'sample.evtx') -Events $result.Events -Channel $Channel -Computer $result.Before.Reader.SourceComputerNames
                $final=Get-WelaMeasurementState $Channel;Assert-WelaMeasurementState $result.Before $final
                $result.Artifacts+=Write-WelaMeasurementArtifact $root 'export-after-state.json' (ConvertTo-Json -InputObject $final -Depth 20)
                $result.Evtx=$verified
                $result.Artifacts+=[pscustomobject]@{Name=$verified.Name;Sha256=$verified.Sha256;Bytes=$verified.Bytes}
            }
            $result.Status='DeliveryWindowObserved';$result.ObservedDeliveriesPerSecond=$result.Events.Count/[double]$capture.ElapsedSeconds
        }
    } catch {$result.Status='Unverified';$result.ExitCode=1;$result.ObservedDeliveriesPerSecond=$null;$result.Diagnostic=$_.Exception.Message}
    finally {if ($observer) {$observer.Dispose()}}
    if ($root) {
        # Keys are private in-memory comparators, not evidence content; original XML carries all fields.
        foreach ($event in $result.Events) {$event.PSObject.Properties.Remove('Key')}
        try {
            foreach ($artifact in $result.Artifacts) {
                $path=Resolve-WelaMeasurementPath (Join-Path $root $artifact.Name)
                if ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length -ne $artifact.Bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256) {throw 'Saved event evidence changed before the manifest was written.'}
            }
            if ((Get-WelaMeasurementCatalog).Sha256 -cne $catalog.Sha256) {throw 'Measurement catalog changed before the manifest was written.'}
        } catch {
            $result.Status='Unverified';$result.ExitCode=1;$result.ObservedDeliveriesPerSecond=$null;$result.Diagnostic+=' Final evidence check failed: '+$_.Exception.Message
            if ($result.Evtx.Status -eq 'ExactSampleReopened') {$result.Evtx.Status='Unverified';$result.Evtx.Bytes=$null}
        }
        try {$null=Write-WelaMeasurementArtifact $root 'manifest.json' (ConvertTo-Json -InputObject $result -Depth 30)}
        catch {$result.Status='Unverified';$result.ExitCode=1;$result.ObservedDeliveriesPerSecond=$null;$result.Diagnostic+=' Manifest write failed: '+$_.Exception.Message}
    }
    return $result
}
