# Read-only local retention/collection evidence. No configuration or transport writes.
function Import-WelaRetentionConfig {
    param([string]$Path)
    $config=if ($Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } else { [pscustomobject]@{ SchemaVersion=1; Role='Source'; Channels=@('Security','System','Application') } }
    $known=@('SchemaVersion','Role','Channels','SampleWindowMinutes','MaxEventsPerChannel','StaleAfterMinutes','ProjectionDays','SubscriptionIds','Archive')
    foreach ($property in $config.PSObject.Properties) { if ($property.Name -cnotin $known) { throw "Unknown retention configuration field: $($property.Name)" } }
    if ($config.SchemaVersion -ne 1 -or $config.Role -cnotin @('Source','Collector')) { throw 'Retention config requires schema 1 and explicit Source or Collector role.' }
    if (@($config.Channels).Count -lt 1 -or @($config.Channels).Count -gt 32) { throw 'Select 1..32 exact native Windows channels.' }
    $seen=@{}
    foreach ($channel in $config.Channels) {
        if (-not (Test-WelaRetentionChannel $channel) -or $seen.ContainsKey($channel)) { throw "Unsupported or duplicate retention channel: $channel" }; $seen[$channel]=$true
    }
    $limits=@{ SampleWindowMinutes=@(60,1,1440); MaxEventsPerChannel=@(1000,1,10000); StaleAfterMinutes=@(60,1,10080); ProjectionDays=@(30,1,3660) }
    foreach ($name in $limits.Keys) {
        if (-not $config.PSObject.Properties[$name]) { $config | Add-Member NoteProperty $name $limits[$name][0] }
        $value=$config.$name
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt $limits[$name][1] -or $value -gt $limits[$name][2]) { throw "Invalid integer $name." }
    }
    if (-not $config.PSObject.Properties['SubscriptionIds']) { $config | Add-Member NoteProperty SubscriptionIds @() }
    if (@($config.SubscriptionIds).Count -gt 32 -or ($config.Role -eq 'Source' -and @($config.SubscriptionIds).Count -gt 0)) { throw 'At most 32 explicit subscription IDs may be assessed on a Collector.' }
    foreach ($id in $config.SubscriptionIds) { if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$') { throw 'Unsupported subscription ID.' } }
    if ($config.Archive) {
        foreach ($property in $config.Archive.PSObject.Properties) { if ($property.Name -cnotin @('DeclaredRetentionMonths','PolicyEvidence','Directory','MaxFiles','ReaderSids')) { throw "Unknown archive declaration field: $($property.Name)" } }
        if ($null -ne $config.Archive.DeclaredRetentionMonths -and (($config.Archive.DeclaredRetentionMonths -isnot [int] -and $config.Archive.DeclaredRetentionMonths -isnot [long]) -or $config.Archive.DeclaredRetentionMonths -lt 1 -or $config.Archive.DeclaredRetentionMonths -gt 120)) { throw 'Declared archive retention must be 1..120 months or null.' }
        if ($config.Archive.PolicyEvidence -and ([string]$config.Archive.PolicyEvidence).Length -gt 4000) { throw 'Archive policy evidence exceeds 4000 characters.' }
        if (-not $config.Archive.PSObject.Properties['MaxFiles']) { $config.Archive | Add-Member NoteProperty MaxFiles 10 }
        if (($config.Archive.MaxFiles -isnot [int] -and $config.Archive.MaxFiles -isnot [long]) -or $config.Archive.MaxFiles -lt 1 -or $config.Archive.MaxFiles -gt 100) { throw 'Archive MaxFiles must be an integer from 1 to 100.' }
        if (@($config.Archive.ReaderSids).Count -gt 32) { throw 'Select at most 32 intended archive reader SIDs.' }
        foreach ($sid in $config.Archive.ReaderSids) { if ($sid -notmatch '^S-1-\d+(-\d+)+$') { throw 'Expected intended reader SID, not an account name.' } }
    }
    return $config
}

function Test-WelaRetentionChannel {
    param([string]$Name)
    return $Name -and $Name -notmatch '(?i)Sysmon|\bEMET\b' -and ($Name -in @('Security','System','Application','ForwardedEvents','Windows PowerShell') -or $Name -match '^Microsoft-Windows-[A-Za-z0-9 -]+/[A-Za-z0-9 -]+$')
}

function ConvertTo-WelaRetentionEvent {
    param($Event)
    $xml=$null; $xmlBytes=$null; $diagnostic=''; $message=$null
    try { $xml=[string]::Concat($Event.ToXml()); $xmlBytes=[Text.Encoding]::UTF8.GetByteCount($xml) } catch { $diagnostic='XML read: ' + $_.ToString() }
    try { $message=[string]::Concat($Event.Message) } catch { $diagnostic += ' Message unavailable: ' + $_.ToString() }
    $utc=$null
    try { if ($null -ne $Event.TimeCreated) { $utc=([datetime]$Event.TimeCreated).ToUniversalTime().ToString('o') } } catch { $diagnostic += ' Timestamp unavailable: ' + $_.ToString() }
    [pscustomobject]@{ RecordId=$Event.RecordId; Id=$Event.Id; Provider=[string]$Event.ProviderName; Channel=[string]$Event.LogName; MachineName=[string]$Event.MachineName; Level=$Event.Level; TimeCreatedUtc=$utc; XmlUtf8Bytes=$xmlBytes; Xml=$xml; Message=$message; Diagnostic=$diagnostic }
}

function Read-WelaRetentionEvents {
    param([string]$Channel,[string]$Path,[datetime]$StartUtc,[datetime]$EndUtc,[int]$Limit=1,[switch]$Oldest,[int[]]$Ids,[int[]]$Levels,[string]$Provider)
    $records=@(); $status='Observed'; $diagnostic=''
    try {
        $arguments=@{ MaxEvents=$Limit; ErrorAction='Stop' }
        if ($Oldest) { $arguments.Oldest=$true }
        if ($Path) { $arguments.Path=$Path }
        elseif ($PSBoundParameters.ContainsKey('StartUtc')) {
            $filter=@{ LogName=$Channel; StartTime=$StartUtc; EndTime=$EndUtc }
            if ($Ids) { $filter.Id=$Ids }; if ($Levels) { $filter.Level=$Levels }; if ($Provider) { $filter.ProviderName=$Provider }
            $arguments.FilterHashtable=$filter
        } else { $arguments.LogName=$Channel }
        foreach ($event in @(Get-WinEvent @arguments)) {
            try {
                if ($Path -and -not (Test-WelaRetentionChannel ([string]$event.LogName))) { throw 'Archive boundary contains an unsupported/non-native channel. Its payload and retention age are excluded.' }
                $records += ConvertTo-WelaRetentionEvent $event
            }
            finally { if ($event -is [IDisposable]) { $event.Dispose() } }
        }
        if (-not $records.Count) { $status='NoRecordsObserved' }
    } catch {
        if ($_.FullyQualifiedErrorId -match '^NoMatchingEventsFound(,|$)') { $status='NoRecordsObserved' }
        else { $status='Unknown'; $diagnostic=$_.ToString() }
    }
    [pscustomobject]@{ Status=$status; Records=$records; Diagnostic=$diagnostic; RequestedLimit=$Limit }
}

function Get-WelaRetentionBuffer {
    param([string]$Channel)
    $buffer=[ordered]@{ Channel=$Channel; Status='Unknown'; MaximumBytes=$null; FileBytes=$null; RecordCount=$null; OldestRecordNumber=$null; IsLogFull=$null; Enabled=$null; Mode=$null; SecurityDescriptor=$null; Diagnostic='' }
    try {
        $logs=@(Get-WinEvent -ListLog $Channel -ErrorAction Stop | Where-Object LogName -eq $Channel)
        if ($logs.Count -ne 1) { throw 'A unique exact channel registration was not returned.' }
        $log=$logs[0]
        $mapping=@{ MaximumBytes='MaximumSizeInBytes'; FileBytes='FileSize'; RecordCount='RecordCount'; OldestRecordNumber='OldestRecordNumber'; IsLogFull='IsLogFull'; Enabled='IsEnabled'; Mode='LogMode'; SecurityDescriptor='SecurityDescriptor' }
        $errors=@()
        foreach ($name in $mapping.Keys) {
            try { $value=$log.($mapping[$name]); if ($null -eq $value) { throw 'Property is unavailable.' }; $buffer[$name]=if ($name -in @('Mode','SecurityDescriptor')) { [string]::Concat($value) } else { $value } }
            catch { $errors += "$name : $_" }
        }
        $buffer.Status=if ($errors.Count) { 'Partial' } else { 'Observed' }; $buffer.Diagnostic=$errors -join '; '
    } catch {
        if ($_.FullyQualifiedErrorId -match '^NoMatchingLogsFound(,|$)') { $buffer.Status='NotInstalled' }
        $buffer.Diagnostic=$_.ToString()
    }
    [pscustomobject]$buffer
}

function Get-WelaRetentionAge {
    param($First,$Last,[datetime]$NowUtc)
    $age=$null; $status='Unknown'; $diagnostic=''
    if ($First.Status -eq 'NoRecordsObserved' -and $Last.Status -eq 'NoRecordsObserved') { $status='NoRecordsObserved' }
    elseif ($First.Status -eq 'Observed' -and $Last.Status -eq 'Observed' -and $First.Records.Count -eq 1 -and $Last.Records.Count -eq 1) {
        try {
            $created=[datetime]::Parse($First.Records[0].TimeCreatedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            if ($created -gt $NowUtc) { $status='ClockOrTimestampAnomaly'; $diagnostic='Oldest readable record has a future timestamp; age cannot be established.' }
            else { $age=($NowUtc-$created).TotalDays; $status='BoundaryObserved' }
        } catch { $diagnostic=$_.ToString() }
    }
    [pscustomobject]@{ Status=$status; OldestReadableRecordAgeDays=$age; OldestRecord=$First; NewestRecord=$Last; CompleteEventCoverage='Unknown'; AchievedRetentionCompliance='Not established'; Diagnostic=$diagnostic; Basis='First and last readable records in log order. Timestamps may be nonmonotonic, especially forwarded events; boundaries do not prove a continuous history.' }
}

function Get-WelaRetentionRate {
    param($Read,[datetime]$StartUtc,[datetime]$EndUtc,[int]$Cap,[int]$ProjectionDays)
    $records=@($Read.Records | Select-Object -First $Cap); $capped=$Read.Records.Count -gt $Cap
    $seconds=($EndUtc-$StartUtc).TotalSeconds; $xmlBytes=[long]0; $completeBytes=$true; $timestampValid=$true
    foreach ($event in $records) {
        if ($null -eq $event.XmlUtf8Bytes) { $completeBytes=$false } else { $xmlBytes += $event.XmlUtf8Bytes }
        try { $utc=[datetime]::Parse($event.TimeCreatedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime(); if ($utc -lt $StartUtc -or $utc -gt $EndUtc) { $timestampValid=$false } }
        catch { $timestampValid=$false }
    }
    $valid=$Read.Status -in @('Observed','NoRecordsObserved') -and $seconds -gt 0 -and $timestampValid
    $observedRate=if ($valid) { $records.Count/$seconds } else { $null }
    $projection=if ($valid -and $completeBytes -and $records.Count -gt 0) { $xmlBytes/$seconds * $ProjectionDays*86400 } else { $null }
    [pscustomobject]@{
        Status=$(if (-not $valid) { 'Unknown' } elseif ($capped) { 'CappedLowerBound' } elseif (-not $records.Count) { 'NoRecordsObserved' } else { 'ObservedRetainedRecords' })
        WindowStartUtc=$StartUtc.ToString('o'); WindowEndUtc=$EndUtc.ToString('o'); WindowSeconds=$seconds; RecordCap=$Cap; SampleCount=$records.Count; Capped=$capped
        RetainedRecordsPerSecond=$observedRate; SampleXmlUtf8Bytes=$(if ($completeBytes -and $valid) { $xmlBytes } else { $null }); AverageXmlUtf8BytesPerRecord=$(if ($completeBytes -and $valid -and $records.Count) { $xmlBytes/$records.Count } else { $null })
        ProjectionDays=$ProjectionDays; ProjectedXmlUtf8Bytes=$projection; ProjectionKind=$(if ($null -eq $projection) { 'Unknown' } elseif ($capped) { 'Lower-bound scenario' } else { 'Conditional scenario' })
        ByteBasis='UTF-8 encoded event XML, excluding rendered Message. Not native EVTX bytes, compressed archive size, index/replica overhead or available capacity.'
        RateBasis='Retained records whose TimeCreated falls in the declared window; not measured arrival throughput. Collector timestamps originate at sources. Clears, overwrites, disabled logging, clock error and sampling can omit events.'
        Assumptions='Extrapolation assumes the sampled retained-event mix/rate persists. No retention capacity or loss-free coverage is inferred from buffers or a zero sample.'; Diagnostic=$Read.Diagnostic
    }
}

function Get-WelaRetentionNativeEvidence {
    param([string]$File,[string[]]$Arguments)
    try { $result=Invoke-WelaNative -FilePath $File -Arguments $Arguments; [pscustomobject]@{ Status='CommandSucceeded'; Command=$File; Arguments=$Arguments; Raw=[string]::Concat($result.Diagnostic); Diagnostic='Raw localized evidence; command success alone does not establish health.' } }
    catch { [pscustomobject]@{ Status='Unknown'; Command=$File; Arguments=$Arguments; Raw=$null; Diagnostic=$_.ToString() } }
}

function Get-WelaRetentionTime {
    $results=@()
    foreach ($arguments in @(@('/query','/status','/verbose'),@('/query','/source'),@('/query','/configuration'))) { $results += Get-WelaRetentionNativeEvidence -File 'w32tm.exe' -Arguments $arguments }
    [pscustomobject]@{ Observations=$results; SynchronizationHealth='Unknown'; CrossHostClockAgreement='Not tested'; Basis='Local read-only w32tm queries; localized text is retained without interpreting English labels or inferring accurate shared time.' }
}

function Get-WelaRetentionSubscriptions {
    param([string[]]$Ids)
    foreach ($id in $Ids) {
        $definition=Get-WelaRetentionNativeEvidence 'wecutil.exe' @('gs',$id,'/f:xml')
        $runtime=Get-WelaRetentionNativeEvidence 'wecutil.exe' @('gr',$id)
        $enabled=$null; $query=$null; $scope='Unknown'; $diagnostic=''
        if ($definition.Status -eq 'CommandSucceeded') {
            try {
                $doc=Read-WelaWefXml $definition.Raw
                $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable); $ns.AddNamespace('s','http://schemas.microsoft.com/2006/03/windows/events/subscription')
                $enabledNodes=@($doc.SelectNodes('/s:Subscription/s:Enabled',$ns)); $queryNodes=@($doc.SelectNodes('/s:Subscription/s:Query',$ns))
                if ($enabledNodes.Count -ne 1 -or $queryNodes.Count -ne 1 -or $enabledNodes[0].InnerText -cnotin @('true','false')) { throw 'Subscription definition lacks unique explicit Enabled/Query fields.' }
                $query=ConvertFrom-WelaWefQuery $queryNodes[0].InnerText; $enabled=$enabledNodes[0].InnerText -eq 'true'; $scope='NativeQueryObserved'
            } catch { $diagnostic=$_.ToString() }
        }
        [pscustomobject]@{ Id=$id; Enabled=$enabled; QueryScope=$scope; Query=$query; Definition=$definition; Runtime=$runtime; Diagnostic=$diagnostic; DeliveryHealth='Unknown'; Backlog='Unknown'; ActualArrival='Not tested' }
    }
}

function Get-WelaRetentionSignal {
    param([string]$Channel,[datetime]$StartUtc,[datetime]$EndUtc,[int]$Cap,[int[]]$Ids,[int[]]$Levels,[string]$Provider,[string]$Meaning)
    $read=Read-WelaRetentionEvents -Channel $Channel -StartUtc $StartUtc -EndUtc $EndUtc -Limit ($Cap+1) -Ids $Ids -Levels $Levels -Provider $Provider
    [pscustomobject]@{ Channel=$Channel; Status=$read.Status; Records=@($read.Records | Select-Object -First $Cap); Capped=($read.Records.Count -gt $Cap); Meaning=$Meaning; Diagnostic=$read.Diagnostic; AbsenceOfLoss='Not established'; WindowStartUtc=$StartUtc.ToString('o'); WindowEndUtc=$EndUtc.ToString('o') }
}

function Get-WelaRetentionArchiveDirectory {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[*?\[\]]|(^|\\)\.\.?(\\|$)' -or $Path.Substring(2).Contains(':')) { throw 'Archive inventory requires an exact local drive directory; UNC, wildcards, relative/device paths and streams are unsupported.' }
    $directory=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or ([int]$directory.Attributes -band [int][IO.FileAttributes]::ReparsePoint)) { throw 'Archive directory must be a regular existing local directory.' }
    $drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot($directory.FullName))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Archive inventory supports a local fixed drive only; remote/mapped storage requires separately supplied local evidence.' }
    $parent=$directory.Parent
    while ($parent) { if ([int]$parent.Attributes -band [int][IO.FileAttributes]::ReparsePoint) { throw 'Archive ancestry contains a reparse point.' }; $parent=$parent.Parent }
    return [string]$directory.FullName
}

function Get-WelaRetentionArchive {
    param($Declaration,[datetime]$NowUtc)
    $result=[ordered]@{ Declaration=$Declaration; DeclarationVerified=$false; ReferenceMinimumMonths=18; Reference='ASD Windows event logging and forwarding, October 2021'; ObservedDirectory=$null; Files=@(); InventoryCapped=$null; ObservedEvtxFileBytes=$null; IntendedReaders=@(); EffectiveReaderAccess='Not tested'; AchievedRetentionCompliance='Not established'; Status='NotDeclared'; Diagnostic='' }
    if (-not $Declaration) { return [pscustomobject]$result }
    $result.Status='DeclarationOnly'
    if (-not $Declaration.Directory) { return [pscustomobject]$result }
    try {
        $directory=Get-WelaRetentionArchiveDirectory $Declaration.Directory
        $acl=Get-Acl -LiteralPath $directory -ErrorAction Stop
        $sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)
        $aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{ Sid=$_.IdentityReference.Value; Rights=[string]$_.FileSystemRights; Type=[string]$_.AccessControlType; Inherited=$_.IsInherited; InheritanceFlags=[string]$_.InheritanceFlags; PropagationFlags=[string]$_.PropagationFlags } })
        $result.ObservedDirectory=[pscustomobject]@{ Path=$directory; SecurityDescriptor=[string]$sddl; Aces=$aces; ReaderAuthorization='Not tested'; ArchiveProtection='Not established' }
        foreach ($sid in $Declaration.ReaderSids) { $result.IntendedReaders += [pscustomobject]@{ Sid=$sid; DirectDirectoryAces=@($aces | Where-Object Sid -eq $sid); EffectiveReadAccess='Not tested'; Basis='Observed directory ACEs do not resolve group membership, denies, privileges, individual file ACLs or the reader token.' } }
        $files=@(Get-ChildItem -LiteralPath $directory -Filter '*.evtx' -File -Force -ErrorAction Stop | Select-Object -First ($Declaration.MaxFiles+1))
        $result.InventoryCapped=$files.Count -gt $Declaration.MaxFiles; $bytes=[long]0
        foreach ($file in @($files | Select-Object -First $Declaration.MaxFiles)) {
            if ([int]$file.Attributes -band [int][IO.FileAttributes]::ReparsePoint) { $result.Files += [pscustomobject]@{ Path=[string]$file.FullName; Status='SkippedReparsePoint'; FileBytes=$null; Age=$null }; continue }
            $first=Read-WelaRetentionEvents -Path $file.FullName -Limit 1 -Oldest; $last=Read-WelaRetentionEvents -Path $file.FullName -Limit 1
            $bytes += $file.Length
            $result.Files += [pscustomobject]@{ Path=[string]$file.FullName; Status=$(if ($first.Status -eq 'Unknown' -or $last.Status -eq 'Unknown') { 'UnknownEventBoundaries' } else { 'Inventoried' }); FileBytes=[long]$file.Length; LastWriteUtc=$file.LastWriteTimeUtc.ToString('o'); Age=(Get-WelaRetentionAge $first $last $NowUtc); ContentScope='Selected local EVTX boundaries only; file contents and complete source coverage are not validated.'; ReaderAccess='Not tested' }
        }
        $result.ObservedEvtxFileBytes=$bytes; $result.Status=if (@($result.Files | Where-Object Status -ne 'Inventoried').Count) { 'PartialInventory' } else { 'LocalInventoryObserved' }
        $result.Diagnostic='Nonrecursive bounded directory enumeration; selection order is filesystem-dependent. File bytes are logical lengths of inventoried files, not allocated-on-disk size or verified usable archive capacity. External policy, storage security and recovery remain unverified.'
    } catch { $result.Status='Unknown'; $result.Diagnostic=$_.ToString() }
    [pscustomobject]$result
}

function Compare-WelaRetentionBoundary {
    param($Current,$Previous)
    if (-not $Previous) { return [pscustomobject]@{ Status='NoPreviousReport'; Cause='Unknown' } }
    $before=$Previous.Buffer.OldestRecordNumber; $after=$Current.Buffer.OldestRecordNumber
    $valid=($before -is [int] -or $before -is [long]) -and ($after -is [int] -or $after -is [long]) -and $before -ge 0 -and $after -ge 0
    $status=if (-not $valid) { 'Unknown' } elseif ($after -gt $before) { 'OldestRecordBoundaryAdvanced' } elseif ($after -lt $before) { 'OldestRecordBoundaryReset' } else { 'NoBoundaryChangeObserved' }
    [pscustomobject]@{ Status=$status; PreviousOldestRecordNumber=$before; CurrentOldestRecordNumber=$after; Cause='Unknown'; LostEventCount=$null; Basis='A boundary change is a rollover/clear/other-change signal, not proof of event loss or successful forwarding. An unchanged boundary also cannot prove continuity.' }
}

function Invoke-WelaRetentionHealth {
    param([string]$ConfigPath,[string]$PreviousPath,[string]$ResultsPath,[string]$HtmlPath)
    $config=Import-WelaRetentionConfig $ConfigPath
    foreach ($output in @($ResultsPath,$HtmlPath) | Where-Object { $_ }) {
        foreach ($inputPath in @($ConfigPath,$PreviousPath) | Where-Object { $_ }) {
            if ([IO.Path]::GetFullPath($output) -ieq [IO.Path]::GetFullPath($inputPath)) { throw 'Retention output must not overwrite the configuration or previous evidence input.' }
        }
    }
    if ($ResultsPath -and $HtmlPath -and [IO.Path]::GetFullPath($ResultsPath) -ieq [IO.Path]::GetFullPath($HtmlPath)) { throw 'JSON and HTML outputs require separate paths.' }
    if ($env:OS -ne 'Windows_NT') { throw 'Retention health reads native local Windows event logs.' }
    $now=[DateTime]::UtcNow; $start=$now.AddMinutes(-$config.SampleWindowMinutes); $previous=$null
    if ($PreviousPath) {
        $previous=Get-Content -LiteralPath $PreviousPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($previous.SchemaVersion -ne 1 -or $previous.Scope -cne 'native-local-retention-health' -or $previous.ComputerName -ine $env:COMPUTERNAME -or $previous.RoleDeclaration -cne $config.Role -or -not $previous.RecordedUtc -or [datetime]$previous.RecordedUtc -ge $now) { throw 'Previous evidence must be an earlier retention report from the same computer and declared role.' }
    }
    $channels=@()
    foreach ($channel in $config.Channels) {
        $buffer=Get-WelaRetentionBuffer $channel
        $first=Read-WelaRetentionEvents -Channel $channel -Limit 1 -Oldest; $last=Read-WelaRetentionEvents -Channel $channel -Limit 1
        $sample=Read-WelaRetentionEvents -Channel $channel -StartUtc $start -EndUtc $now -Limit ($config.MaxEventsPerChannel+1)
        $age=Get-WelaRetentionAge $first $last $now
        $row=[pscustomobject]@{ Channel=$channel; Buffer=$buffer; Age=$age; Rate=(Get-WelaRetentionRate $sample $start $now $config.MaxEventsPerChannel $config.ProjectionDays); CollectionRoleDeclaration=$config.Role; ObservedLatestRecordStale=$null; Backlog='Unknown' }
        if ($last.Status -eq 'Observed' -and $last.Records[0].TimeCreatedUtc) {
            try { $latest=[datetime]::Parse($last.Records[0].TimeCreatedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime(); if ($latest -le $now) { $row.ObservedLatestRecordStale=($now-$latest).TotalMinutes -gt $config.StaleAfterMinutes } } catch { }
        }
        $prior=@(if ($previous) { $previous.Channels | Where-Object Channel -eq $channel | Select-Object -First 1 })
        $row | Add-Member NoteProperty BoundaryComparison (Compare-WelaRetentionBoundary $row $(if ($prior.Count) { $prior[0] } else { $null }))
        $channels += $row
    }
    $signals=@(Get-WelaRetentionSignal -Channel Security -StartUtc $start -EndUtc $now -Cap $config.MaxEventsPerChannel -Ids @(1101,1102,1104,1105,1108) -Provider 'Microsoft-Windows-Eventlog' -Meaning 'Audit transport drop, clear, full, automatic backup or processing-error indicators; inspect event ID/XML/message. No loss total is inferred.')
    $signals+=Get-WelaRetentionSignal -Channel System -StartUtc $start -EndUtc $now -Cap $config.MaxEventsPerChannel -Ids @(104) -Provider 'Microsoft-Windows-Eventlog' -Meaning 'Event-log clear indicator; affected channel remains in event XML.'
    $forwardChannel=if ($config.Role -eq 'Collector') { 'Microsoft-Windows-EventCollector/Operational' } else { 'Microsoft-Windows-Forwarding/Operational' }
    $signals+=Get-WelaRetentionSignal -Channel $forwardChannel -StartUtc $start -EndUtc $now -Cap $config.MaxEventsPerChannel -Levels @(1,2,3) -Meaning 'Recent critical/error/warning forwarding or collection indicators. Their absence does not establish healthy delivery.'
    $subscriptions=@(Get-WelaRetentionSubscriptions @($config.SubscriptionIds))
    $archive=Get-WelaRetentionArchive $config.Archive $now
    $time=Get-WelaRetentionTime
    $unknown=@($channels | Where-Object { $_.Buffer.Status -in @('Unknown','NotInstalled','Partial') -or $_.Age.Status -eq 'Unknown' -or $_.Rate.Status -eq 'Unknown' }).Count -gt 0 -or $archive.Status -in @('Unknown','PartialInventory') -or @($signals | Where-Object Status -eq 'Unknown').Count -gt 0 -or @($time.Observations | Where-Object Status -eq 'Unknown').Count -gt 0 -or @($subscriptions | Where-Object { $_.QueryScope -eq 'Unknown' -or $_.Runtime.Status -eq 'Unknown' }).Count -gt 0
    $report=[pscustomobject][ordered]@{ SchemaVersion=1; Scope='native-local-retention-health'; RecordedUtc=$now.ToString('o'); ComputerName=$env:COMPUTERNAME; RoleDeclaration=$config.Role; ExitCode=$(if ($unknown) { 1 } else { 0 }); AssessmentStatus=$(if ($unknown) { 'PartialEvidence' } else { 'ObservationsCollected' }); Config=$config; Channels=$channels; Archive=$archive; Signals=$signals; Subscriptions=$subscriptions; Time=$time; EndToEndDelivery='Not tested'; RetentionCompliance='Not established'; SigmaCoverage='Not assessed'; Limits=@('Local source/collector roles are declared; remote host state is not observed.','Boundary ages, buffer sizes and declarations do not prove complete event coverage or 18-month compliance.','Stale source timestamps can reflect quiet periods, source clocks or replay; backlog and arrival latency remain unknown.','Reader token authorization, multi-host clock comparison, rollover/recovery and representative event arrivals require an isolated lab.') }
    Write-Host 'Retention evidence collected. Complete coverage, achieved archive compliance, shared time and end-to-end delivery remain unverified.' -ForegroundColor Yellow
    $channels | Select-Object Channel,@{n='BufferBytes';e={$_.Buffer.MaximumBytes}},@{n='Mode';e={$_.Buffer.Mode}},@{n='BoundaryAgeDays';e={$_.Age.OldestReadableRecordAgeDays}},@{n='Sample';e={$_.Rate.SampleCount}},@{n='RateStatus';e={$_.Rate.Status}} | Format-Table -AutoSize | Out-Host
    Write-Host "Archive: $($archive.Status); declared months: $($archive.Declaration.DeclaredRetentionMonths); achieved compliance: not established. Time synchronization and forwarding health: unknown."
    if ($HtmlPath) { try { Export-WelaRetentionHtml $report $HtmlPath } catch { $report.ExitCode=1; Write-Host "[Failed] Retention HTML export: $_" -ForegroundColor Red } }
    if ($ResultsPath) { try { $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop } catch { $report.ExitCode=1; Write-Host "[Failed] Retention JSON export: $_" -ForegroundColor Red } }
    return $report
}

function Export-WelaRetentionHtml {
    param($Report,[string]$Path)
    $encode={ param($value) [Net.WebUtility]::HtmlEncode([string]$value) }
    $rows=@()
    foreach ($row in $Report.Channels) { $rows += '<tr>' + ((@($row.Channel,$row.Buffer.Status,$row.Buffer.MaximumBytes,$row.Buffer.Mode,$row.Age.OldestReadableRecordAgeDays,$row.Rate.Status,$row.Rate.RetainedRecordsPerSecond,$row.Rate.ProjectedXmlUtf8Bytes) | ForEach-Object { '<td>' + (& $encode $_) + '</td>' }) -join '') + '</tr>' }
    $signalRows=@()
    foreach ($signal in $Report.Signals) { $signalRows += '<tr><td>' + (& $encode $signal.Channel) + '</td><td>' + (& $encode $signal.Status) + '</td><td>' + (& $encode $signal.Records.Count) + '</td><td>' + (& $encode $signal.Capped) + '</td></tr>' }
    $summary='<h2>Archive and health evidence</h2><p>Archive inventory: ' + (& $encode $Report.Archive.Status) + '. Declared retention months: ' + (& $encode $Report.Archive.Declaration.DeclaredRetentionMonths) + '. ASD October 2021 reference: at least 18 months. Achieved retention and effective reader access are not established.</p><p>Selected collector subscriptions: ' + (& $encode $Report.Subscriptions.Count) + '. Delivery/backlog and shared time remain unknown; native localized results are preserved below.</p><table><tr><th>Signal channel</th><th>Read status</th><th>Observed indicators</th><th>Capped</th></tr>' + ($signalRows -join '') + '</table><p>Zero observed indicators does not prove no loss or healthy forwarding.</p>'
    $json=& $encode ($Report | ConvertTo-Json -Depth 20)
    $html='<!doctype html><html lang="en"><meta charset="utf-8"><title>WELA retention evidence</title><style>body{font:16px system-ui;margin:2rem;max-width:1100px}table{border-collapse:collapse}td,th{padding:.55rem;border:1px solid #bbb;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}.note{padding:1rem;background:#fff2cd}</style><h1>WELA retention and collection evidence</h1><p>' + (& $encode $Report.ComputerName) + ' · declared ' + (& $encode $Report.RoleDeclaration) + ' · ' + (& $encode $Report.RecordedUtc) + '</p><p class="note">Local buffers, recorded event boundaries, declared archive policy and actual complete retention are separate. Complete coverage, delivery, synchronized time and 18-month compliance are not established.</p><table><tr><th>Channel</th><th>Read state</th><th>Buffer bytes</th><th>Mode</th><th>Oldest-record age (days)</th><th>Sample status</th><th>Retained records/sec</th><th>Projected XML bytes</th></tr>' + ($rows -join '') + '</table><p>Rates use the declared timestamp window and cap. Projected bytes are UTF-8 XML scenarios, not EVTX size, archive capacity or measured collector arrivals. See the complete evidence for assumptions, raw localized diagnostics, archive ACLs and unknown states.</p>' + $summary + '<h2>Complete evidence</h2><pre>' + $json + '</pre></html>'
    [IO.File]::WriteAllText($Path,$html,(New-Object Text.UTF8Encoding($false)))
}
