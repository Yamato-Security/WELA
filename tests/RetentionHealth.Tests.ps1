# Bounded public-report fixtures. Native reads are mocked; no Windows mutations.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/WefSubscriptions.psm1') -Force
. (Join-Path $repo 'scripts/RetentionHealth.ps1')
$script:count=0
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" }; $script:count++ }
function Assert-Throws([scriptblock]$Code,[string]$Message) { $caught=$false; try { & $Code | Out-Null } catch { $caught=$true }; Assert $caught $Message }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-retention-' + [guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory $temp
$configPath=Join-Path $temp 'config.json'; $jsonPath=Join-Path $temp 'report.json'; $htmlPath=Join-Path $temp 'report.html'
$savedOS=$env:OS; $savedComputer=$env:COMPUTERNAME
function Reset-Fixture {
    $script:fixture=@{ Denied=''; Empty=''; Capped=$false; Future=$false; MissingXml=$false; OldestId=20; TimeFailure=$false; SubscriptionFailure=$false; ArchiveFailure=$false; Reads=(New-Object 'System.Collections.Generic.List[object]') }
    $script:config=[pscustomobject]@{ SchemaVersion=1; Role='Source'; Channels=@('Security','System'); SampleWindowMinutes=60; MaxEventsPerChannel=2; StaleAfterMinutes=60; ProjectionDays=30 }
    Save-Config
}
function Save-Config { $script:config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding UTF8 }
function New-FixtureEvent([string]$Channel,[datetime]$Time,[long]$RecordId=30) {
    $event=[pscustomobject]@{ RecordId=$RecordId; Id=1104; ProviderName='Microsoft-Windows-Eventlog'; LogName=$Channel; MachineName='fixture-source'; Level=2; TimeCreated=$Time; Message='Localized <script>alert(1)</script> message' }
    $event | Add-Member ScriptMethod ToXml { if ($script:fixture.MissingXml) { throw 'Fixture XML access failure' }; return '<Event><System><EventID>1104</EventID></System></Event>' }
    return $event
}
function Get-WinEvent {
    param($ListLog,$LogName,$FilterHashtable,$Path,$MaxEvents,[switch]$Oldest)
    $channel=if ($ListLog) { $ListLog } elseif ($FilterHashtable) { $FilterHashtable.LogName } elseif ($Path) { 'Security' } else { $LogName }
    $script:fixture.Reads.Add([pscustomobject]@{ Channel=$channel; MaxEvents=$MaxEvents; Path=$Path; Filter=$FilterHashtable; Oldest=[bool]$Oldest })
    if ($script:fixture.Denied -eq $channel) { throw 'Fixture access denied' }
    if ($ListLog) { return [pscustomobject]@{ LogName=$channel; MaximumSizeInBytes=[long]2147483648; FileSize=[long]65536; RecordCount=100; OldestRecordNumber=$script:fixture.OldestId; IsLogFull=$false; IsEnabled=$true; LogMode='Circular'; SecurityDescriptor='O:BAG:SYD:(A;;0x1;;;SY)' } }
    if ($script:fixture.Empty -eq $channel) { return }
    if ($Oldest) { return New-FixtureEvent $channel ([datetime]::UtcNow.AddDays($(if ($script:fixture.Future) { 1 } else { -800 }))) 20 }
    if ($FilterHashtable -and ($FilterHashtable.Id -or $FilterHashtable.Level)) { return New-FixtureEvent $channel $FilterHashtable.StartTime.AddMinutes(5) }
    if ($FilterHashtable) {
        New-FixtureEvent $channel $FilterHashtable.StartTime.AddMinutes(30)
        if ($script:fixture.Capped) { New-FixtureEvent $channel $FilterHashtable.StartTime.AddMinutes(20); New-FixtureEvent $channel $FilterHashtable.StartTime.AddMinutes(10) }
        return
    }
    return New-FixtureEvent $channel ([datetime]::UtcNow.AddMinutes(-120))
}
function Invoke-WelaNative {
    param($FilePath,$Arguments)
    Assert ($FilePath -in @('w32tm.exe','wecutil.exe')) 'Only selected native read utilities are invoked'
    if ($FilePath -eq 'w32tm.exe') {
        Assert ($Arguments[0] -eq '/query' -and ($Arguments -join ' ') -notmatch '/computer|/resync|/config\s') 'Time evidence uses local query operations only'
        if ($script:fixture.TimeFailure) { throw 'Localized native time query failure, exit 5' }
        return [pscustomobject]@{ Diagnostic='Zeitquelle: Quelle <unsafe>; letzter Status unbekannt'; ExitCode=0 }
    }
    Assert ($Arguments[0] -in @('gs','gr')) 'WEF reporting cannot create/change/retry subscriptions'
    if ($script:fixture.SubscriptionFailure) { throw 'Native subscription query access denied' }
    $text=if ($Arguments[0] -eq 'gr') { 'Localized runtime status: fixture' } else { '<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription"><Enabled>false</Enabled><Query><![CDATA[<QueryList><Query Id="0" Path="Security"><Select>*</Select></Query></QueryList>]]></Query></Subscription>' }
    return [pscustomobject]@{ Diagnostic=$text; ExitCode=0 }
}
function Get-WelaRetentionArchiveDirectory {
    param($Path)
    if ($script:fixture.ArchiveFailure) { throw 'Fixture directory access denied' }; return 'C:\Archive'
}
function Get-Acl {
    param($LiteralPath)
    $acl=[pscustomobject]@{}
    $acl | Add-Member ScriptMethod GetSecurityDescriptorSddlForm { param($Sections) 'O:BAG:SYD:(A;;FR;;;S-1-5-21-1-2-3-1000)' }
    $acl | Add-Member ScriptMethod GetAccessRules { param($Explicit,$Inherited,$Type) [pscustomobject]@{ IdentityReference=[pscustomobject]@{ Value='S-1-5-21-1-2-3-1000' }; FileSystemRights='Read'; AccessControlType='Allow'; IsInherited=$false; InheritanceFlags='ContainerInherit, ObjectInherit'; PropagationFlags='None' } }
    return $acl
}
function Get-ChildItem {
    param($LiteralPath,$Filter,[switch]$File,[switch]$Force)
    Assert ($Filter -eq '*.evtx' -and $File) 'Archive inventory selects only local EVTX files'
    foreach ($number in 1..3) { [pscustomobject]@{ FullName="C:\Archive\file$number.evtx"; Attributes=[IO.FileAttributes]::Normal; Length=[long]65536; LastWriteTimeUtc=[datetime]::UtcNow } }
}
function Run-Report { Invoke-WelaRetentionHealth -ConfigPath $configPath -ResultsPath $jsonPath -HtmlPath $htmlPath }
try {
    $env:OS='Windows_NT'; $env:COMPUTERNAME='fixture-host <script>host</script>'
    $default=Import-WelaRetentionConfig
    Assert ($default.Role -eq 'Source' -and $default.Channels.Count -eq 3 -and -not $default.Archive) 'Default assessment needs no archive declaration/config file'
    Reset-Fixture
    $report=Run-Report
    $json=Get-Content $jsonPath -Raw | ConvertFrom-Json
    Assert ($json.Channels.Count -eq 2 -and $json.Channels[0].Buffer.MaximumBytes -eq 2147483648) 'Public report retains separate selected buffer observations'
    Assert ($json.Channels[0].Age.OldestReadableRecordAgeDays -gt 799 -and $json.RetentionCompliance -eq 'Not established') 'An 800-day-old record does not prove 18-month retention compliance'
    Assert ($json.Channels[0].Age.CompleteEventCoverage -eq 'Unknown') 'Observed boundary age never implies continuous event coverage'
    Assert ($json.Channels[0].Rate.SampleCount -eq 1 -and [math]::Abs($json.Channels[0].Rate.RetainedRecordsPerSecond-(1/3600)) -lt 0.00000001) 'Rate denominator is the explicit 3600-second timestamp window'
    $expectedBytes=[Text.Encoding]::UTF8.GetByteCount('<Event><System><EventID>1104</EventID></System></Event>')
    Assert ($json.Channels[0].Rate.SampleXmlUtf8Bytes -eq $expectedBytes -and $json.Channels[0].Rate.ProjectedXmlUtf8Bytes -eq $expectedBytes*24*30) 'XML byte projection uses measured serialized bytes and declared horizon'
    Assert ($json.Channels[0].Rate.ByteBasis -like '*Not native EVTX bytes*') 'Storage byte assumptions are explicit'
    Assert ($json.Channels[0].ObservedLatestRecordStale -and $json.Channels[0].Backlog -eq 'Unknown') 'Old source timestamps are a stale signal rather than invented backlog'
    Assert ($json.Time.SynchronizationHealth -eq 'Unknown' -and $json.Time.Observations[0].Raw -like 'Zeitquelle*') 'Localized time output is preserved without English-field parsing or synchronization claims'
    Assert ($json.Signals.Count -eq 3 -and $json.Signals[0].AbsenceOfLoss -eq 'Not established') 'Loss/clear/forwarding evidence is reported independently'
    Assert ($json.Archive.Status -eq 'NotDeclared') 'Archive declaration remains distinct from large source buffers'
    $html=Get-Content $htmlPath -Raw
    Assert ($html -notmatch '<script' -and $html -match '&lt;script&gt;host&lt;/script&gt;') 'Untrusted summary text is HTML-escaped without active script markup'
    # Windows PowerShell 5.1 may JSON-escape angle brackets before HTML encoding.
    # Assert the payload round-trip, not one serializer's equivalent spelling.
    $embeddedMatch=[regex]::Match($html,'<pre>([\s\S]*?)</pre>')
    Assert $embeddedMatch.Success 'Self-contained HTML retains the complete JSON evidence'
    $embedded=[Net.WebUtility]::HtmlDecode($embeddedMatch.Groups[1].Value) | ConvertFrom-Json
    Assert ($embedded.Signals[0].Records[0].Message -ceq 'Localized <script>alert(1)</script> message') 'Escaped event evidence round-trips without losing or activating its text'
    Assert (@($script:fixture.Reads | Where-Object { $_.MaxEvents -gt 3 }).Count -eq 0) 'All fixture queries obey cap plus one sentinel'
    $oldReport=Join-Path $temp 'previous.json'; Copy-Item $jsonPath $oldReport
    $script:fixture.OldestId=40
    $report=Invoke-WelaRetentionHealth -ConfigPath $configPath -PreviousPath $oldReport
    Assert ($report.Channels[0].BoundaryComparison.Status -eq 'OldestRecordBoundaryAdvanced' -and $null -eq $report.Channels[0].BoundaryComparison.LostEventCount) 'Boundary advance flags rollover/clear uncertainty without inventing loss count'
    Reset-Fixture; $script:fixture.Capped=$true
    $report=Run-Report
    Assert ($report.Channels[0].Rate.Capped -and $report.Channels[0].Rate.SampleCount -eq 2 -and $report.Channels[0].Rate.Status -eq 'CappedLowerBound') 'A cap never produces an uncapped EPS claim'
    Assert ($report.Channels[0].Rate.ProjectionKind -eq 'Lower-bound scenario') 'Capped projections retain their lower-bound qualification'
    Reset-Fixture; $script:fixture.Empty='Security'
    $report=Run-Report
    Assert ($report.Channels[0].Age.Status -eq 'NoRecordsObserved' -and $null -eq $report.Channels[0].Rate.ProjectedXmlUtf8Bytes) 'Empty observations do not imply zero required capacity or a retained history'
    Reset-Fixture; $script:fixture.Denied='Security'; $script:fixture.TimeFailure=$true
    $report=Run-Report
    Assert ($report.ExitCode -eq 1 -and $report.Channels[0].Buffer.Status -eq 'Unknown' -and $report.Channels[1].Buffer.Status -eq 'Observed') 'Denied channels/native queries do not erase independent channel observations'
    Assert ($null -eq $report.Channels[0].Rate.RetainedRecordsPerSecond -and $report.Signals[0].Status -eq 'Unknown') 'Access denied never becomes zero event/loss evidence'
    Reset-Fixture; $script:fixture.Future=$true
    $report=Run-Report
    Assert ($report.Channels[0].Age.Status -eq 'ClockOrTimestampAnomaly' -and $null -eq $report.Channels[0].Age.OldestReadableRecordAgeDays) 'Future record timestamps cannot produce negative achieved retention'
    Reset-Fixture; $script:fixture.MissingXml=$true
    $report=Run-Report
    Assert ($null -eq $report.Channels[0].Rate.ProjectedXmlUtf8Bytes) 'Missing XML bytes prevent storage extrapolation'
    Reset-Fixture
    $config.Role='Collector'; $config.Channels=@('ForwardedEvents'); $config | Add-Member NoteProperty SubscriptionIds @('Reviewed Subscription')
    $config | Add-Member NoteProperty Archive ([pscustomobject]@{ DeclaredRetentionMonths=18; PolicyEvidence='External immutable archive policy (declared)'; Directory='C:\Archive'; MaxFiles=2; ReaderSids=@('S-1-5-21-1-2-3-1000') }); Save-Config
    $report=Run-Report
    Assert ($report.Archive.Declaration.DeclaredRetentionMonths -eq 18 -and -not $report.Archive.DeclarationVerified -and $report.Archive.AchievedRetentionCompliance -eq 'Not established') 'Archive policy declaration is never promoted to achieved compliance'
    Assert ($report.Archive.InventoryCapped -and $report.Archive.Files.Count -eq 2 -and $report.Archive.ObservedEvtxFileBytes -eq 131072) 'Local EVTX inventory has a separate bounded logical-byte basis'
    Assert ($report.Archive.IntendedReaders[0].DirectDirectoryAces.Count -eq 1 -and $report.Archive.IntendedReaders[0].EffectiveReadAccess -eq 'Not tested') 'An observed reader ACE does not prove effective archive/file access'
    Assert ($report.Subscriptions[0].Enabled -eq $false -and $report.Subscriptions[0].Runtime.Raw -like '*fixture*' -and $report.Subscriptions[0].DeliveryHealth -eq 'Unknown') 'Disabled subscription and raw runtime evidence stay distinct from healthy delivery'
    Assert ($report.Channels[0].Rate.RateBasis -like '*not measured arrival throughput*') 'Forwarded-event timestamp density is not arrival EPS'
    $script:fixture.ArchiveFailure=$true; $script:fixture.SubscriptionFailure=$true
    $report=Run-Report
    Assert ($report.ExitCode -eq 1 -and $report.Archive.Status -eq 'Unknown' -and $report.Channels[0].Buffer.Status -eq 'Observed') 'Archive and WEF failures preserve collector buffer evidence'
    Reset-Fixture; $config.Channels=@('Microsoft-Windows-Sysmon/Operational'); Save-Config
    Assert-Throws { Import-WelaRetentionConfig $configPath } 'Sysmon channel input is excluded'
    Reset-Fixture; $config.Channels=@('Security*'); Save-Config
    Assert-Throws { Import-WelaRetentionConfig $configPath } 'Wildcard channels cannot expand the read scope'
    Reset-Fixture; $config.MaxEventsPerChannel=10001; Save-Config
    Assert-Throws { Import-WelaRetentionConfig $configPath } 'Sampling limits are bounded before native reads'
    Reset-Fixture; $config | Add-Member NoteProperty EnableArchive $true; Save-Config
    Assert-Throws { Import-WelaRetentionConfig $configPath } 'Unknown input fields cannot silently authorize archive changes'
    Reset-Fixture
    $prior=Get-Content $oldReport -Raw | ConvertFrom-Json; $prior.ComputerName='another-host'; $prior | ConvertTo-Json -Depth 20 | Set-Content $oldReport
    Assert-Throws { Invoke-WelaRetentionHealth -ConfigPath $configPath -PreviousPath $oldReport } 'Cross-host snapshots cannot imply local rollover continuity'
    Assert-Throws { Invoke-WelaRetentionHealth -ConfigPath $configPath -ResultsPath $configPath } 'A report cannot overwrite its configuration input'
    Assert-Throws { Invoke-WelaRetentionHealth -ConfigPath $configPath -ResultsPath $jsonPath -HtmlPath $jsonPath } 'JSON and HTML cannot overwrite each other'
    Write-Host "RetentionHealth.Tests: $script:count assertions passed. No Windows configuration changed."
} finally { $env:OS=$savedOS; $env:COMPUTERNAME=$savedComputer; Remove-Item -LiteralPath $temp -Recurse -Force }
$global:LASTEXITCODE=0
