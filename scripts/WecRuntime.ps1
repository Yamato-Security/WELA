# Local, explicitly selected WEC runtime reads; no service/subscription changes.
function Initialize-WelaWecRuntimeNative {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {throw 'Typed WEC runtime requires native 64-bit Windows.'}
    if (-not ('Wela.WecRuntime.Native' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'WecRuntimeNative.cs') -ErrorAction Stop}
}
function Read-WelaWecRuntimeValue {
    param([string]$Id,[AllowNull()][string]$Source,[int]$Property)
    Initialize-WelaWecRuntimeNative
    # PowerShell converts $null to an empty .NET string; the native API requires
    # a genuine null pointer to select subscription-level status.
    [Wela.WecRuntime.Native]::Read($Id,$(if ($Source) {$Source} else {[NullString]::Value}),$Property)
}
function ConvertTo-WelaWecRuntimeField {
    param($Value,[int]$Property)
    $row=[pscustomobject]@{Status=$Value.State;NativeType=$Value.NativeType;ErrorCode=$Value.ErrorCode;Value=$null;RawFileTime=$null;Diagnostic=$Value.Diagnostic}
    if ($Value.State -notin @('Observed','NotAvailable','Unknown')) {throw 'Invalid native observation status.'}
    if ($Value.State -ne 'Observed') {
        if ($Value.State -eq 'NotAvailable' -and $Property -in @(0,1,5)) {$row.Status='Unknown';$row.Diagnostic='Required native activity/error/source-inventory value is unavailable.'}
        return $row
    }
    switch ($Property) {
        {$_ -in @(0,1)} {
            if ($Value.NativeType -ne 2 -or $Value.Data -isnot [uint32]) {throw 'Runtime status/error requires native UInt32.'}
            $row.Value=$Value.Data
            if ($Property -eq 0 -and $Value.Data -notin @(1,2,3,4)) {$row.Status='Unknown';$row.Diagnostic='Unrecognized native activity enum; numeric value retained.'}
        }
        2 {if ($Value.NativeType -ne 4 -or $Value.Data -isnot [string]) {throw 'Runtime message requires native String.'};$row.Value=$Value.Data}
        {$_ -in @(3,4,6)} {
            if ($Value.NativeType -ne 3 -or $Value.Data -isnot [uint64]) {throw 'Runtime time requires native FILETIME.'}
            $row.RawFileTime=$Value.Data.ToString([Globalization.CultureInfo]::InvariantCulture)
            if ($Value.Data -eq 0) {$row.Status='NotAvailable';$row.Diagnostic='Zero FILETIME; no observed timestamp.'}
            else {try {$row.Value=[DateTime]::FromFileTimeUtc([long]$Value.Data).ToString('o')} catch {$row.Status='Unknown';$row.Diagnostic='Native FILETIME is outside the supported timestamp range.'}}
        }
        5 {
            if ($Value.NativeType -ne 132 -or $Value.Data -isnot [array] -or @($Value.Data).Count -ne $Value.Count) {throw 'Source inventory requires a native String array with matching count.'}
            $row.Value=@($Value.Data)
        }
    }
    $row
}
function Get-WelaWecRuntimeFields {
    param([string]$Id,[AllowNull()][string]$Source)
    $names=@{0='Activity';1='LastError';2='LastErrorMessage';3='LastErrorTimeUtc';4='NextRetryTimeUtc';6='LastHeartbeatTimeUtc'}
    $fields=[ordered]@{}
    foreach ($property in @(0,1,2,3,4,6)) {
        try {$fields[$names[$property]]=ConvertTo-WelaWecRuntimeField (Read-WelaWecRuntimeValue $Id $Source $property) $property}
        catch {$fields[$names[$property]]=[pscustomobject]@{Status='Unknown';NativeType=$null;ErrorCode=$null;Value=$null;RawFileTime=$null;Diagnostic=$_.Exception.Message}}
    }
    $activity='Unknown'
    if ($fields.Activity.Status -eq 'Observed') {$activity=@{1='Disabled';2='Active';3='Inactive';4='Trying'}[[int]$fields.Activity.Value]}
    [pscustomobject]@{Source=$Source;Activity=$activity;Fields=[pscustomobject]$fields;Complete=(@($fields.Values | Where-Object Status -eq 'Unknown').Count -eq 0)}
}
function Get-WelaWecRuntimeContext {
    Initialize-WelaWecRuntimeNative
    $hostContext=Get-WelaDefaultContext
    if (-not (Test-WelaDefaultContextComplete $hostContext)) {throw 'Actual collector host context is incomplete.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostContext;ReaderSid=$identity.User.Value;ReaderName=$identity.Name;AuthenticationType=$identity.AuthenticationType;ImpersonationLevel=[string]$identity.ImpersonationLevel;GroupSids=@($identity.Groups | ForEach-Object Value | Sort-Object);IsSystem=$identity.IsSystem}
    } finally {$identity.Dispose()}
}
function Get-WelaWecRuntimeDefinition {
    param([string]$Id)
    $xml=Read-WelaWecSubscriptionXml -Id $Id
    $doc=Read-WelaWefXml $xml
    $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('s','http://schemas.microsoft.com/2006/03/windows/events/subscription')
    $fields=@{}
    foreach ($name in @('SubscriptionId','SubscriptionType','Enabled','Query')) {
        $nodes=@($doc.SelectNodes('/s:Subscription/s:'+$name,$ns))
        if ($nodes.Count -ne 1) {throw "Native definition requires exactly one $name."}
        $fields[$name]=$nodes[0].InnerText
    }
    if ($fields.SubscriptionId -cne $Id -or $fields.SubscriptionType -cnotin @('SourceInitiated','CollectorInitiated') -or $fields.Enabled -cnotin @('true','false')) {throw 'Native subscription identity/type/enabled state is invalid.'}
    $query=ConvertFrom-WelaWefQuery $fields.Query
    [pscustomobject]@{Id=$Id;Type=$fields.SubscriptionType;Enabled=($fields.Enabled -eq 'true');Query=$query;RawXml=$xml;Key=(Get-WelaWefXmlKey $doc.DocumentElement)}
}
function Get-WelaWecRuntime {
    param([string]$Id,[ValidateRange(1,512)][int]$MaximumSources=128)
    $ErrorActionPreference='Stop'
    if ($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$') {throw 'Select an exact supported subscription ID.'}
    $report=[pscustomobject][ordered]@{Id=$Id;Status='Unknown';StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;CollectorBefore=$null;CollectorAfter=$null;DefinitionBefore=$null;DefinitionAfter=$null;Subscription=$null;SourceInventory=$null;Sources=@();MaximumSources=$MaximumSources;Capped=$false;SourceListChanged=$false;Diagnostic='';EventArrival='Not tested';TransmissionLatency='Not measured';Backlog='Unknown';ReadyRuleCredit=0}
    try {
        $report.CollectorBefore=Get-WelaWecRuntimeContext
        $report.DefinitionBefore=Get-WelaWecRuntimeDefinition $Id
        $report.Subscription=Get-WelaWecRuntimeFields $Id $null
        $inventory=ConvertTo-WelaWecRuntimeField (Read-WelaWecRuntimeValue $Id $null 5) 5
        $report.SourceInventory=[pscustomobject]@{Observation=$inventory;AfterObservation=$null;Meaning=$(if ($report.DefinitionBefore.Type -eq 'SourceInitiated') {'Sources the collector heard from in the past 30 days; persistent across reboot. This is not a current connection count.'} else {'Configured event sources, not a current connection count.'});ReportedCount=$null;QueriedCount=0}
        $sources=@()
        if ($inventory.Status -eq 'Observed') {$sources=@($inventory.Value);$report.SourceInventory.ReportedCount=$sources.Count}
        $seen=@{}
        foreach ($source in $sources) {if ($source -isnot [string] -or [string]::IsNullOrWhiteSpace($source) -or $source.Length -gt 32768 -or $source -match '[\x00-\x1f]' -or $seen.ContainsKey($source)) {throw 'Invalid or duplicate native source identity.'};$seen[$source]=$true}
        $report.Capped=$sources.Count -gt $MaximumSources
        $report.Sources=@(foreach ($source in ($sources | Select-Object -First $MaximumSources)) {Get-WelaWecRuntimeFields $Id $source})
        $report.SourceInventory.QueriedCount=$report.Sources.Count
        $afterInventory=ConvertTo-WelaWecRuntimeField (Read-WelaWecRuntimeValue $Id $null 5) 5
        $report.SourceInventory.AfterObservation=$afterInventory
        $afterSources=if ($afterInventory.Status -eq 'Observed') {@($afterInventory.Value | Sort-Object)} else {@()}
        if ($afterInventory.Status -ne $inventory.Status -or $afterInventory.Status -eq 'Unknown' -or (ConvertTo-Json -InputObject @($sources | Sort-Object) -Compress) -cne (ConvertTo-Json -InputObject @($afterSources) -Compress)) {$report.SourceListChanged=$true}
        $report.DefinitionAfter=Get-WelaWecRuntimeDefinition $Id
        $report.CollectorAfter=Get-WelaWecRuntimeContext
        if ($report.DefinitionAfter.Key -cne $report.DefinitionBefore.Key -or (ConvertTo-Json $report.CollectorBefore -Depth 16 -Compress) -cne (ConvertTo-Json $report.CollectorAfter -Depth 16 -Compress)) {throw 'Collector identity/context or subscription definition changed during observation.'}
        $report.Status=if ($report.Capped -or $report.SourceListChanged -or $inventory.Status -eq 'Unknown' -or -not $report.Subscription.Complete -or @($report.Sources | Where-Object {-not $_.Complete}).Count) {'Partial'} else {'Observed'}
    } catch {$report.Status=if ($null -ne $report.Subscription) {'Partial'} else {'Unknown'};$report.Diagnostic=$_.Exception.Message}
    finally {
        if ($null -ne $report.CollectorBefore -and $null -eq $report.CollectorAfter) {try {$report.CollectorAfter=Get-WelaWecRuntimeContext} catch {$report.Diagnostic+=' Final collector context unavailable: '+$_.Exception.Message}}
        $report.CompletedUtc=[DateTime]::UtcNow.ToString('o')
    }
    $report
}
function Invoke-WelaWecRuntime {
    param([string[]]$Ids,[ValidateRange(1,512)][int]$MaximumSources=128,[string]$ResultsPath)
    if (-not $Ids -or $Ids.Count -gt 32) {throw 'Select 1..32 explicit local subscription IDs.'}
    $seen=@{};foreach ($id in $Ids) {if ($id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$' -or $seen.ContainsKey($id)) {throw 'Invalid or duplicate subscription ID.'};$seen[$id]=$true}
    $output=$null
    if ($ResultsPath) {
        $provider=$null;$drive=$null;$output=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ResultsPath,[ref]$provider,[ref]$drive)
        if ($provider.Name -ne 'FileSystem' -or $output -match '^[\\/]{2}' -or $output.Substring([IO.Path]::GetPathRoot($output).Length).Contains(':') -or (Test-Path -LiteralPath $output)) {throw 'Results require a new ordinary local file without streams.'}
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($output))).DriveType -ne [IO.DriveType]::Fixed) {throw 'Results require a local fixed drive.'}
        $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($output)) -ErrorAction Stop
        for ($node=$parent;$null -ne $node;$node=$node.Parent) {if ([int]$node.Attributes -band [int][IO.FileAttributes]::ReparsePoint) {throw 'Results cannot traverse reparse points.'}}
    }
    $rows=@(foreach ($id in $Ids) {Get-WelaWecRuntime $id $MaximumSources})
    $report=[pscustomobject]@{SchemaVersion=1;Kind='WelaWecRuntime';CapturedUtc=[DateTime]::UtcNow.ToString('o');ExitCode=[int](@($rows | Where-Object Status -ne 'Observed').Count -gt 0);Subscriptions=$rows;ReadyRuleCredit=0;Scope='Local typed WEC runtime observations; API success/activity and historical source inventory do not establish successful event arrival, backlog, latency or rule readiness.'}
    if ($output) {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $report -Depth 30))
        $stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    }
    $report
}
