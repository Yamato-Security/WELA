# Fixed native DNS Client event3008 collection; no policy/channel/DNS configuration.
function Initialize-WelaDnsClientProbeNative {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'DNS Client probe requires native 64-bit Windows.'}
    $bytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'DnsClientProbeNative.cs'));$hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.DnsClientProbe.Native' -as [type])){$source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff);Add-Type -TypeDefinition $source.Replace('__WELA_DNS_CLIENT_SOURCE_SHA256__',$hash) -ErrorAction Stop}
    if([Wela.DnsClientProbe.Native]::SourceSha256 -cne $hash){throw 'Loaded DNS helper differs from source; start a fresh PowerShell process.'}
}
function Assert-WelaDnsClientResolver {
    param([string]$Resolver)
    $ip=$null
    if($Resolver -cnotmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' -or -not [Net.IPAddress]::TryParse($Resolver,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Resolver -or $ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224){throw 'Select one approved canonical unicast IPv4 DNS resolver; no hostname, port, multicast or unspecified address.'}
}
function Get-WelaDnsClientProbeSources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/DnsClientProbe.ps1','scripts/DnsClientProbeWorker.ps1','scripts/DnsClientProbeNative.cs','scripts/WefArrival.ps1','scripts/AuditRecovery.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/NativeProviderPacks.ps1','scripts/ControlApplicability.ps1','config/native_provider_packs.json','config/security_rules.json','modules/NativeProviders.psm1','modules/AuditProfiles.psm1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$name)) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    $catalog=Get-WelaProviderPackCatalog
    foreach($rule in $catalog.ruleReviews){$sources['config/'+$rule.localPath]=$rule.sha256}
    [pscustomobject]$sources
}
function Get-WelaDnsClientProbeState {
    $service=Get-Service Dnscache -ErrorAction Stop
    if($service.Status -ne 'Running'){throw 'DNS Client must already be running; no service is started.'}
    $hostState=Get-WelaDefaultContext
    if(-not(Test-WelaDefaultContextComplete $hostState) -or ($hostState.ProductType -eq 1 -and $hostState.Build -notin @(22000,22621,22631,26100,26200)) -or ($hostState.ProductType -in @(2,3) -and $hostState.Build -notin @(20348,26100))){throw 'Complete reviewed Windows 11/Server2022/2025 context required.'}
    $catalog=Get-WelaProviderPackCatalog;$pack=@($catalog.packs|Where-Object id -ceq 'dns-client')[0]
    $schema=Get-WelaProviderPackSchema $pack
    $channel=Get-WelaNativeChannel $pack.channel
    $engine=(Get-Process -Id $PID -ErrorAction Stop).Path
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostState;Service=[string]$service.Status;Schema=$schema;Channel=$channel;Engine=$engine;EngineSha256=(Get-FileHash $engine -Algorithm SHA256).Hash.ToLowerInvariant();Sources=(Get-WelaDnsClientProbeSources);RuleReviews=@($catalog.ruleReviews|Where-Object {$pack.ruleIds -contains $_.id}|Select-Object id,title,sha256,ruleChannels);Reader=(Get-WelaChannelReader)}
}
function Get-WelaDnsClientProbeStateKey {
    param($State)
    $metadataErrors=if($State.Channel.MetadataErrors -is [Collections.IDictionary]){$State.Channel.MetadataErrors.Count}else{@($State.Channel.MetadataErrors.PSObject.Properties|Where-Object MemberType -eq NoteProperty).Count}
    if($State.Service -cne 'Running' -or $State.Channel.State -cne 'Enabled' -or $State.Channel.Name -cne 'Microsoft-Windows-DNS-Client/Operational' -or -not $State.Channel.SecurityDescriptor -or $metadataErrors -or $State.Channel.Error -or $State.Channel.IsEnabled -ne $true -or $State.Channel.MaximumSizeInBytes -le 0 -or $State.Channel.LogMode -notin @('Circular','AutoBackup','Retain')){throw 'Enabled, fully observed DNS Client Operational channel is required.'}
    if($State.Schema.State -cne 'Observed' -or $State.Schema.Provider -cne 'Microsoft-Windows-DNS-Client' -or $State.Schema.ChannelType -cne 'Operational' -or -not $State.Schema.ProviderGuid){throw 'Exact native DNS Client provider/channel manifest required.'}
    $events=@($State.Schema.Events|Where-Object Id -eq 3008)
    if($events.Count -ne 1){throw 'Exactly one reviewed native event3008 template is required.'}
    foreach($event in $events){
        if($event.Version -ne 0 -or $event.Channel -cne $State.Channel.Name -or @($event.Fields).Count -ne 5){throw 'Unreviewed native DNS3008 version/channel.'}
        foreach($name in @('QueryName','QueryType','QueryOptions','QueryStatus','QueryResults')){
            $field=@($event.Fields|Where-Object Name -ceq $name)
            $types=switch($name){QueryName {@('win:UnicodeString')} QueryResults {@('win:UnicodeString')} QueryOptions {@('win:UInt64','win:HexInt64')} default {@('win:UInt32')}}
            if($field.Count -ne 1 -or $field[0].InType -cnotin $types){throw "Native DNS3008 field/type is unreviewed: $name"}
        }
    }
    # Metadata inventories may adjust and restore token privileges. Full token stability
    # is verified around query/event I/O, outside those inventories.
    $key=[ordered]@{};foreach($property in $State.PSObject.Properties){if($property.Name -cne 'Reader'){$key[$property.Name]=$property.Value}}
    $key.ReaderContext=Get-WelaDnsClientProbeReaderKey $State.Reader
    Get-WelaChannelReadKey ([pscustomobject]$key)
}
function Get-WelaDnsClientProbeReaderKey {
    param($Reader)
    Get-WelaChannelReadKey ([pscustomobject][ordered]@{Computer=$Reader.Computer;UserSid=$Reader.UserSid;UserName=$Reader.UserName;AuthenticationId=$Reader.AuthenticationId;GroupSids=@($Reader.GroupSids);GroupCount=$Reader.GroupCount;PrivilegeCount=$Reader.PrivilegeCount;ElevatedAdministrator=$Reader.ElevatedAdministrator;TokenType=$Reader.TokenType;Impersonation=$Reader.Impersonation})
}
function Get-WelaDnsClientProbeWatermark {
    $reader=$null;$record=$null
    try{$query=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-DNS-Client/Operational',[Diagnostics.Eventing.Reader.PathType]::LogName,'*');$query.ReverseDirection=$true;$reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=1;$record=$reader.ReadEvent([TimeSpan]::FromSeconds(5));Assert-WelaChannelQueryStatus -Channel 'Microsoft-Windows-DNS-Client/Operational' -LogStatus @($reader.LogStatus);if($record){if($record.RecordId -le 0){throw 'Invalid native record boundary.'};return [long]$record.RecordId};return [long]0}finally{if($record){$record.Dispose()};if($reader){$reader.Dispose()}}
}
function Start-WelaDnsClientProbeQuery {
    param($State,[string]$Resolver,[string]$QueryName)
    $fresh=Get-WelaDnsClientProbeState
    if((Get-WelaDnsClientProbeStateKey $fresh) -cne (Get-WelaDnsClientProbeStateKey $State)){throw 'DNS prerequisites changed before query.'}
    $boundary=Get-WelaDnsClientProbeWatermark
    $callerBefore=Get-WelaChannelReader
    $worker=Join-Path $PSScriptRoot 'DnsClientProbeWorker.ps1'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Engine;$info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Resolver "'+$Resolver+'" -QueryName "'+$QueryName+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false,$true)
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
    try{
        $launch=[DateTimeOffset]::UtcNow;$started=$process.Start();if(-not $started){throw 'DNS probe worker did not start.'}
        $output=$process.StandardOutput.ReadToEndAsync();$errorText=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(20000)){throw 'DNS query worker exceeded twenty seconds; operation completion is unverified.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($output,$errorText),5000)){throw 'DNS worker output did not finish.'}
        if($output.Result.Length -gt 262144 -or $errorText.Result.Length -gt 65536){throw 'DNS worker output exceeded evidence bounds.'}
        if($process.ExitCode -ne 0 -or $errorText.Result){throw ('DNS worker failed: '+$errorText.Result)}
        $operation=ConvertFrom-WelaRecoveryJson $output.Result
        if($operation.ProcessId -ne $process.Id -or $operation.Query.QueryName -cne $QueryName -or $operation.Query.Resolver -cne $Resolver -or $operation.Query.Options -ne 2103790 -or $operation.Query.Status -ne $operation.Query.ResultStatus -or $operation.Query.Status -notin @(0,9003,9501)){throw 'Unexpected DNS worker response or unsupported native outcome.'}
        $begin=ConvertTo-WelaArrivalUtc $operation.StartedUtc;$end=ConvertTo-WelaArrivalUtc $operation.CompletedUtc
        $operation.StartedUtc=$begin.UtcDateTime.ToString('o');$operation.CompletedUtc=$end.UtcDateTime.ToString('o')
        if($begin -lt $launch -or $end -lt $begin -or $end -gt [DateTimeOffset]::UtcNow -or ($end-$begin).TotalSeconds -gt 20){throw 'Invalid DNS operation timestamps.'}
        if((Get-WelaChannelReadKey $operation.BeforeToken) -cne (Get-WelaChannelReadKey $operation.AfterToken) -or (Get-WelaDnsClientProbeReaderKey $operation.BeforeToken) -cne (Get-WelaDnsClientProbeReaderKey $callerBefore)){throw 'DNS worker token differs from observed caller or changed.'}
        $operation|Add-Member NoteProperty RecordIdBefore $boundary
        $operation|Add-Member NoteProperty CallerBefore $callerBefore
        $operation
    }finally{try{if($started -and -not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Owned DNS worker termination could not be verified.'}}}finally{$process.Dispose()}}
}
function Read-WelaDnsClientProbeEvents {
    param($Operation)
    $channel='Microsoft-Windows-DNS-Client/Operational'
    $xpath="*[System[Provider[@Name='Microsoft-Windows-DNS-Client'] and EventID=3008 and EventRecordID>$($Operation.RecordIdBefore) and TimeCreated[@SystemTime>='$($Operation.StartedUtc)' and @SystemTime<='$($Operation.CompletedUtc)']]]"
    $reader=$null;$record=$null;$xml=@();$timer=[Diagnostics.Stopwatch]::StartNew()
    try{
        $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($channel,[Diagnostics.Eventing.Reader.PathType]::LogName,$xpath);$query.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=16
        while($xml.Count -lt 256){
            if($timer.Elapsed.TotalSeconds -ge 5){throw 'DNS event read exceeded five-second bound.'}
            $record=$reader.ReadEvent([TimeSpan]::FromSeconds(5-$timer.Elapsed.TotalSeconds))
            if($null -eq $record){break}
            try{$text=$record.ToXml();if($text.Length -gt 131072){throw 'Native DNS XML exceeds bound.'};$xml+=$text}finally{$record.Dispose();$record=$null}
        }
        $status=@($reader.LogStatus|ForEach-Object{[pscustomobject]@{LogName=$_.LogName;StatusCode=$_.StatusCode}})
        Assert-WelaChannelQueryStatus -Channel $channel -LogStatus $status
        [pscustomobject]@{Xml=$xml;Capped=($xml.Count -ge 256);Query=$xpath;LogStatus=$status}
    }finally{if($record){$record.Dispose()};if($reader){$reader.Dispose()}}
}
function Test-WelaDnsClientProbeEvent {
    param([string]$Xml,$Operation,$State)
    $reader=$null
    try{
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','EventRecordID','Channel','Computer','TimeCreated','Execution')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne $State.Schema.Provider -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine $State.Schema.ProviderGuid.Trim('{}') -or $system.EventID.InnerText -cne '3008' -or $system.Version.InnerText -cne '0' -or $system.Channel.InnerText -cne $State.Channel.Name -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.RecordIdBefore){return $false}
        $computers=@($State.Computer);if($State.Host.DomainJoined){$computers+=$State.Computer+'.'+$State.Host.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime');if($time -lt (ConvertTo-WelaArrivalUtc $Operation.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.CompletedUtc)){return $false}
        # Capture the native emitter PID but do not equate service-broker PID with caller identity.
        if($system.Execution.GetAttribute('ProcessID') -cnotmatch '^[1-9][0-9]*$' -or [uint32]$system.Execution.GetAttribute('ProcessID') -eq 0){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e') -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$name=$node.GetAttribute('Name');if(-not $name -or $data.ContainsKey($name)){return $false};$data[$name]=$node.InnerText}
        if($data.Count -ne 5 -or $data.QueryName.TrimEnd('.') -cne $Operation.Query.QueryName.TrimEnd('.') -or $data.QueryType -cne '1' -or $data.QueryStatus -cne [string]$Operation.Query.Status -or -not $data.ContainsKey('QueryResults')){return $false}
        $options=if($data.QueryOptions -match '^0x[0-9a-fA-F]+$'){[Convert]::ToUInt64($data.QueryOptions.Substring(2),16)}elseif($data.QueryOptions -match '^[0-9]+$'){[uint64]$data.QueryOptions}else{return $false}
        if(($options -band [uint64]$Operation.Query.Options) -ne [uint64]$Operation.Query.Options){return $false}
        return $true
    }catch{return $false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaDnsClientProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$Resolver,[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    $ErrorActionPreference='Stop';Assert-WelaDnsClientResolver $Resolver
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new output directory; Plan writes no files.'}
    $report=[pscustomobject][ordered]@{Kind='WelaNativeDnsClientProbe';SchemaVersion=1;Action=$Action;Status='Unverified';ExitCode=1;Resolver=$Resolver;QueryPattern='wela-<random-guid>.wela.test.';QueryType='A';Transport='DNS TCP port53; recursion disabled';Before=$null;After=$null;Operation=$null;Query=$null;QueryLogStatus=@();ReaderBefore=$null;ReaderAfter=$null;ReaderInterval='After all initial metadata/output preparation and record boundary, through worker/event I/O and continuity read; before final metadata inventory.';Candidates=0;Matches=0;Artifacts=@();OutputPath=$null;Diagnostic='';ReadyRuleCredit=0;ConfigurationChanges=0;RuleChannelMismatch='Pinned DNS rules use Microsoft-Windows-DNS Client Events/Operational; actual source is Microsoft-Windows-DNS-Client/Operational. No alias rewrite or rule credit.';Correlation='Random query name, native outcome, source/host, record boundary and operation time. Emitter PID is retained but may be a service broker. Event3008 does not independently prove resolver wire identity or exclusive request attribution.';Scope='One fixed native DNS Client lookup completion; no DNS configuration, cache flush, policy/channel/service changes, forwarding or backend execution. Sysmon excluded.'}
    if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $PSScriptRoot}
    try{
        $before=Get-WelaDnsClientProbeState;$report.Before=$before;$key=Get-WelaDnsClientProbeStateKey $before
        if($Action -eq 'Plan'){$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 24)
        $queryName='wela-'+[guid]::NewGuid().ToString('N')+'.wela.test.'
        $operation=Start-WelaDnsClientProbeQuery $before $Resolver $queryName;$report.Operation=$operation;$report.ReaderBefore=$operation.CallerBefore
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'operation.json' ($operation|ConvertTo-Json -Depth 15)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do{$batch=Read-WelaDnsClientProbeEvents $operation;$report.Query=$batch.Query;$report.QueryLogStatus=@($batch.LogStatus);Assert-WelaChannelQueryStatus -Channel 'Microsoft-Windows-DNS-Client/Operational' -LogStatus $report.QueryLogStatus;$report.Candidates=@($batch.Xml).Count;if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'DNS event query cap reached or completeness unknown.'};$matches=@($batch.Xml|Where-Object {Test-WelaDnsClientProbeEvent $_ $operation $before});if($matches.Count){break};Start-Sleep -Milliseconds 250}while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.Matches=$matches.Count;if($matches.Count -gt 16){throw 'DNS matching event set exceeds sixteen records.'}
        $i=0;foreach($xml in $matches){$i++;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('event-'+$i+'.xml') $xml}
        if(-not $matches.Count){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('candidate-'+$i+'.xml') $xml};throw 'No matching native DNS3008 completion event was observed.'}
        if((Get-WelaDnsClientProbeWatermark) -lt $operation.RecordIdBefore){throw 'DNS log record boundary moved backwards; continuity unverified.'}
        $report.ReaderAfter=Get-WelaChannelReader;if((Get-WelaChannelReadKey $report.ReaderAfter) -cne (Get-WelaChannelReadKey $report.ReaderBefore)){throw 'Reader primary token changed during query/event collection.'}
        $after=Get-WelaDnsClientProbeState;$report.After=$after;if((Get-WelaDnsClientProbeStateKey $after) -cne $key){throw 'DNS host, token, schema, channel or source changed during collection.'}
        $report.Status='NativeDnsLookupObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    finally{if($report.Before -and -not $report.After){try{$report.After=Get-WelaDnsClientProbeState}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}};if($report.OutputPath -and $report.After){$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'after.json' ($report.After|ConvertTo-Json -Depth 24)}}
    if($report.OutputPath){$null=Write-WelaArrivalArtifact $report.OutputPath 'manifest.json' ($report|ConvertTo-Json -Depth 28)}
    $report
}
