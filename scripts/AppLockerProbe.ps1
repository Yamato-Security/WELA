# Fixed benign EXE probe. Does not change AppLocker, services, channels or audit policy.
function Get-WelaAppLockerProbeState {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {throw 'A native 64-bit Windows process is required.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$reader=[ordered]@{Name=$identity.Name;Sid=$identity.User.Value;Groups=@($identity.Groups.Value|Sort-Object);AuthenticationType=$identity.AuthenticationType}} finally {$identity.Dispose()}
    $hostState=Get-WelaAppLockerHost
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/EXE and DLL')
    try {$log=[ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode}} finally {$channel.Dispose()}
    $source=Resolve-WelaArrivalPath (Join-Path ([Environment]::SystemDirectory) 'cmd.exe')
    [pscustomobject][ordered]@{Host=$hostState;Computer=[Environment]::MachineName;Domain=[string]$computer.Domain;Reader=$reader;EffectivePolicy=(Get-WelaAppLockerPolicySnapshot Effective);Service=(Get-WelaAppLockerService);Channel=$log;Source=$source;SourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
}
function Get-WelaAppLockerProbeKey {
    param($State)
    if (-not $State.Host.Is64BitProcess -or $State.Host.Status -ne 'Candidate') {throw 'An observed supported client/member Windows host is required.'}
    if ($State.EffectivePolicy.Status -ne 'Observed' -or $State.EffectivePolicy.Policy.HasUnknownPolicyData) {throw 'Effective Group Policy AppLocker settings must be readable and understood.'}
    $collection=@($State.EffectivePolicy.Policy.Collections|Where-Object Type -eq Exe)
    if ($collection.Count -ne 1 -or $collection[0].EnforcementMode -cne 'AuditOnly' -or $collection[0].RuleCount -lt 1) {throw 'A nonempty effective EXE AuditOnly collection is required.'}
    if ($State.Service.Status -ne 'Observed' -or $State.Service.State -ne 'Running') {throw 'AppIDSvc must already be running.'}
    if ($State.Channel.Enabled -isnot [bool] -or -not $State.Channel.Enabled -or -not $State.Channel.SecurityDescriptor -or $State.Channel.Name -cne 'Microsoft-Windows-AppLocker/EXE and DLL') {throw 'The readable EXE and DLL channel must already be enabled.'}
    if ($State.Reader.Sid -notmatch '^S-1-\d+(-\d+)+$' -or $State.SourceHash -cnotmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrWhiteSpace($State.Computer)) {throw 'Incomplete reader, source or computer identity.'}
    [ordered]@{Host=$State.Host;Computer=$State.Computer;Domain=$State.Domain;Reader=$State.Reader;Policy=(Get-WelaAppLockerXmlKey $State.EffectivePolicy.Policy.Xml);Service=$State.Service;Channel=$State.Channel;Source=$State.Source;SourceHash=$State.SourceHash}|ConvertTo-Json -Depth 12 -Compress
}
function Start-WelaAppLockerProbeProcess {
    param([string]$Root,$State)
    $nonce=[guid]::NewGuid().ToString('N');$path=Join-Path $Root ('wela-applocker-'+$nonce+'.exe')
    $source=$null;$target=$null;$lock=$null;$process=$null
    try {
        $source=[IO.File]::Open($State.Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $target=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $source.CopyTo($target);$target.Flush();$target.Dispose();$target=$null
        $lock=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.SourceHash) {throw 'Native executable bytes changed before launch.'}
        $fresh=Get-WelaAppLockerProbeState
        if ((Get-WelaAppLockerProbeKey $fresh) -cne (Get-WelaAppLockerProbeKey $State)) {throw 'AppLocker prerequisites changed before launch.'}
        $arguments='/d /c echo WELA_APPLOCKER_'+$nonce
        $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$path;$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.WorkingDirectory=$Root
        $started=[DateTime]::UtcNow;$process=[Diagnostics.Process]::Start($info);$processId=$process.Id
        if (-not $process.WaitForExit(10000)) {$process.Kill();throw 'The owned fixed probe exceeded its ten-second process limit.'}
        $stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne 0 -or $stdout.Trim() -cne ('WELA_APPLOCKER_'+$nonce) -or $stderr) {throw 'The fixed native executable did not complete with its expected marker.'}
        [pscustomobject]@{Executable=$path;ExecutableHash=$State.SourceHash;Arguments=$arguments;ProcessId=$processId;UserSid=$State.Reader.Sid;StartedUtc=$started.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');ExitCode=$process.ExitCode;Marker=$stdout.Trim()}
    } finally {foreach ($item in @($process,$lock,$target,$source)) {if ($item) {$item.Dispose()}}}
}
function Read-WelaAppLockerProbeEvents {
    param([datetime]$StartUtc,[datetime]$EndUtc)
    $query="*[System[Provider[@Name='Microsoft-Windows-AppLocker'] and (EventID=8002 or EventID=8003) and TimeCreated[@SystemTime>='$($StartUtc.ToString('o'))' and @SystemTime<='$($EndUtc.ToString('o'))']]]"
    $records=@();$xml=@()
    try {
        try {$records=@(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -FilterXPath $query -MaxEvents 512 -ErrorAction Stop)} catch {if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {throw}}
        foreach ($record in $records) {$xml+=[string]$record.ToXml()}
        [pscustomobject]@{Xml=$xml;Capped=($records.Count -ge 512);Query=$query}
    } finally {foreach ($record in $records) {$record.Dispose()}}
}
function Test-WelaAppLockerProbeEvent {
    param([string]$Xml,$Process,$State,[datetime]$EndUtc)
    $reader=$null
    try {
        $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=4194304
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event');$ns.AddNamespace('a','http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0')
        if ($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData/a:RuleAndFileData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count) {return $false}
        $system=@{};foreach ($name in @('Provider','EventID','Version','EventRecordID','Channel','Computer','TimeCreated')) {$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if ($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-AppLocker' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine 'cbda4dbf-8d5d-4f69-9578-be14aa540d22' -or $system.EventID.InnerText -cnotin @('8002','8003') -or $system.Version.InnerText -cne '0' -or $system.EventRecordID.InnerText -notmatch '^[1-9][0-9]*$' -or $system.Channel.InnerText -cne 'Microsoft-Windows-AppLocker/EXE and DLL') {return $false}
        $computers=@($State.Computer);if($State.Host.PartOfDomain){$computers+=$State.Computer+'.'+$State.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime')
        if($time.UtcDateTime -lt ([DateTimeOffset]::Parse($Process.StartedUtc)).UtcDateTime -or $time.UtcDateTime -gt $EndUtc){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:UserData/a:RuleAndFileData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns.LookupNamespace('a') -or $data.ContainsKey($node.LocalName) -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$data[$node.LocalName]=$node.InnerText}
        if($data.PolicyName -cne 'EXE' -or $data.TargetUser -cne $Process.UserSid -or $data.TargetProcessId -notmatch '^[1-9][0-9]*$' -or [long]$data.TargetProcessId -ne $Process.ProcessId){return $false}
        # AppLocker may render the exact Windows directory through this documented path variable.
        $eventPath=$data.FilePath
        if($eventPath -imatch '^%OSDRIVE%\\'){$eventPath=[IO.Path]::GetPathRoot($State.Source).TrimEnd('\')+$eventPath.Substring(9)}
        return $eventPath -ieq $Process.Executable
    } catch {return $false} finally {if($reader){$reader.Dispose()}}
}
function Invoke-WelaAppLockerProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    if (($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))) {throw 'Run requires a new AppLockerProbeOutputPath; Plan does not write files.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaAppLockerExeProbe';Action=$Action;Status='Unverified';ExitCode=0;RecordedUtc=[DateTime]::UtcNow.ToString('o');Before=$null;After=$null;Process=$null;EventId=$null;Artifacts=@();Diagnostic='';OutputPath=$null;PolicyChanges=0;ReadyRuleCredit=0;CspPolicyState='Unknown';Scope='One fixed native EXE event only; scripts, MSI, DLL, packaged apps, forwarding and Sigma/backend validation are not tested. Sysmon excluded.'}
    if($Action -eq 'Run'){$sourceDirectory=[Environment]::SystemDirectory;if(-not $sourceDirectory){$sourceDirectory=$PSScriptRoot};$report.OutputPath=New-WelaArrivalOutput -Path $OutputPath -SourcePath $sourceDirectory}
    try {
        $before=Get-WelaAppLockerProbeState;$report.Before=$before;$key=Get-WelaAppLockerProbeKey $before
        if($Action -eq 'Plan'){$report.Status='PrerequisitesObserved';return $report}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 20)
        $process=Start-WelaAppLockerProbeProcess $report.OutputPath $before;$report.Process=$process
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'process.json' ($process|ConvertTo-Json -Depth 6)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do {
            $end=[DateTime]::UtcNow;$batch=Read-WelaAppLockerProbeEvents ([DateTimeOffset]::Parse($process.StartedUtc)).UtcDateTime $end
            if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'The 512-event query cap was reached or completeness is unknown.'}
            $matches=@($batch.Xml|Where-Object {Test-WelaAppLockerProbeEvent $_ $process $before $end})
            if($matches.Count -gt 1){throw 'Multiple exact AppLocker events make the result ambiguous.'}
            if($matches.Count -eq 1){break}
            Start-Sleep -Milliseconds 250
        } while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        if($matches.Count -ne 1){foreach($xml in @($batch.Xml|Select-Object -First 4)){$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('candidate-'+[guid]::NewGuid().ToString('N')+'.xml') $xml};throw 'No exact AppLocker EXE event arrived within the timeout.'}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'event.xml' $matches[0]
        $after=Get-WelaAppLockerProbeState;$report.After=$after;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'after.json' ($after|ConvertTo-Json -Depth 20)
        if((Get-WelaAppLockerProbeKey $after) -cne $key -or (Get-FileHash -LiteralPath $process.Executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $process.ExecutableHash){throw 'Host, policy, service, channel, reader or probe bytes changed during collection.'}
        $event=[xml]$matches[0];$report.EventId=[int]$event.Event.System.EventID;$report.Status='NativeExeEventObserved'
    } catch {$report.ExitCode=1;$report.Diagnostic=$_.Exception.Message}
    if($report.OutputPath){$null=Write-WelaArrivalArtifact $report.OutputPath 'manifest.json' ($report|ConvertTo-Json -Depth 24)}
    $report
}
