# One fixed native Windows PowerShell script. Never prepares policy/services/channels.
function Get-WelaAppLockerScriptKey { param($Value) ConvertTo-Json -InputObject $Value -Depth 30 -Compress }
function Get-WelaAppLockerScriptSources {
    $sources=[ordered]@{}
    foreach($path in @('WELA.ps1','scripts/AppLockerScriptProbe.ps1','scripts/AppLockerScriptNative.cs','scripts/AppLockerScriptWorker.ps1','scripts/AppLockerReadiness.ps1','scripts/WefArrival.ps1')) {
        $sources[$path]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Initialize-WelaAppLockerScriptNative {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'A native 64-bit Windows process is required.'}
    $bytes=[IO.File]::ReadAllBytes((Join-Path $script:ScriptRoot 'scripts/AppLockerScriptNative.cs'))
    $hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.AppLockerScript.Native' -as [type])) {
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
        if(([regex]::Matches($text,'__WELA_SOURCE_SHA256__')).Count -ne 1){throw 'Unexpected native source fingerprint placeholder.'}
        Add-Type -TypeDefinition $text.Replace('__WELA_SOURCE_SHA256__',$hash) -ErrorAction Stop
    }
    if([Wela.AppLockerScript.Native]::SourceSha256 -cne $hash){throw 'Loaded helper differs from current source; start a fresh PowerShell process.'}
}
function Get-WelaAppLockerScriptReader { [Wela.AppLockerScript.Native]::Snapshot() }
function Get-WelaAppLockerScriptUtcNow { [Wela.AppLockerScript.Native]::UtcNow() }
function Get-WelaAppLockerScriptExecutionPolicy {
    $values=[ordered]@{InheritedProcessValue=$env:PSExecutionPolicyPreference;Machine=@();User=@()}
    foreach($scope in @('Machine','User')) {
        $base=if($scope -eq 'Machine'){[Microsoft.Win32.Registry]::LocalMachine}else{[Microsoft.Win32.Registry]::CurrentUser}
        foreach($path in @('SOFTWARE\Policies\Microsoft\Windows\PowerShell','SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell')) {
            $key=$base.OpenSubKey($path,$false)
            try {
                foreach($name in @('EnableScripts','ExecutionPolicy')) {
                    $present=$null -ne $key -and $name -cin @($key.GetValueNames())
                    $values[$scope]+=[pscustomobject]@{Path=$path;Name=$name;Present=[bool]$present;Kind=$(if($present){[string]$key.GetValueKind($name)}else{$null});Value=$(if($present){$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$null})}
                }
            }finally{if($key){$key.Dispose()}}
        }
    }
    [pscustomobject]$values
}
function Get-WelaAppLockerScriptServices {
    # Direct SCM observations precede every CIM connection; observation must not
    # implicitly start stopped WMI or AppLocker generation dependencies.
    $rows=@()
    foreach($name in @('Winmgmt','EventLog','AppIDSvc')) {
        $service=Get-Service -Name $name -ErrorAction Stop
        if($null -eq $service -or $service.Name -ine $name -or $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running){throw ($name+' must already be running; no CIM connection or child was started.')}
        $rows+=[pscustomobject]@{Name=$name;Status=[string]$service.Status}
    }
    $rows
}
function Get-WelaAppLockerScriptState {
    $services=@(Get-WelaAppLockerScriptServices)
    $hostState=Get-WelaAppLockerHost
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $machine=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-AppLocker/MSI and Script')
    try {$log=[ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode;LogFilePath=$channel.LogFilePath}}finally{$channel.Dispose()}
    $source=Resolve-WelaArrivalPath (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
    [pscustomobject][ordered]@{Services=$services;Host=$hostState;MachineGuid=$machine.MachineGuid;UBR=$version.UBR;Computer=[Environment]::MachineName;Domain=[string]$computer.Domain;LocalPolicy=(Get-WelaAppLockerPolicySnapshot Local);EffectivePolicy=(Get-WelaAppLockerPolicySnapshot Effective);Management=(Get-WelaAppLockerManagement);Service=(Get-WelaAppLockerService);Channel=$log;ExecutionPolicy=(Get-WelaAppLockerScriptExecutionPolicy);Source=$source;SourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
}
function Get-WelaAppLockerScriptStateKey {
    param($State)
    foreach($status in @($State.Host.Status,$State.LocalPolicy.Status,$State.EffectivePolicy.Status,$State.Service.Status,$State.Service.State,$State.Management.Status)){if($status -isnot [string]){throw 'Native context status must be a typed string.'}}
    $services=@($State.Services)
    if($services.Count -ne 3 -or @($services|Where-Object{$_.Name -isnot [string] -or $_.Status -isnot [string] -or $_.Status -cne 'Running'}).Count -or (($services.Name -join ',') -cne 'Winmgmt,EventLog,AppIDSvc')){throw 'Complete running-service preflight evidence is required.'}
    if($State.Host.Status -cne 'Candidate' -or $State.Host.Is64BitProcess -isnot [bool] -or -not $State.Host.Is64BitProcess -or $State.Host.ProductType -notin @(1,3) -or ($State.Host.ProductType -eq 1 -and $State.Host.Build -notin @(22000,22621,22631,26100,26200)) -or ($State.Host.ProductType -eq 3 -and $State.Host.Build -notin @(20348,26100))){throw 'A reviewed native Windows 11 or Server 2022/2025 member host is required; DCs are excluded.'}
    foreach($policy in @($State.LocalPolicy,$State.EffectivePolicy)){if($policy.Status -cne 'Observed' -or $policy.Policy.HasUnknownPolicyData -isnot [bool] -or $policy.Policy.HasUnknownPolicyData){throw 'Local and effective GP policy must be readable and understood.'}}
    $collection=@($State.EffectivePolicy.Policy.Collections|Where-Object Type -CEQ 'Script')
    if($collection.Count -ne 1 -or $collection[0].EnforcementMode -isnot [string] -or $collection[0].EnforcementMode -cne 'AuditOnly' -or ($collection[0].RuleCount -isnot [int] -and $collection[0].RuleCount -isnot [long]) -or $collection[0].RuleCount -lt 1){throw 'An existing nonempty effective Script AuditOnly collection is required.'}
    if($State.Service.Status -cne 'Observed' -or $State.Service.State -cne 'Running'){throw 'AppIDSvc must already be running.'}
    if($State.Channel.Enabled -isnot [bool] -or -not $State.Channel.Enabled -or $State.Channel.Name -cne 'Microsoft-Windows-AppLocker/MSI and Script' -or -not $State.Channel.SecurityDescriptor){throw 'The native MSI and Script channel must already be enabled and readable.'}
    if($State.Management.Status -cne 'Observed' -or $State.SourceHash -cnotmatch '^[a-f0-9]{64}$' -or -not $State.MachineGuid -or -not $State.Computer){throw 'Incomplete management, machine or source observation.'}
    Get-WelaAppLockerScriptKey $State
}
function Get-WelaAppLockerScriptAuthorizationKey {
    param($Token)
    if($Token.Sid -cnotmatch '^S-1-\d+(-\d+)+$' -or $Token.AuthenticationId -cnotmatch '^0x[0-9a-f]+$' -or $null -eq $Token.Groups -or $null -eq $Token.Privileges){throw 'Incomplete actual token evidence.'}
    Get-WelaAppLockerScriptKey ([ordered]@{Sid=$Token.Sid;AuthenticationId=$Token.AuthenticationId;Groups=$Token.Groups;Privileges=$Token.Privileges})
}
function New-WelaAppLockerScriptText {
    param([string]$Template,[string]$Nonce)
    if($Nonce -cnotmatch '^[a-f0-9]{32}$' -or ([regex]::Matches($Template,'__WELA_SCRIPT_NONCE__')).Count -ne 3){throw 'Unexpected fixed worker template or nonce.'}
    $Template.Replace('__WELA_SCRIPT_NONCE__',$Nonce)
}
function Read-WelaAppLockerScriptBoundary {
    $reader=$null;$record=$null
    try {
        $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-AppLocker/MSI and Script',[Diagnostics.Eventing.Reader.PathType]::LogName,'*');$query.ReverseDirection=$true;$query.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=1
        $record=$reader.ReadEvent([TimeSpan]::FromSeconds(5))
        $status=@($reader.LogStatus)
        if($status.Count -ne 1 -or $status[0].LogName -cne 'Microsoft-Windows-AppLocker/MSI and Script' -or $status[0].StatusCode -ne 0){throw 'Incomplete native channel query status.'}
        if($null -eq $record){return [long]0}
        if($record.LogName -cne $status[0].LogName -or $record.RecordId -le 0){throw 'Invalid native record boundary.'}
        [long]$record.RecordId
    }finally{if($record){$record.Dispose()};if($reader){$reader.Dispose()}}
}
function Start-WelaAppLockerScriptProcess {
    param([string]$Root,$State,$Reader,[string]$SourcesKey)
    $nonce=[guid]::NewGuid().ToString('N');$path=Join-Path $Root ('wela-script-'+$nonce+'.ps1')
    $template=[IO.File]::ReadAllText((Join-Path $script:ScriptRoot 'scripts/AppLockerScriptWorker.ps1'))
    $scriptBytes=[Text.UTF8Encoding]::new($false).GetBytes((New-WelaAppLockerScriptText $template $nonce))
    $artifact=Write-WelaArrivalArtifact $Root ([IO.Path]::GetFileName($path)) ([Text.UTF8Encoding]::new($false).GetString($scriptBytes))
    $source=$null;$scriptFile=$null;$process=$null;$started=$false;$stderr=$null
    try {
        $source=[IO.File]::Open($State.Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $scriptFile=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $sourceId=[Wela.AppLockerScript.Native]::FileId($source.SafeFileHandle.DangerousGetHandle());$scriptId=[Wela.AppLockerScript.Native]::FileId($scriptFile.SafeFileHandle.DangerousGetHandle())
        if((Get-FileHash -LiteralPath $State.Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $State.SourceHash -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'The held native source or generated script differs before launch.'}
        if((Get-WelaAppLockerScriptKey (Get-WelaAppLockerScriptSources)) -cne $SourcesKey){throw 'Source changed before script launch.'}
        $readerKey=Get-WelaAppLockerScriptKey $Reader
        if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey){throw 'Caller token changed before launch.'}
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Source;$info.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$path+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.WorkingDirectory=$Root
        $process=[Diagnostics.Process]::new();$process.StartInfo=$info
        $start=(Get-WelaAppLockerScriptUtcNow)
        $started=$process.Start();if(-not $started){throw 'The fixed script process did not start.'}
        $stderr=[Wela.AppLockerScript.Native]::ReadBoundedAsync($process.StandardError,4096)
        $ready=[Wela.AppLockerScript.Native]::ReadLineBoundedAsync($process.StandardOutput,256)
        if(-not $ready.Wait(30000)){throw 'The fixed script did not reach its ready marker within thirty seconds.'}
        $line=$ready.GetAwaiter().GetResult()
        if($line -cnotmatch ('^WELA_SCRIPT_READY_'+$nonce+'\|(FullLanguage|ConstrainedLanguage)\|5\.1\.[0-9.]+$')){throw ('Unexpected fixed script ready marker: '+$line)}
        $child=[Wela.AppLockerScript.Native]::Child($process.Handle)
        if((Get-WelaAppLockerScriptAuthorizationKey $child) -cne (Get-WelaAppLockerScriptAuthorizationKey $Reader)){throw 'The actual child primary/logon authorization differs from the caller.'}
        if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey){throw 'Caller token changed while the fixed child started.'}
        $stdout=[Wela.AppLockerScript.Native]::ReadBoundedAsync($process.StandardOutput,4096)
        $process.StandardInput.WriteLine('WELA_SCRIPT_GO_'+$nonce);$process.StandardInput.Close()
        if(-not $process.WaitForExit(10000)){throw 'The fixed child did not complete within ten seconds of release.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'The fixed child output did not complete within five seconds.'}
        $out=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult();$end=(Get-WelaAppLockerScriptUtcNow)
        if($process.ExitCode -ne 0 -or $out.TrimEnd("`r","`n") -cne ('WELA_SCRIPT_COMPLETE_'+$nonce) -or $err){throw ('The fixed script did not complete correctly. Exit='+$process.ExitCode+' Error='+$err)}
        if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey -or [Wela.AppLockerScript.Native]::FileId($source.SafeFileHandle.DangerousGetHandle()) -cne $sourceId -or [Wela.AppLockerScript.Native]::FileId($scriptFile.SafeFileHandle.DangerousGetHandle()) -cne $scriptId){throw 'Reader or held file identity changed during script execution.'}
        [pscustomobject][ordered]@{ProcessId=$process.Id;UserSid=$Reader.Sid;ChildToken=$child;NativePowerShell=$State.Source;NativePowerShellSha256=$State.SourceHash;NativePowerShellFileId=$sourceId;ScriptPath=$path;ScriptSha256=$artifact.Sha256;ScriptFileId=$scriptId;ScriptArtifact=$artifact;Nonce=$nonce;Arguments=$info.Arguments;StartedUtc=$start.ToString('o');CompletedUtc=$end.ToString('o');Clock='GetSystemTimePreciseAsFileTime';Ready=$line;Marker=$out.TrimEnd("`r","`n");ExitCode=$process.ExitCode}
    }catch{
        $message=$_.Exception.Message
        if($stderr -and $stderr.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$message+=' Native stderr: '+$stderr.GetAwaiter().GetResult()}
        throw $message
    }finally{
        try{if($process){try{if($started -and -not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Owned script process termination is unconfirmed.'}}}finally{$process.Dispose()}}}
        finally{if($scriptFile){$scriptFile.Dispose()};if($source){$source.Dispose()}}
    }
}
function Read-WelaAppLockerScriptEvents {
    param([long]$Boundary)
    $query="*[System[Provider[@Name='Microsoft-Windows-AppLocker'] and (EventID=8005 or EventID=8006) and EventRecordID>$Boundary]]"
    $reader=$null;$record=$null;$xml=@();$bytes=0
    try {
        $nativeQuery=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-AppLocker/MSI and Script',[Diagnostics.Eventing.Reader.PathType]::LogName,$query);$nativeQuery.ReverseDirection=$false;$nativeQuery.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($nativeQuery);$reader.BatchSize=16
        while($null -ne ($record=$reader.ReadEvent([TimeSpan]::FromSeconds(2)))) {
            try{$text=$record.ToXml();$bytes+=[Text.Encoding]::UTF8.GetByteCount($text);if($xml.Count -ge 255 -or $bytes -gt 1048576){throw 'Native script query reached its 256-event/one-MiB cap.'};$xml+=$text}finally{$record.Dispose();$record=$null}
        }
        $status=@($reader.LogStatus);if($status.Count -ne 1 -or $status[0].LogName -cne 'Microsoft-Windows-AppLocker/MSI and Script' -or $status[0].StatusCode -ne 0){throw 'Incomplete native script query status.'}
        [pscustomobject]@{Xml=$xml;Query=$query;Bytes=$bytes;Complete=$true}
    }finally{if($record){$record.Dispose()};if($reader){$reader.Dispose()}}
}

function Test-WelaAppLockerScriptEvent {
    param([string]$Xml,$Process,$State,[long]$Boundary)
    $reader=$null
    try {
        $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=4194304
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event');$ns.AddNamespace('a','http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0')
        if ($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData/a:RuleAndFileData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count) {return $false}
        $system=@{};foreach ($name in @('Provider','EventID','Version','EventRecordID','Channel','Computer','TimeCreated')) {$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if ($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-AppLocker' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine 'cbda4dbf-8d5d-4f69-9578-be14aa540d22' -or $system.EventID.InnerText -cnotin @('8005','8006') -or $system.Version.InnerText -cne '0' -or $system.EventRecordID.InnerText -notmatch '^[1-9][0-9]*$' -or $system.Channel.InnerText -cne 'Microsoft-Windows-AppLocker/MSI and Script') {return $false}
        $computers=@($State.Computer);if($State.Host.PartOfDomain){$computers+=$State.Computer+'.'+$State.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime')
        if($time.UtcDateTime -lt ([DateTimeOffset]::Parse($Process.StartedUtc)).UtcDateTime -or $time.UtcDateTime -gt (ConvertTo-WelaArrivalUtc $Process.CompletedUtc).UtcDateTime -or [long]$system.EventRecordID.InnerText -le $Boundary){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:UserData/a:RuleAndFileData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.NamespaceURI -cne $ns.LookupNamespace('a') -or $data.ContainsKey($node.LocalName) -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$data[$node.LocalName]=$node.InnerText}
        if($data.PolicyName -cne 'SCRIPT' -or $data.TargetUser -cne $Process.UserSid -or $data.TargetProcessId -notmatch '^[1-9][0-9]*$' -or [long]$data.TargetProcessId -ne $Process.ProcessId){return $false}
        # AppLocker may render the exact Windows directory through this documented path variable.
        $eventPath=$data.FilePath
        if($eventPath -imatch '^%OSDRIVE%\\'){$eventPath=[IO.Path]::GetPathRoot($State.Source).TrimEnd('\')+$eventPath.Substring(9)}
        return $eventPath -ieq $Process.ScriptPath
    } catch {return $false} finally {if($reader){$reader.Dispose()}}
}
function Invoke-WelaAppLockerScriptProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new AppLockerScriptOutputPath; Plan does not write files.'}
    Initialize-WelaAppLockerScriptNative
    $sources=Get-WelaAppLockerScriptSources;$sourceKey=Get-WelaAppLockerScriptKey $sources
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaAppLockerScriptProbe';Action=$Action;Status='Unverified';ExitCode=1;RecordedUtc=(Get-WelaAppLockerScriptUtcNow).ToString('o');Sources=$sources;Before=$null;After=$null;ReaderBefore=$null;ReaderAfter=$null;ReaderInterval='After output/context preparation, through child execution and actual event queries; final metadata is checked separately';Boundary=$null;Process=$null;EventId=$null;Decision=$null;Artifacts=@();Diagnostic='';OutputPath=$null;PolicyChanges=0;ReadyRuleCredit=0;CspPolicyState='Unknown';Scope='One fixed native Windows PowerShell5.1 Script-collection event. Other engines, collections, forwarding and Sigma/backend validation are not tested. Sysmon excluded.'}
    try {
        $before=Get-WelaAppLockerScriptState;$report.Before=$before;$key=Get-WelaAppLockerScriptStateKey $before
        if($Action -eq 'Plan'){$report.ReaderBefore=(Get-WelaAppLockerScriptReader);$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.OutputPath=New-WelaArrivalOutput -Path $OutputPath -SourcePath $script:ScriptRoot
        if((Get-WelaAppLockerScriptStateKey (Get-WelaAppLockerScriptState)) -cne $key){throw 'Context changed during output preparation.'}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 24)
        $reader=(Get-WelaAppLockerScriptReader);$report.ReaderBefore=$reader;$readerKey=Get-WelaAppLockerScriptKey $reader
        $report.Boundary=Read-WelaAppLockerScriptBoundary
        if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey){throw 'Reader changed during the actual boundary query.'}
        $process=Start-WelaAppLockerScriptProcess -Root $report.OutputPath -State $before -Reader $reader -SourcesKey $sourceKey;$report.Process=$process
        $report.Artifacts+= $process.ScriptArtifact
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'process.json' ($process|ConvertTo-Json -Depth 16)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@();$batch=$null
        do {
            if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey){throw 'Reader changed before script event query.'}
            $batch=Read-WelaAppLockerScriptEvents $report.Boundary
            if($batch.Complete -isnot [bool] -or -not $batch.Complete){throw 'Script query completeness is unknown.'}
            if((Get-WelaAppLockerScriptKey ((Get-WelaAppLockerScriptReader))) -cne $readerKey){throw 'Reader changed during script event query.'}
            $matches=@($batch.Xml|Where-Object{Test-WelaAppLockerScriptEvent $_ $process $before $report.Boundary})
            if($matches.Count -gt 1){throw 'Multiple exact script records make the result ambiguous.'}
            if($matches.Count -eq 1){break}
            Start-Sleep -Milliseconds 250
        }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.ReaderAfter=(Get-WelaAppLockerScriptReader)
        if((Get-WelaAppLockerScriptKey $report.ReaderAfter) -cne $readerKey){throw 'Reader changed before completion of the actual query interval.'}
        if($matches.Count -ne 1){
            # Retain only bounded candidates bearing the owned unique script name.
            $owned=@($batch.Xml|Where-Object{$_ -like ('*wela-script-'+$process.Nonce+'.ps1*')}|Select-Object -First 4)
            for($i=0;$i -lt $owned.Count;$i++){$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('candidate-'+$i+'.xml') $owned[$i]}
            throw 'No exact native Script8005/8006 event arrived within the timeout.'
        }
        $report.After=Get-WelaAppLockerScriptState
        if((Get-WelaAppLockerScriptStateKey $report.After) -cne $key -or (Get-WelaAppLockerScriptKey (Get-WelaAppLockerScriptSources)) -cne $sourceKey -or (Get-FileHash -LiteralPath $process.ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $process.ScriptSha256){throw 'Host, policy, service, channel, execution-policy observation or implementation changed.'}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'after.json' ($report.After|ConvertTo-Json -Depth 24)
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'event.xml' $matches[0]
        $event=[xml]$matches[0];$report.EventId=[int]$event.Event.System.EventID
        $report.Decision=if($report.EventId -eq 8005){'Allowed'}else{'AllowedWouldBlockIfEnforced'}
        $report.Status='NativeScriptEventObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    if($report.OutputPath){$json=$report|ConvertTo-Json -Depth 32;if([Text.Encoding]::UTF8.GetByteCount($json) -gt 2097152){throw 'The script probe report exceeded its two-MiB bound.'};$null=Write-WelaArrivalArtifact $report.OutputPath 'manifest.json' $json}
    $report
}
