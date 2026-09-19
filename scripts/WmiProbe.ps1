# A fixed local namespace read. Never changes namespace security, policy or services.
function Assert-WelaWmiProbeNamespace {
    param([string]$Namespace)
    if($Namespace -cnotmatch '^root(\\[A-Za-z_][A-Za-z0-9_]{0,63}){1,5}$' -or $Namespace.Length -gt 256){throw 'Select one exact local root\namespace; remote paths, wildcards and queries are unsupported.'}
}
function Initialize-WelaWmiProbeNative {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'The WMI probe requires native 64-bit Windows.'}
    $source=Join-Path $PSScriptRoot 'WmiProbeNative.cs';$hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash
    if(-not ('Wela.WmiProbe.Native' -as [type])){Add-Type -Path $source -ErrorAction Stop;$script:WelaWmiProbeNativeHash=$hash}
    if($script:WelaWmiProbeNativeHash -cne $hash){throw 'Loaded WMI probe helper differs from its source; start a fresh session.'}
}
function Get-WelaWmiProbeSources {
    $sources=[ordered]@{}
    foreach($name in @('scripts/WmiProbe.ps1','scripts/WmiProbeWorker.ps1','scripts/WmiProbeNative.cs','scripts/WmiNamespaceAuditing.ps1','scripts/WefArrival.ps1','scripts/Configuration.ps1','scripts/ControlApplicability.ps1','modules/AuditProfiles.psm1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$name)) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    $sources|ConvertTo-Json -Compress
}
function Get-WelaWmiProbeTokenKey {
    param($Token,[switch]$AuthorizationOnly)
    if($Token.Sid -cnotmatch '^S-1-\d+(-\d+)+$' -or $Token.AuthenticationId -cnotmatch '^0x[0-9a-f]+$' -or -not $Token.Name -or -not $Token.Groups){throw 'Incomplete native token observation.'}
    $value=[ordered]@{Sid=$Token.Sid;Name=$Token.Name;AuthenticationId=$Token.AuthenticationId;AuthenticationType=$Token.AuthenticationType;Groups=@($Token.Groups)}
    if(-not $AuthorizationOnly){$value.Privileges=@($Token.Privileges)}
    $value|ConvertTo-Json -Depth 8 -Compress
}
function Get-WelaWmiProbeState {
    param([string]$Namespace)
    Assert-WelaWmiProbeNamespace $Namespace
    Initialize-WelaWmiProbeNative
    $token=[Wela.WmiProbe.Native]::Snapshot()
    $hostState=Get-WelaDefaultContext
    if(-not(Test-WelaDefaultContextComplete $hostState)){throw 'Complete actual host/build/patch/role context is required.'}
    $snapshot=Get-WelaWmiNamespaceSnapshot $Namespace
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try{$log=[ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode}}finally{$channel.Dispose()}
    $engine=(Get-Process -Id $PID -ErrorAction Stop).Path
    $state=[pscustomobject][ordered]@{Namespace=$Namespace;Computer=[Environment]::MachineName;Host=$hostState;Token=$token;Descriptor=$snapshot;AuditMask=(Get-WelaAuditPolicyMask '0CCE9227-69AE-11D9-BED3-505054503030');Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Channel=$log;Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant();Sources=(Get-WelaWmiProbeSources)}
    $finalToken=[Wela.WmiProbe.Native]::Snapshot()
    if((Get-WelaWmiProbeTokenKey $token) -cne (Get-WelaWmiProbeTokenKey $finalToken)){throw 'Token changed while observing namespace prerequisites.'}
    $state.Token=$finalToken
    $state
}
function Get-WelaWmiProbeStateKey {
    param($State)
    Assert-WelaWmiProbeNamespace $State.Namespace
    $null=Get-WelaWmiProbeTokenKey $State.Token
    if($State.Host.Status -cne 'Observed' -or $State.Host.Build -notin @(22000,22621,22631,20348,26100,26200) -or $State.Host.ProductType -notin @(1,2,3) -or -not $State.Computer){throw 'Host is outside the reviewed Windows 11/Server context.'}
    if($State.AuditMask -notin @(1,3) -or -not $State.Precedence.ValueExists -or $State.Precedence.Type -cne 'DWord' -or $State.Precedence.Value -ne 1){throw 'Other Object Access success auditing and typed audit precedence DWORD1 must already be configured.'}
    if(-not $State.Channel.Enabled -or $State.Channel.Name -cne 'Security' -or -not $State.Channel.SecurityDescriptor){throw 'The Security channel must already be readable and enabled.'}
    if($State.Descriptor.Namespace -cne $State.Namespace -or -not $State.Descriptor.DescriptorMof){throw 'Incomplete selected namespace descriptor.'}
    $descriptor=$State.Descriptor.DescriptorJson|ConvertFrom-Json -ErrorAction Stop
    $sids=@($State.Token.Sid)+@($State.Token.Groups|Where-Object {($_.Attributes -band 4) -ne 0 -and ($_.Attributes -band 16) -eq 0}|ForEach-Object Sid)
    $matches=@($descriptor.SACL|Where-Object {$_.AceType -eq 2 -and ($_.AceFlags -band 64) -ne 0 -and ($_.AceFlags -band 8) -eq 0 -and ($_.AccessMask -band 1) -ne 0 -and (Get-WelaWmiSid $_.Trustee) -in $sids})
    if(-not $matches.Count){throw 'No observed success read audit ACE matches this caller on the selected namespace; no SACL is added.'}
    $State|ConvertTo-Json -Depth 16 -Compress
}
function Get-WelaWmiProbeWatermark {
    $record=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    try{if($null -eq $record.RecordId -or $record.RecordId -lt 1){throw 'Unknown Security record boundary.'};[long]$record.RecordId}finally{$record.Dispose()}
}
function Start-WelaWmiProbeRead {
    param($State)
    $fresh=Get-WelaWmiProbeState $State.Namespace
    if((Get-WelaWmiProbeStateKey $fresh) -cne (Get-WelaWmiProbeStateKey $State)){throw 'WMI prerequisites changed before the fixed read.'}
    $watermark=Get-WelaWmiProbeWatermark
    $worker=Join-Path $PSScriptRoot 'WmiProbeWorker.ps1'
    $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$State.Engine
    $info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Namespace "'+$State.Namespace+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false,$true)
    $process=$null
    try{
        $process=[Diagnostics.Process]::Start($info);$output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(20000)){$process.Kill();$null=$process.WaitForExit(1000);throw 'The fixed WMI read worker exceeded twenty seconds.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($output,$errors),1000)){throw 'The fixed read output did not complete.'}
        $text=$output.Result;$diagnostic=$errors.Result
        if($text.Length -gt 262144 -or $diagnostic.Length -gt 65536){throw 'Worker output exceeded its evidence bound.'}
        if($process.ExitCode -ne 0 -or $diagnostic){throw ('Fixed local WMI read failed: '+$diagnostic)}
        $operation=ConvertFrom-WelaArrivalJson $text
        if($operation.Namespace -cne $State.Namespace -or $operation.ProcessId -ne $process.Id -or $operation.ExpectedAccessMask -ne 1 -or $operation.ReturnedRows -ne 0 -or $operation.Query -cnotmatch "^SELECT Name FROM __Namespace WHERE Name='WelaReadProbe_[a-f0-9]{32}'$"){throw 'Unexpected fixed worker response.'}
        $start=ConvertTo-WelaArrivalUtc $operation.StartedUtc;$end=ConvertTo-WelaArrivalUtc $operation.CompletedUtc
        if($start -gt $end -or ($end-$start).TotalSeconds -gt 20 -or $end -gt [DateTimeOffset]::UtcNow){throw 'Invalid fixed worker time interval.'}
        # Older PowerShell7 JSON readers can materialize UTC strings as DateTime.
        $operation.StartedUtc=$start.UtcDateTime.ToString('o');$operation.CompletedUtc=$end.UtcDateTime.ToString('o')
        if((Get-WelaWmiProbeTokenKey $operation.BeforeToken) -cne (Get-WelaWmiProbeTokenKey $operation.AfterToken) -or (Get-WelaWmiProbeTokenKey $operation.BeforeToken -AuthorizationOnly) -cne (Get-WelaWmiProbeTokenKey $State.Token -AuthorizationOnly)){throw 'Worker token differs from the observed caller or changed during access.'}
        $operation|Add-Member NoteProperty SecurityRecordIdBefore $watermark
        $operation
    }finally{if($process){try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(1000)}}finally{$process.Dispose()}}}
}
function Read-WelaWmiProbeEvents {
    param($Operation)
    $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4662 and EventRecordID>$($Operation.SecurityRecordIdBefore) and TimeCreated[@SystemTime>='$($Operation.StartedUtc)' and @SystemTime<='$($Operation.CompletedUtc)']]]"
    $records=@();$xml=@()
    try{
        try{$records=@(Get-WinEvent -LogName Security -FilterXPath $query -MaxEvents 256 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
        foreach($record in $records){$text=[string]$record.ToXml();if($text.Length -gt 131072){throw 'Native event exceeds the 128 KiB character bound.'};$xml+=$text}
        [pscustomobject]@{Xml=$xml;Capped=($records.Count -ge 256);Query=$query;MaximumEvents=256}
    }finally{foreach($record in $records){$record.Dispose()}}
}
function Test-WelaWmiProbeEvent {
    param([string]$Xml,$Operation,$State)
    $reader=$null
    try{
        if($Xml.Length -gt 131072){return $false}
        $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','Keywords','EventRecordID','Channel','Computer','TimeCreated')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or $system.EventID.InnerText -cne '4662' -or $system.Version.InnerText -cne '0' -or $system.Channel.InnerText -cne 'Security' -or $system.Keywords.InnerText -ine '0x8020000000000000' -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.SecurityRecordIdBefore){return $false}
        $computers=@($State.Computer);if($State.Host.DomainJoined){$computers+=$State.Computer+'.'+$State.Host.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime')
        if($time -lt (ConvertTo-WelaArrivalUtc $Operation.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.CompletedUtc)){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};$name=$node.GetAttribute('Name');if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e') -or -not $name -or $data.ContainsKey($name) -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$data[$name]=$node.InnerText}
        # DS4662 and WMI4662 are different sources. No event-ID-only credit.
        if($data.ObjectServer -cne 'WMI' -or $data.ObjectName -ine $State.Namespace -or $data.SubjectUserSid -cne $Operation.BeforeToken.Sid -or $data.SubjectLogonId -notmatch '^0x[0-9a-fA-F]+$' -or $data.AccessMask -notmatch '^0x[0-9a-fA-F]+$'){return $false}
        if([Convert]::ToUInt64($data.SubjectLogonId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.BeforeToken.AuthenticationId.Substring(2),16) -or [Convert]::ToUInt64($data.AccessMask.Substring(2),16) -ne 1){return $false}
        return $true
    }catch{return $false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaWmiProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$Namespace,[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    Assert-WelaWmiProbeNamespace $Namespace
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new WmiProbeOutputPath; Plan creates no files.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaLocalWmiReadProbe';Action=$Action;Status='Unverified';ExitCode=1;RecordedUtc=[DateTime]::UtcNow.ToString('o');Before=$null;After=$null;Operation=$null;Query=$null;Candidates=0;Matches=0;Artifacts=@();Diagnostic='';OutputPath=$null;PolicyChanges=0;NamespaceChanges=0;ReadyRuleCredit=0;RequestAttribution='Not exclusive: WMI4662 has no probe nonce or client PID; concurrent same-token namespace reads can match.';Scope='Observed local WMI namespace read access only; provider-operation success, remote access, forwarding and Sigma/backend validation are separate. Sysmon excluded.'}
    if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $PSScriptRoot}
    try{
        $before=Get-WelaWmiProbeState $Namespace;$report.Before=$before;$key=Get-WelaWmiProbeStateKey $before
        if($Action -eq 'Plan'){$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 20)
        $operation=Start-WelaWmiProbeRead $before;$report.Operation=$operation
        $report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'operation.json' ($operation|ConvertTo-Json -Depth 12)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do{
            $batch=Read-WelaWmiProbeEvents $operation;$report.Query=$batch.Query;$report.Candidates=@($batch.Xml).Count
            if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'The 256-event query cap was reached or completeness is unknown.'}
            $matches=@($batch.Xml|Where-Object {Test-WelaWmiProbeEvent $_ $operation $before})
            if($matches.Count){break};Start-Sleep -Milliseconds 250
        }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.Matches=$matches.Count
        if($matches.Count -gt 16){throw 'More than 16 matching records exceed the bounded evidence set.'}
        $i=0;foreach($xml in $matches){$i++;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('event-'+$i+'.xml') $xml}
        if(-not $matches.Count){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath ('candidate-'+$i+'.xml') $xml};throw 'No exact WMI namespace read event was observed in the fixed operation interval.'}
        if((Get-WelaWmiProbeWatermark) -lt $operation.SecurityRecordIdBefore){throw 'Security log record boundary moved backwards; evidence continuity is unknown.'}
        $after=Get-WelaWmiProbeState $Namespace;$report.After=$after
        if((Get-WelaWmiProbeStateKey $after) -cne $key){throw 'Host, token, namespace descriptor, policy, channel or source changed during collection.'}
        $report.Status='LocalNamespaceAccessObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    finally{
        if($report.Before -and -not $report.After){try{$report.After=Get-WelaWmiProbeState $Namespace}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}}
        if($report.OutputPath -and $report.After){$report.Artifacts+=Write-WelaArrivalArtifact $report.OutputPath 'after.json' ($report.After|ConvertTo-Json -Depth 20)}
    }
    if($report.OutputPath){$null=Write-WelaArrivalArtifact $report.OutputPath 'manifest.json' ($report|ConvertTo-Json -Depth 24)}
    $report
}
