# One local nonexistent-account attempt under already configured failure auditing.
function Initialize-WelaFailedLogonNative {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Native 64-bit Windows is required.'}
    $path=Join-Path $PSScriptRoot 'FailedLogonProbeNative.cs';$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if(-not ('Wela.FailedLogonProbe.Native' -as [type])){Add-Type -Path $path -ErrorAction Stop;$script:WelaFailedLogonHash=$hash}
    if($script:WelaFailedLogonHash -cne $hash){throw 'Loaded failed-logon helper differs from source; start a fresh process.'}
}
function Get-WelaFailedLogonSources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/FailedLogonProbe.ps1','scripts/FailedLogonProbeWorker.ps1','scripts/FailedLogonProbeNative.cs','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/Configuration.ps1','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    $sources|ConvertTo-Json -Compress
}
function Get-WelaFailedLogonTokenKey {
    param($Token,[switch]$AuthorizationOnly)
    foreach($name in @('UserSid','AuthenticationId','TokenId','ModifiedId','TokenType','Impersonation')){if($Token.$name -isnot [string]){throw 'Incomplete elevated primary-token observation.'}}
    if($Token.ElevatedAdministrator -isnot [bool]){throw 'Incomplete elevated primary-token observation.'}
    if($Token.UserSid -cnotmatch '^S-1-\d+(-\d+)+$' -or $Token.AuthenticationId -cnotmatch '^[a-f0-9]{16}$' -or -not $Token.ElevatedAdministrator -or $Token.TokenType -cne 'Primary' -or $Token.Impersonation -cne 'Absent' -or $Token.GroupSids -isnot [array]){throw 'Incomplete elevated primary-token observation.'}
    foreach($name in @('TokenId','ModifiedId')){if($Token.$name -cnotmatch '^[a-f0-9]{16}$'){throw 'Incomplete elevated primary-token observation.'}}
    foreach($name in @('GroupCount','PrivilegeCount','ProcessId')){if($Token.$name -isnot [int] -and $Token.$name -isnot [long] -and $Token.$name -isnot [uint32]){throw 'Incomplete elevated primary-token observation.'};if($Token.$name -lt 1){throw 'Incomplete elevated primary-token observation.'}}
    if(@($Token.GroupSids|Where-Object {$_ -isnot [string] -or $_ -cnotmatch '^S-1-\d+(-\d+)+$'}).Count){throw 'Incomplete elevated primary-token observation.'}
    $key=[ordered]@{Sid=$Token.UserSid;Logon=$Token.AuthenticationId;Groups=$Token.GroupSids;GroupCount=$Token.GroupCount;PrivilegeCount=$Token.PrivilegeCount}
    if(-not $AuthorizationOnly){$key.TokenId=$Token.TokenId;$key.ModifiedId=$Token.ModifiedId;$key.ProcessId=$Token.ProcessId}
    $key|ConvertTo-Json -Depth 8 -Compress
}
function Get-WelaFailedLogonState {
    Initialize-WelaFailedLogonNative
    foreach($name in @('EventLog','Winmgmt','SamSs','RpcSs')){if((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running'){throw 'Required native observation/authentication services must already be running.'}}
    $reader=Get-WelaChannelReader;$hostState=Get-WelaChannelReadHost
    if($hostState.ProductType -notin @(1,3) -or $hostState.DomainRole -notin @(0,1,2,3)){throw 'A local SAM Windows client or member/standalone server is required; domain controllers are excluded.'}
    $policies=Get-WelaEffectiveAuditPolicy;$precedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try{$log=[ordered]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;Size=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode;Path=$channel.LogFilePath;SecurityDescriptor=$channel.SecurityDescriptor}}finally{$channel.Dispose()}
    $engine=(Get-Process -Id $PID).Path
    $state=[pscustomobject][ordered]@{Host=$hostState;Token=$reader;AuditPolicies=$policies;Precedence=$precedence;Channel=$log;Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash;Sources=(Get-WelaFailedLogonSources)}
    if((Get-WelaFailedLogonTokenKey (Get-WelaChannelReader)) -cne (Get-WelaFailedLogonTokenKey $reader)){throw 'Reader changed during prerequisite observation.'}
    $state
}
function Get-WelaFailedLogonStateKey {
    param($State)
    $null=Get-WelaFailedLogonTokenKey $State.Token
    $mask=$State.AuditPolicies['0cce9215-69ae-11d9-bed3-505054503030']
    if(($mask -isnot [int] -and $mask -isnot [long]) -or $mask -notin @(2,3) -or $State.Precedence.Type -cne 'DWord' -or -not $State.Precedence.ValueExists -or $State.Precedence.Value -ne 1 -or -not $State.Channel.Enabled){throw 'Logon failure auditing, DWORD1 audit precedence and enabled/readable Security channel must already be configured.'}
    $State|ConvertTo-Json -Depth 12 -Compress
}
function Get-WelaFailedLogonWatermark {
    $record=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    try{if($null -eq $record.RecordId -or $record.RecordId -lt 1){throw 'Unknown Security record boundary.'};[long]$record.RecordId}finally{$record.Dispose()}
}
function Assert-WelaFailedLogonOperation {
    param($Operation,$State,[string]$Nonce,[int]$ProcessId,[DateTimeOffset]$Launch,[DateTimeOffset]$Observed)
    $a=$Operation.Attempt
    foreach($name in @('Nonce','Executable')){if($Operation.$name -isnot [string]){throw 'Unexpected fixed local authentication receipt type.'}}
    foreach($name in @('UserName','Domain','Clock','StartedUtc','CompletedUtc')){if($a.$name -isnot [string]){throw 'Unexpected fixed local authentication receipt type.'}}
    foreach($name in @('MissingAccountStatus','LogonType','LogonProvider','NativeError')){if($a.$name -isnot [int] -and $a.$name -isnot [long]){throw 'Unexpected fixed local authentication receipt type.'}}
    if($Operation.ProcessId -isnot [int] -and $Operation.ProcessId -isnot [long]){throw 'Unexpected fixed local authentication receipt type.'}
    if($Operation.Nonce -cne $Nonce -or $Operation.ProcessId -ne $ProcessId -or $Operation.Executable -ine $State.Engine -or $a.UserName -cne ('WL'+$Nonce.Substring(0,18)) -or $a.Domain -cne '.' -or $a.MissingAccountStatus -ne 2221 -or $a.LogonType -ne 3 -or $a.LogonProvider -ne 2 -or $a.Succeeded -isnot [bool] -or $a.Succeeded -or $a.NativeError -ne 1326 -or $a.Clock -cne 'GetSystemTimePreciseAsFileTime'){throw 'Unexpected fixed local authentication result; no failed-logon proof is granted.'}
    $start=ConvertTo-WelaArrivalUtc $a.StartedUtc;$end=ConvertTo-WelaArrivalUtc $a.CompletedUtc
    if($Launch -gt $Observed -or $start -lt $Launch -or $start -gt $end -or $end -gt $Observed -or ($end-$start).TotalSeconds -gt 20){throw 'Invalid exact native operation interval.'}
    if((Get-WelaFailedLogonTokenKey $Operation.BeforeToken) -cne (Get-WelaFailedLogonTokenKey $Operation.AfterToken) -or (Get-WelaFailedLogonTokenKey $Operation.BeforeToken -AuthorizationOnly) -cne (Get-WelaFailedLogonTokenKey $State.Token -AuthorizationOnly)){throw 'Worker token changed or differs from the observed caller.'}
    $a.StartedUtc=$start.UtcDateTime.ToString('o');$a.CompletedUtc=$end.UtcDateTime.ToString('o')
}
function Start-WelaFailedLogonAttempt {
    param($State,[string]$OutputPath)
    if((Get-WelaFailedLogonStateKey (Get-WelaFailedLogonState)) -cne (Get-WelaFailedLogonStateKey $State)){throw 'Prerequisites changed before the fixed attempt.'}
    $nonce=[guid]::NewGuid().ToString('N');$watermark=Get-WelaFailedLogonWatermark
    $null=Write-WelaWecUpdateArtifact $OutputPath 'intent.json' ([ordered]@{Nonce=$nonce;LocalAccount=('WL'+$nonce.Substring(0,18));Domain='.';Attempts=1;SecurityRecordIdBefore=$watermark}|ConvertTo-Json)
    $worker=Join-Path $PSScriptRoot 'FailedLogonProbeWorker.ps1'
    $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$State.Engine;$info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -Nonce '+$nonce
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false,$true)
    $process=$null
    try{
        $launch=[DateTimeOffset][Wela.FailedLogonProbe.Native]::UtcNow()
        $process=[Diagnostics.Process]::Start($info);$output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(20000)){$process.Kill();$null=$process.WaitForExit(1000);throw 'Fixed local authentication worker exceeded twenty seconds.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($output,$errors),1000)){throw 'Worker output did not complete.'}
        if($output.Result.Length -gt 65536 -or $errors.Result.Length -gt 65536){throw 'Worker output exceeded its bound.'}
        if($process.ExitCode -ne 0 -or $errors.Result){throw ('Fixed local authentication worker failed: '+$errors.Result)}
        $operation=ConvertFrom-WelaArrivalJson $output.Result
        Assert-WelaFailedLogonOperation $operation $State $nonce $process.Id $launch ([DateTimeOffset][Wela.FailedLogonProbe.Native]::UtcNow())
        $operation|Add-Member NoteProperty SecurityRecordIdBefore $watermark
        $operation
    }finally{if($process){try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(1000)}}finally{$process.Dispose()}}}
}
function Read-WelaFailedLogonEvents {
    param($Operation)
    $a=$Operation.Attempt
    $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625 and EventRecordID>$($Operation.SecurityRecordIdBefore) and TimeCreated[@SystemTime>='$($a.StartedUtc)' and @SystemTime<='$($a.CompletedUtc)']]]"
    $records=@();$xml=@()
    try{
        try{$records=@(Get-WinEvent -LogName Security -FilterXPath $query -MaxEvents 256 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
        foreach($record in $records){$text=[string]$record.ToXml();if($text.Length -gt 131072){throw 'Native event exceeded its bound.'};$xml+=$text}
        [pscustomobject]@{Xml=$xml;Capped=($records.Count -ge 256);Query=$query}
    }finally{foreach($record in $records){$record.Dispose()}}
}
function Test-WelaFailedLogonEvent {
    param([string]$Xml,$Operation,$State)
    $reader=$null
    try{
        if($Xml.Length -gt 131072){return $false}
        $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','Keywords','EventRecordID','Channel','Computer','TimeCreated')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or $system.EventID.InnerText -cne '4625' -or $system.Version.InnerText -cne '0' -or $system.Channel.InnerText -cne 'Security' -or $system.Keywords.InnerText -ine '0x8010000000000000' -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.SecurityRecordIdBefore){return $false}
        $computers=@($State.Host.Computer);if($State.Host.DomainJoined){$computers+=$State.Host.Computer+'.'+$State.Host.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime')
        if($time -lt (ConvertTo-WelaArrivalUtc $Operation.Attempt.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.Attempt.CompletedUtc)){return $false}
        $map=@{}
        foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){
            if($node.NodeType -eq 'Whitespace'){continue}
            if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e') -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false}
            $name=$node.GetAttribute('Name');if(-not $name -or $map.ContainsKey($name)){return $false};$map[$name]=$node.InnerText
        }
        if($map.TargetUserName -cne $Operation.Attempt.UserName -or $map.TargetDomainName -notin @('.',$State.Host.Computer) -or $map.TargetUserSid -cne 'S-1-0-0' -or $map.LogonType -cne '3' -or $map.AuthenticationPackageName -cne 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0' -or $map.Status -ine '0xc000006d' -or $map.SubStatus -ine '0xc0000064' -or $map.ProcessName -ine $Operation.Executable -or $map.SubjectUserSid -cne $Operation.BeforeToken.UserSid){return $false}
        if($map.ProcessId -cnotmatch '^0x[0-9a-fA-F]+$' -or $map.SubjectLogonId -cnotmatch '^0x[0-9a-fA-F]+$' -or [Convert]::ToInt64($map.ProcessId.Substring(2),16) -ne $Operation.ProcessId -or [Convert]::ToUInt64($map.SubjectLogonId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.BeforeToken.AuthenticationId,16)){return $false}
        return $true
    }catch{return $false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaFailedLogonProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    $ErrorActionPreference='Stop'
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new FailedLogonOutputPath; Plan creates no files.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaLocalFailedLogonProbe';Action=$Action;Status='Unverified';ExitCode=1;Before=$null;After=$null;Operation=$null;Candidates=0;Matches=0;Artifacts=@();Diagnostic='';OutputPath=$null;PolicyChanges=0;AccountChanges=0;ReadyRuleCredit=0;Scope='One fixed local SAM nonexistent-account network-logon-type attempt only. No remote/domain authentication, real credentials, account creation, impersonation, forwarding or Sigma proof. Sysmon excluded.'}
    if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $PSScriptRoot}
    try{
        $before=Get-WelaFailedLogonState;$report.Before=$before;$key=Get-WelaFailedLogonStateKey $before
        if($Action -eq 'Plan'){$null=Get-WelaFailedLogonWatermark;$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'before.json' ($before|ConvertTo-Json -Depth 16)
        $operation=Start-WelaFailedLogonAttempt $before $report.OutputPath;$report.Operation=$operation
        $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'operation.json' ($operation|ConvertTo-Json -Depth 12)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do{
            $batch=Read-WelaFailedLogonEvents $operation;$report.Candidates=@($batch.Xml).Count
            if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'Candidate completeness is unknown or the 256-event cap was reached.'}
            $matches=@($batch.Xml|Where-Object {Test-WelaFailedLogonEvent $_ $operation $before})
            if($matches.Count){break};Start-Sleep -Milliseconds 250
        }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.Matches=$matches.Count
        if($matches.Count -ne 1){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath ('candidate-'+$i+'.xml') $xml};throw 'Exactly one matching local nonexistent-account Security4625 was not observed.'}
        $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'event.xml' $matches[0]
        if((Get-WelaFailedLogonWatermark) -lt $operation.SecurityRecordIdBefore){throw 'Security record boundary moved backwards; continuity is unknown.'}
        $after=Get-WelaFailedLogonState;$report.After=$after
        if((Get-WelaFailedLogonStateKey $after) -cne $key){throw 'Host, token, policies, channel, engine or sources changed during collection.'}
        $report.Status='LocalFailedLogonObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    finally{if($report.Before -and -not $report.After){try{$report.After=Get-WelaFailedLogonState}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}}}
    if($report.OutputPath){if($report.After){$report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'after.json' ($report.After|ConvertTo-Json -Depth 16)};$null=Write-WelaWecUpdateArtifact $report.OutputPath 'manifest.json' ($report|ConvertTo-Json -Depth 24)}
    $report
}
