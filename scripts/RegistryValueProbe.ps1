# Fixed current-user diagnostic key only. Existing auditing is required, never installed.
function Initialize-WelaRegistryValueProbe {
    Initialize-WelaWmiProbeNative
    $source=Join-Path $PSScriptRoot 'RegistryValueProbeNative.cs';$bytes=[IO.File]::ReadAllBytes($source);$hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.RegistryValueProbe.Target' -as [type])){Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).Replace('__WELA_REGISTRY_VALUE_PROBE_SOURCE_SHA256__',$hash)) -ErrorAction Stop}
    if([Wela.RegistryValueProbe.Descriptor]::SourceSha256 -cne $hash){throw 'Loaded registry probe helper differs from source; start a fresh session.'}
}
function Get-WelaRegistryValueProbeSources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/RegistryValueProbe.ps1','scripts/RegistryValueProbeNative.cs','scripts/FileAccessProbe.ps1','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/Configuration.ps1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1','scripts/IpsecPrerequisites.ps1','config/audit_profiles.json')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$name)) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    [pscustomobject]$sources
}
function Get-WelaRegistryValueProbeState {
    if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'Native 64-bit Windows is required.'}
    Initialize-WelaRegistryValueProbe
    $tokenBefore=[Wela.RegistryValueProbe.TokenReader]::Snapshot()
    $services=@(Get-Service EventLog,Winmgmt,RpcSs -ErrorAction Stop|Sort-Object Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status}})
    if($services.Count -ne 3 -or @($services|Where-Object Status -ne Running).Count){throw 'EventLog, Winmgmt and RpcSs must already be running.'}
    $reader=Get-WelaChannelReader;$null=Get-WelaFileProbeReaderKey $reader
    $computer=Get-CimInstance Win32_ComputerSystem -Property DomainRole,PartOfDomain -ErrorAction Stop
    if(-not(Test-WelaFileProbeInteger $computer.DomainRole) -or $computer.PartOfDomain -isnot [bool]){throw 'Native Windows role and join observations are incomplete.'}
    $hostState=Get-WelaChannelReadHost
    if($hostState.DomainRole -ne $computer.DomainRole -or $hostState.DomainJoined -ne $computer.PartOfDomain){throw 'Native Windows role or join state changed during observation.'}
    $target=[Wela.RegistryValueProbe.Target]::new($false)
    try{$registry=$target.Read()}finally{$target.Dispose()}
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try{$log=[pscustomobject]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode}}finally{$channel.Dispose()}
    $policy=Get-WelaEffectiveAuditPolicy;$masks=[ordered]@{};foreach($guid in @($policy.Keys|Sort-Object)){$masks[$guid]=$policy[$guid]}
    $engine=(Get-Process -Id $PID -ErrorAction Stop).Path;$token=[Wela.RegistryValueProbe.TokenReader]::Snapshot()
    if((Get-WelaFileProbeTokenKey $tokenBefore) -cne (Get-WelaFileProbeTokenKey $token)){throw 'Registry prerequisite observation changed the full process token.'}
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostState;Services=$services;Reader=($reader|Select-Object UserSid,UserName,AuthenticationId,GroupSids,GroupCount,PrivilegeCount,ElevatedAdministrator,TokenType,Impersonation);Token=$token;Registry=$registry;AuditPolicies=[pscustomobject]$masks;Precedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy;Channel=$log;Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine).Hash.ToLowerInvariant();Sources=Get-WelaRegistryValueProbeSources}
}
function Get-WelaRegistryValueProbeStateKey {
    param($State)
    $null=Get-WelaFileProbeTokenKey $State.Token
    if($State.Computer -isnot [string] -or -not $State.Computer -or -not(Test-WelaFileProbeInteger $State.Host.ProductType) -or $State.Host.ProductType -notin 1,2,3 -or -not(Test-WelaFileProbeInteger $State.Host.Build) -or $State.Host.Build -notin 22000,22621,22631,20348,26100,26200 -or $State.Host.DomainJoined -isnot [bool]){throw 'Complete supported native host context is required.'}
    if(-not(Test-WelaFileProbeInteger $State.Host.DomainRole) -or
       ($State.Host.ProductType -eq 1 -and ($State.Host.DomainRole -notin 0,1 -or $State.Host.Build -notin 22000,22621,22631,26100,26200)) -or
       ($State.Host.ProductType -eq 2 -and ($State.Host.DomainRole -notin 4,5 -or $State.Host.Build -notin 20348,26100)) -or
       ($State.Host.ProductType -eq 3 -and ($State.Host.DomainRole -notin 2,3 -or $State.Host.Build -notin 20348,26100)) -or
       ($State.Host.DomainJoined -ne ($State.Host.DomainRole -in 1,3,4,5))){throw 'Contradictory Windows product/build/domain-role/join evidence.'}
    if($State.Services -isnot [array] -or ($State.Services.Name -join ',') -cne 'EventLog,RpcSs,Winmgmt' -or @($State.Services|Where-Object Status -ne Running).Count){throw 'Required services must already be running.'}
    if($State.Reader.ElevatedAdministrator -isnot [bool] -or -not $State.Reader.ElevatedAdministrator -or $State.Reader.TokenType -cne 'Primary' -or $State.Reader.Impersonation -cne 'Absent' -or $State.Reader.UserSid -cne $State.Token.Sid){throw 'Actual elevated non-impersonating primary token required.'}
    $expected='HKEY_USERS\'+$State.Token.Sid+'\Software\WELA\AuditProbe'
    $r=$State.Registry
    if($r.Path -ine $expected -or $r.Kind -cne 'Registry' -or $r.IsDirectory -isnot [bool] -or $r.IsDirectory -or -not(Test-WelaFileProbeInteger $r.SecurityInformation) -or $r.SecurityInformation -ne 511 -or $r.DescriptorBase64 -isnot [string] -or -not $r.DescriptorBase64 -or $r.Identity -isnot [string] -or -not $r.Identity -or $r.Values -isnot [array] -or $r.Values.Count -gt 128 -or $r.Aces -isnot [array] -or $r.Aces.Count -gt 128){throw 'Complete fixed registry-key observation is required.'}
    foreach($ace in $r.Aces){if($ace.Ordinary -isnot [bool] -or -not(Test-WelaFileProbeInteger $ace.Type) -or -not(Test-WelaFileProbeInteger $ace.Flags) -or -not(Test-WelaFileProbeInteger $ace.Mask)){throw 'Typed audit ACE evidence is required.'}}
    $mask=$State.AuditPolicies.'0CCE921E-69AE-11D9-BED3-505054503030'
    if(-not(Test-WelaFileProbeInteger $mask) -or $mask -notin 1,3 -or $State.Precedence.ValueExists -isnot [bool] -or -not $State.Precedence.ValueExists -or $State.Precedence.Type -cne 'DWord' -or -not(Test-WelaFileProbeInteger $State.Precedence.Value) -or $State.Precedence.Value -ne 1){throw 'Registry success auditing and typed precedence DWORD1 must already be configured.'}
    if($State.Channel.Name -cne 'Security' -or $State.Channel.Enabled -isnot [bool] -or -not $State.Channel.Enabled -or -not $State.Channel.SecurityDescriptor){throw 'Security channel must already be enabled and readable.'}
    $sids=@($State.Token.Sid)+@($State.Token.Groups|Where-Object {($_.Attributes -band 4) -and -not($_.Attributes -band 16)}|ForEach-Object Sid)
    $aces=@($r.Aces|Where-Object {$_.Ordinary -and $_.Type -eq 2 -and ($_.Flags -band 64) -and -not($_.Flags -band 8) -and ($_.Mask -band 2) -and $_.Sid -in $sids})
    if(-not $aces.Count){throw 'An existing matching success SetValue audit ACE is required; no SACL is added.'}
    if($State.Engine -isnot [string] -or -not $State.Engine -or $State.EngineHash -cnotmatch '^[a-f0-9]{64}$'){throw 'Native engine identity is incomplete.'}
    if(-not @($State.Sources.PSObject.Properties).Count){throw 'Implementation fingerprints are missing.'}
    foreach($source in $State.Sources.PSObject.Properties){if($source.Value -isnot [string] -or $source.Value -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid implementation fingerprint.'}}
    # Registry last-write time changes after the owned temporary value lifecycle; preserve it in raw receipts.
    $stable=$State|Select-Object * -ExcludeProperty Registry
    $stable|Add-Member NoteProperty Registry ($r|Select-Object * -ExcludeProperty Identity)
    Get-WelaFileProbeKey $stable
}
function Invoke-WelaRegistryValueProbeOperation {
    param($State,[string]$Nonce)
    $fresh=Get-WelaRegistryValueProbeState
    if((Get-WelaRegistryValueProbeStateKey $fresh) -cne (Get-WelaRegistryValueProbeStateKey $State) -or $fresh.Registry.Identity -cne $State.Registry.Identity){throw 'Registry prerequisites changed before the owned value operation.'}
    $watermark=Get-WelaFileProbeWatermark;$before=[Wela.RegistryValueProbe.TokenReader]::Snapshot();$target=$null;$native=$null
    $launch=[Wela.RegistryValueProbe.Target]::UtcNow()
    try{$target=[Wela.RegistryValueProbe.Target]::new($true);$native=$target.Run($Nonce,$State.Registry.Identity,$State.Registry.DescriptorBase64)}finally{if($target){$target.Dispose()}}
    $after=[Wela.RegistryValueProbe.TokenReader]::Snapshot()
    $operation=[pscustomobject]@{Kind='WelaOwnedRegistryValueModification';Nonce=$Nonce;ProcessId=$PID;Executable=$State.Engine;RecordIdBefore=$watermark;BeforeToken=$before;AfterToken=$after;LaunchedUtc=$launch.ToString('o');ObservedUtc=[Wela.RegistryValueProbe.Target]::UtcNow().ToString('o');Native=$native}
    return $operation
}
function Assert-WelaRegistryValueProbeOperation {
    param($Operation,$State)
    $r=$Operation.Native
    if($Operation.Kind -cne 'WelaOwnedRegistryValueModification' -or $Operation.Nonce -cnotmatch '^[a-f0-9]{32}$' -or -not(Test-WelaFileProbeInteger $Operation.ProcessId) -or $Operation.ProcessId -le 0 -or $Operation.Executable -ine $State.Engine -or -not(Test-WelaFileProbeInteger $Operation.RecordIdBefore) -or $Operation.RecordIdBefore -le 0){throw 'Incomplete registry operation authority.'}
    if($r.Succeeded -isnot [bool] -or -not $r.Succeeded -or $r.CleanupComplete -isnot [bool] -or -not $r.CleanupComplete -or $r.Nonce -cne $Operation.Nonce -or $r.Name -cne ('WELA_Probe_'+$Operation.Nonce) -or $r.BeforeValue -cne ('WELA_BEFORE_'+$Operation.Nonce) -or $r.AfterValue -cne ('WELA_AFTER_'+$Operation.Nonce) -or $r.HandleId -cnotmatch '^0x[1-9a-f][0-9a-f]*$'){throw ('Owned value operation or cleanup failed: '+$r.Diagnostic)}
    if($r.Before.Path -ine $State.Registry.Path -or $r.After.Path -ine $State.Registry.Path -or (Get-WelaFileProbeKey $r.Before.Values) -cne (Get-WelaFileProbeKey $State.Registry.Values) -or $r.Before.Identity -cne $State.Registry.Identity -or $r.Before.DescriptorBase64 -cne $State.Registry.DescriptorBase64 -or $r.After.DescriptorBase64 -cne $State.Registry.DescriptorBase64 -or (Get-WelaFileProbeKey $r.Before.Values) -cne (Get-WelaFileProbeKey $r.After.Values)){throw 'Held registry descriptor or unrelated values changed.'}
    $start=ConvertTo-WelaArrivalUtc $r.StartedUtc;$returned=ConvertTo-WelaArrivalUtc $r.WriteReturnedUtc;$end=ConvertTo-WelaArrivalUtc $r.CompletedUtc
    if($start -lt (ConvertTo-WelaArrivalUtc $Operation.LaunchedUtc) -or $returned -lt $start -or $end -lt $returned -or $end -gt (ConvertTo-WelaArrivalUtc $Operation.ObservedUtc) -or ($end-$start).TotalSeconds -gt 10){throw 'Invalid precise native value-modification interval.'}
    if((Get-WelaFileProbeTokenKey $Operation.BeforeToken) -cne (Get-WelaFileProbeTokenKey $Operation.AfterToken) -or (Get-WelaFileProbeTokenKey $Operation.BeforeToken) -cne (Get-WelaFileProbeTokenKey $State.Token)){throw 'Registry operation changed the full process token.'}
}
function Read-WelaRegistryValueProbeEvents {
    param($Operation)
    # Keep out-of-interval candidates for diagnosis; the matcher never credits them.
    $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4657 and EventRecordID>$($Operation.RecordIdBefore)]]"
    $reader=$null;$records=New-Object 'System.Collections.Generic.List[string]'
    try {
        $q=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Security',[Diagnostics.Eventing.Reader.PathType]::LogName,$query);$q.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($q);$reader.BatchSize=16
        while($records.Count -lt 256){$event=$reader.ReadEvent([TimeSpan]::FromSeconds(1));if($null -eq $event){break};try{$xml=$event.ToXml();if($xml.Length -gt 131072){throw 'Security event exceeds the XML bound.'};$records.Add($xml)}finally{$event.Dispose()}}
        $status=@($reader.LogStatus|ForEach-Object {[pscustomobject]@{LogName=$_.LogName;StatusCode=$_.StatusCode}});Assert-WelaChannelQueryStatus Security $status
        [pscustomobject]@{Xml=@($records.ToArray());Capped=($records.Count -ge 256);Query=$query;MaximumEvents=256;LogStatus=$status}
    }finally{if($reader){$reader.Dispose()}}
}
function Test-WelaRegistryValueProbeEvent {
    param([string]$Xml,$Operation,$State)
    $reader=$null
    try {
        if($Xml.Length -gt 131072){return $false}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','Keywords','EventRecordID','Channel','Computer','TimeCreated','Level','Task','Opcode')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or $system.EventID.InnerText -cne '4657' -or $system.Version.InnerText -cne '0' -or $system.Keywords.InnerText -ine '0x8020000000000000' -or $system.Channel.InnerText -cne 'Security' -or $system.Level.InnerText -cne '0' -or $system.Task.InnerText -cne '12801' -or $system.Opcode.InnerText -cne '0' -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.RecordIdBefore){return $false}
        $computers=@($State.Computer);if($State.Host.DomainJoined){$computers+=$State.Computer+'.'+$State.Host.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime');if($time -lt (ConvertTo-WelaArrivalUtc $Operation.Native.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.Native.CompletedUtc)){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e')){return $false};$name=$node.GetAttribute('Name');if(-not $name -or $data.ContainsKey($name) -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$data[$name]=$node.InnerText}
        foreach($name in @('SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectName','ObjectValueName','HandleId','OperationType','OldValueType','OldValue','NewValueType','NewValue','ProcessId','ProcessName')){if(-not $data.ContainsKey($name)){return $false}}
        $nativePath='\REGISTRY\USER\'+$State.Token.Sid+'\Software\WELA\AuditProbe'
        if($data.Count -ne 14 -or $data.ObjectName -ine $nativePath -or $data.ObjectValueName -cne $Operation.Native.Name -or $data.ProcessName -ine $State.Engine -or $data.SubjectUserSid -cne $Operation.BeforeToken.Sid -or $data.OperationType -cne '%%1905' -or $data.OldValueType -cne '%%1873' -or $data.NewValueType -cne '%%1873' -or $data.OldValue -cne $Operation.Native.BeforeValue -or $data.NewValue -cne $Operation.Native.AfterValue){return $false}
        foreach($name in @('SubjectLogonId','ProcessId','HandleId')){if($data[$name] -cnotmatch '^0x[0-9a-fA-F]+$'){return $false}}
        if([Convert]::ToUInt64($data.SubjectLogonId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.BeforeToken.AuthenticationId.Substring(2),16) -or [Convert]::ToUInt64($data.ProcessId.Substring(2),16) -ne $Operation.ProcessId -or [Convert]::ToUInt64($data.HandleId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.Native.HandleId.Substring(2),16)){return $false}
        $true
    }catch{$false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaRegistryValueProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new RegistryProbeOutputPath; Plan creates no output.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaRegistryValueProbe';Action=$Action;Status='Unverified';ExitCode=1;RecordedUtc=[datetime]::UtcNow.ToString('o');Before=$null;After=$null;Operation=$null;Candidates=0;Matches=0;Query=$null;Artifacts=@();Diagnostic='';OutputPath=$null;ConfigurationChanges=0;TemporaryRegistryValueWrites='Only Run: create/modify/delete one owned nonce value in fixed current-user probe key.';SigmaEvtxCredit=0;Scope='One owned current-user registry REG_SZ modification only; other keys/users, inherited coverage, forwarding and Sigma are unverified. Native key last-write metadata changes.'}
    $outputKey=$null;$beforeKey=$null
    try {
        if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $script:ScriptRoot;$outputKey=Get-WelaFileProbeOutputKey $report.OutputPath}
        $before=Get-WelaRegistryValueProbeState;$beforeKey=Get-WelaRegistryValueProbeStateKey $before;$report.Before=$before
        if($Action -eq 'Plan'){$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'before.json' ($before|ConvertTo-Json -Depth 24)
        $nonce=[guid]::NewGuid().ToString('N');$intent=[pscustomobject]@{Kind='WelaOwnedRegistryValueIntent';Nonce=$nonce;Path=$before.Registry.Path;Name=('WELA_Probe_'+$nonce);Original='Absent';Outcome='Pending; interruption may leave the owned marker value. Inspect receipts before manual cleanup.'}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'intent.json' ($intent|ConvertTo-Json -Depth 8)
        $operation=Invoke-WelaRegistryValueProbeOperation $before $nonce;$report.Operation=$operation
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'operation.json' ($operation|ConvertTo-Json -Depth 24)
        Assert-WelaRegistryValueProbeOperation $operation $before
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do{$batch=Read-WelaRegistryValueProbeEvents $operation;$report.Candidates=@($batch.Xml).Count;$report.Query=$batch.Query
            if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'Security query reached its 256-event cap or completeness is unknown.'}
            $matches=@($batch.Xml|Where-Object {Test-WelaRegistryValueProbeEvent $_ $operation $before});if($matches.Count){break};Start-Sleep -Milliseconds 250
        }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.Matches=$matches.Count
        if($matches.Count -ne 1){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey ('candidate-'+$i+'.xml') $xml};throw 'Exactly one attributable native4657 was not observed in the measured owned-value modification phase.'}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'event.xml' $matches[0]
        if((Get-WelaFileProbeWatermark) -lt $operation.RecordIdBefore){throw 'Security record boundary moved backwards.'}
        $after=Get-WelaRegistryValueProbeState;$report.After=$after
        if((Get-WelaRegistryValueProbeStateKey $after) -cne $beforeKey){throw 'Registry values/security, policy, channel, host, token or implementation changed during the probe.'}
        $report.Status='RegistryValueModificationObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    finally{if($report.Before -and -not $report.After){try{$report.After=Get-WelaRegistryValueProbeState}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}}}
    if($report.OutputPath -and $outputKey){
        if($report.After){$report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'after.json' ($report.After|ConvertTo-Json -Depth 24)}
        $null=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'manifest.json' ($report|ConvertTo-Json -Depth 28)
    }
    $report
}
