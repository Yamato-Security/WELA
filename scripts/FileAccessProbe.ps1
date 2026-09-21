# Explicit one-byte existing-file read and exact local Security4663 evidence.
function Initialize-WelaFileProbeNative {
    Initialize-WelaWmiProbeNative
    $source=Join-Path $PSScriptRoot 'FileAccessProbeNative.cs';$bytes=[IO.File]::ReadAllBytes($source);$hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.FileAccessProbe.FileHandle' -as [type])){
        $definition=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).Replace('__WELA_FILE_PROBE_SOURCE_SHA256__',$hash)
        Add-Type -TypeDefinition $definition -ErrorAction Stop
    }
    if([Wela.FileAccessProbe.FileHandle]::SourceSha256 -cne $hash){throw 'Loaded file probe helper differs from its source; start a fresh session.'}
}
function Test-WelaFileProbeInteger {param($Value) ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64])}
function Assert-WelaFileProbePath {
    param([string]$Path)
    if(-not $Path -or $Path.Length -gt 240 -or $Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '["*?<>|/\x00-\x1f]|(^|\\)\.\.?($|\\)|[ .](\\|$)|\\$|\\\\'){throw 'Select one exact ordinary absolute local leaf file, at most 240 characters; links, streams, wildcards and remote paths are unsupported.'}
}
function Get-WelaFileProbeSources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/FileAccessProbe.ps1','scripts/FileAccessProbeWorker.ps1','scripts/FileAccessProbeNative.cs','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/Configuration.ps1','scripts/CustomAuditProfiles.ps1','scripts/IpsecPrerequisites.ps1','modules/AuditProfiles.psm1','config/audit_profiles.json')) {
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ('../'+$name)) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Get-WelaFileProbeKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Get-WelaFileProbeTokenKey {
    param($Token)
    foreach($name in @('Sid','Name','AuthenticationId','AuthenticationType','ImpersonationLevel','TokenSource')){if($Token.$name -isnot [string]){throw 'Incomplete typed file-reader token.'}}
    if($Token.Sid -cnotmatch '^S-1-\d+(-\d+)+$' -or $Token.AuthenticationId -cnotmatch '^0x[0-9a-f]+$' -or $Token.TokenSource -cne 'Process' -or $Token.Groups -isnot [array] -or -not $Token.Groups.Count -or $Token.Privileges -isnot [array]){throw 'An ordinary native primary-token file reader is required.'}
    foreach($group in $Token.Groups){if($group.Sid -isnot [string] -or $group.Sid -cnotmatch '^S-1-\d+(-\d+)+$' -or -not(Test-WelaFileProbeInteger $group.Attributes)){throw 'Incomplete typed file-reader group.'}}
    foreach($privilege in $Token.Privileges){if($privilege.Luid -isnot [string] -or $privilege.Luid -cnotmatch '^0x[0-9a-f]+$' -or -not(Test-WelaFileProbeInteger $privilege.Attributes)){throw 'Incomplete typed file-reader privilege.'}}
    Get-WelaFileProbeKey $Token
}
function Get-WelaFileProbeReaderKey {
    param($Reader,[switch]$AuthorizationOnly)
    foreach($name in @('UserSid','UserName','AuthenticationId','TokenId','ModifiedId','TokenType','Impersonation')){if($Reader.$name -isnot [string]){throw 'Incomplete typed reader observation.'}}
    if($Reader.TokenType -cne 'Primary' -or $Reader.Impersonation -cne 'Absent' -or $Reader.ElevatedAdministrator -isnot [bool] -or -not $Reader.ElevatedAdministrator){throw 'An elevated primary-token reader with no impersonation is required.'}
    if($AuthorizationOnly){Get-WelaFileProbeKey ($Reader|Select-Object UserSid,UserName,AuthenticationId,GroupSids,GroupCount,PrivilegeCount,ElevatedAdministrator,TokenType,Impersonation)}
    else{Get-WelaFileProbeKey $Reader}
}
function Assert-WelaFileProbeSnapshot {
    param($Snapshot)
    foreach($name in @('Path','NativePath','Identity','DescriptorBase64','StateKey')){if($Snapshot.$name -isnot [string] -or -not $Snapshot.$name){throw 'Incomplete typed file observation.'}}
    Assert-WelaFileProbePath $Snapshot.Path
    if($Snapshot.NativePath -cnotmatch '^\\Device\\[^\\]+\\'){throw 'Incomplete native NT file path observation.'}
    if($Snapshot.StateKey -cnotmatch '^[a-f0-9]{64}$' -or -not(Test-WelaFileProbeInteger $Snapshot.Size) -or $Snapshot.Size -le 0 -or -not(Test-WelaFileProbeInteger $Snapshot.SecurityInformation) -or $Snapshot.SecurityInformation -ne 511 -or -not(Test-WelaFileProbeInteger $Snapshot.Links) -or $Snapshot.Links -ne 1 -or -not(Test-WelaFileProbeInteger $Snapshot.Attributes) -or ($Snapshot.Attributes -band (16+1024+4096+16384+262144+4194304))){throw 'Only a complete nonempty ordinary single-link leaf-file observation is supported.'}
    $Snapshot.LastWriteUtc=(ConvertTo-WelaArrivalUtc $Snapshot.LastWriteUtc).UtcDateTime.ToString('o')
    if($Snapshot.Aces -isnot [array] -or $Snapshot.Aces.Count -gt 128){throw 'Missing or oversized file audit ACE inventory.'}
    foreach($ace in $Snapshot.Aces){
        if($ace.Ordinary -isnot [bool] -or -not(Test-WelaFileProbeInteger $ace.Type) -or -not(Test-WelaFileProbeInteger $ace.Flags) -or -not(Test-WelaFileProbeInteger $ace.Mask) -or $ace.Binary -isnot [string]){throw 'Incomplete typed file audit ACE.'}
        if($ace.Ordinary -and ($ace.Type -ne 2 -or $ace.Sid -isnot [string] -or $ace.Sid -cnotmatch '^S-1-\d+(-\d+)+$')){throw 'Incomplete ordinary file audit ACE.'}
    }
}
function Get-WelaFileProbeSnapshot {
    param([string]$Path)
    Assert-WelaFileProbePath $Path;Initialize-WelaFileProbeNative
    $handle=[Wela.FileAccessProbe.FileHandle]::new($Path,$false)
    try{$handle.Observe()}finally{$handle.Dispose()}
}
function Get-WelaFileProbeState {
    param([string]$Path)
    Assert-WelaFileProbePath $Path;Initialize-WelaFileProbeNative
    $services=@(Get-Service -Name EventLog,Winmgmt,RpcSs -ErrorAction Stop|Sort-Object Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status}})
    if($services.Count -ne 3 -or @($services|Where-Object Status -ne 'Running').Count){throw 'EventLog, Winmgmt and RpcSs must already be running.'}
    $null=Get-WelaFileProbeReaderKey (Get-WelaChannelReader)
    $tokenBefore=[Wela.WmiProbe.Native]::Snapshot();$snapshot=Get-WelaFileProbeSnapshot $Path
    $hostState=Get-WelaChannelReadHost
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security')
    try{$log=[pscustomobject]@{Name=$channel.LogName;Enabled=$channel.IsEnabled;SecurityDescriptor=$channel.SecurityDescriptor;MaximumSize=$channel.MaximumSizeInBytes;Mode=[string]$channel.LogMode;Type=[string]$channel.LogType;Provider=$channel.OwningProviderName}}finally{$channel.Dispose()}
    $policy=Get-WelaEffectiveAuditPolicy;$masks=[ordered]@{};foreach($guid in @($policy.Keys|Sort-Object)){$masks[$guid]=$policy[$guid]}
    $engine=(Get-Process -Id $PID -ErrorAction Stop).Path
    $reader=Get-WelaChannelReader;$token=[Wela.WmiProbe.Native]::Snapshot()
    if((Get-WelaFileProbeTokenKey $tokenBefore) -cne (Get-WelaFileProbeTokenKey $token)){throw 'File prerequisite observation changed token groups or privileges.'}
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Host=$hostState;MachineGuid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid;Services=$services;Reader=($reader|Select-Object UserSid,UserName,AuthenticationId,GroupSids,GroupCount,PrivilegeCount,ElevatedAdministrator,TokenType,Impersonation);Token=$token;File=$snapshot;AuditPolicies=[pscustomobject]$masks;Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Channel=$log;Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant();Sources=(Get-WelaFileProbeSources)}
}
function Get-WelaFileProbeStateKey {
    param($State)
    Assert-WelaFileProbeSnapshot $State.File;$null=Get-WelaFileProbeTokenKey $State.Token
    if($State.Computer -isnot [string] -or -not $State.Computer -or $State.MachineGuid -isnot [string] -or $State.MachineGuid -cnotmatch '^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$' -or -not(Test-WelaFileProbeInteger $State.Host.ProductType) -or $State.Host.ProductType -notin @(1,2,3) -or -not(Test-WelaFileProbeInteger $State.Host.Build) -or $State.Host.Build -notin @(22000,22621,22631,20348,26100,26200) -or $State.Host.DomainJoined -isnot [bool]){throw 'Complete actual supported Windows host identity is required.'}
    if($State.Services -isnot [array] -or $State.Services.Count -ne 3 -or (@($State.Services.Name)-join ',') -cne 'EventLog,RpcSs,Winmgmt'){throw 'Complete native service observations are required.'}
    foreach($service in $State.Services){if($service.Status -isnot [string] -or $service.Status -cne 'Running'){throw 'Required services must already be running.'}}
    $mask=$State.AuditPolicies.'0CCE921D-69AE-11D9-BED3-505054503030'
    if(-not(Test-WelaFileProbeInteger $mask) -or $mask -notin @(1,3) -or $State.Precedence.ValueExists -isnot [bool] -or -not $State.Precedence.ValueExists -or $State.Precedence.Type -isnot [string] -or $State.Precedence.Type -cne 'DWord' -or -not(Test-WelaFileProbeInteger $State.Precedence.Value) -or $State.Precedence.Value -ne 1){throw 'File System success auditing and typed audit precedence DWORD1 must already be configured.'}
    if($State.Channel.Name -isnot [string] -or $State.Channel.Name -cne 'Security' -or $State.Channel.Enabled -isnot [bool] -or -not $State.Channel.Enabled -or $State.Channel.SecurityDescriptor -isnot [string] -or -not $State.Channel.SecurityDescriptor){throw 'The Security channel must already be enabled with readable configuration.'}
    if($State.Reader.TokenType -isnot [string] -or $State.Reader.TokenType -cne 'Primary' -or $State.Reader.Impersonation -isnot [string] -or $State.Reader.Impersonation -cne 'Absent' -or $State.Reader.ElevatedAdministrator -isnot [bool] -or -not $State.Reader.ElevatedAdministrator -or $State.Reader.UserSid -isnot [string] -or $State.Reader.UserSid -cne $State.Token.Sid){throw 'Complete elevated primary-token reader identity is required.'}
    $sids=@($State.Token.Sid)+@($State.Token.Groups|Where-Object {($_.Attributes -band 4) -and -not($_.Attributes -band 16)}|ForEach-Object Sid)
    $matches=@($State.File.Aces|Where-Object {$_.Ordinary -and $_.Type -eq 2 -and ($_.Flags -band 64) -and -not($_.Flags -band 8) -and ($_.Mask -band 1) -and $_.Sid -in $sids})
    if(-not $matches.Count){throw 'No existing ordinary success ReadData audit ACE matches this token on the selected file; no SACL is added.'}
    foreach($name in @('Engine','EngineHash')){if($State.$name -isnot [string] -or -not $State.$name){throw 'Missing native engine identity.'}}
    if($State.EngineHash -cnotmatch '^[a-f0-9]{64}$' -or -not @($State.Sources.PSObject.Properties).Count){throw 'Missing implementation fingerprints.'}
    foreach($source in $State.Sources.PSObject.Properties){if($source.Value -isnot [string] -or $source.Value -cnotmatch '^[a-f0-9]{64}$'){throw 'Malformed implementation fingerprint.'}}
    # Windows paths may change spelling/case while referring to this same native identity.
    $State|ConvertTo-Json -Depth 24 -Compress
}
function Get-WelaFileProbeWatermark {
    $result=Read-WelaChannelLatest Security
    if($result.Status -isnot [string] -or $result.Status -cne 'EventObserved' -or -not(Test-WelaFileProbeInteger $result.Event.RecordId) -or $result.Event.RecordId -lt 1){throw 'A successful native Security query and positive record boundary are required.'}
    [long]$result.Event.RecordId
}
function Get-WelaFileProbeOutputKey {
    param([string]$Path)
    $full=Resolve-WelaArrivalPath $Path;$item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if(-not $item.PSIsContainer){throw 'Probe output is not a directory.'}
    $acl=Get-Acl -LiteralPath $full -ErrorAction Stop
    Get-WelaFileProbeKey ([pscustomobject]@{Path=$item.FullName;CreatedUtc=$item.CreationTimeUtc.ToString('o');Attributes=[int]$item.Attributes;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)})
}
function Write-WelaFileProbeArtifact {
    param([string]$Root,[string]$OutputKey,[string]$Name,[string]$Text)
    if((Get-WelaFileProbeOutputKey $Root) -cne $OutputKey){throw 'Private probe output directory changed.'}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);$path=Join-Path $Root $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $hash=Get-WelaArrivalHash $bytes
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'Saved probe evidence hash differs.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
function Assert-WelaFileProbeOperation {
    param($Operation,$State,[string]$Nonce,[int]$ProcessId,[DateTimeOffset]$LaunchedUtc,[DateTimeOffset]$ObservedUtc)
    foreach($name in @('Kind','Nonce','Executable','FilePath')){if($Operation.$name -isnot [string]){throw 'Untyped fixed file worker authority.'}}
    if($Operation.Kind -cne 'WelaOneByteFileRead' -or $Operation.Nonce -cne $Nonce -or -not(Test-WelaFileProbeInteger $Operation.ProcessId) -or $Operation.ProcessId -ne $ProcessId -or $Operation.Executable -ine $State.Engine -or $Operation.FilePath -ine $State.File.Path){throw 'Unexpected fixed file worker identity.'}
    $read=$Operation.Read
    foreach($name in @('Clock','HandleId','BeforeKey','AfterKey')){if($read.$name -isnot [string]){throw 'Untyped native read receipt.'}}
    if($read.Clock -cne 'GetSystemTimePreciseAsFileTime' -or $read.Succeeded -isnot [bool] -or -not $read.Succeeded -or -not(Test-WelaFileProbeInteger $read.ReadCalls) -or $read.ReadCalls -ne 1 -or -not(Test-WelaFileProbeInteger $read.BytesRead) -or $read.BytesRead -ne 1 -or $read.HandleId -cnotmatch '^0x[0-9a-f]+$' -or [Convert]::ToUInt64($read.HandleId.Substring(2),16) -eq 0 -or $read.BeforeKey -cne $State.File.StateKey -or $read.AfterKey -cne $State.File.StateKey){throw 'Expected exactly one successful byte read from the unchanged held file.'}
    $start=ConvertTo-WelaArrivalUtc $read.StartedUtc;$end=ConvertTo-WelaArrivalUtc $read.CompletedUtc
    if($LaunchedUtc -gt $ObservedUtc -or $start -lt $LaunchedUtc -or $end -lt $start -or $end -gt $ObservedUtc -or ($end-$start).TotalSeconds -gt 20){throw 'Invalid precise one-byte native read interval.'}
    if((Get-WelaFileProbeTokenKey $Operation.BeforeToken) -cne (Get-WelaFileProbeTokenKey $Operation.AfterToken) -or (Get-WelaFileProbeTokenKey $Operation.BeforeToken) -cne (Get-WelaFileProbeTokenKey $State.Token) -or
       (Get-WelaFileProbeReaderKey $Operation.BeforeReader) -cne (Get-WelaFileProbeReaderKey $Operation.AfterReader) -or (Get-WelaFileProbeReaderKey $Operation.BeforeReader -AuthorizationOnly) -cne (Get-WelaFileProbeKey $State.Reader)){throw 'Worker primary token differs from the caller or changed during the native read.'}
    $read.StartedUtc=$start.UtcDateTime.ToString('o');$read.CompletedUtc=$end.UtcDateTime.ToString('o')
}
function Start-WelaFileProbeRead {
    param($State,[string]$RequestPath,[string]$Nonce)
    $fresh=Get-WelaFileProbeState $State.File.Path
    if((Get-WelaFileProbeStateKey $fresh) -cne (Get-WelaFileProbeStateKey $State)){throw 'File probe prerequisites drifted before worker launch.'}
    $watermark=Get-WelaFileProbeWatermark;$worker=Join-Path $PSScriptRoot 'FileAccessProbeWorker.ps1'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$State.Engine;$info.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'" -RequestPath "'+$RequestPath+'" -Nonce '+$Nonce
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true);$info.StandardErrorEncoding=$info.StandardOutputEncoding;$process=$null
    try {
        $launch=[DateTimeOffset][Wela.FileAccessProbe.FileHandle]::UtcNow();$process=[Diagnostics.Process]::Start($info)
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(20000)){$process.Kill();$null=$process.WaitForExit(1000);throw 'File worker exceeded twenty seconds; the read may have been attempted.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),1000)){throw 'File worker output did not complete.'}
        if($stdout.Result.Length -gt 1048576 -or $stderr.Result.Length -gt 65536){throw 'File worker output exceeded its evidence bound.'}
        if($process.ExitCode -ne 0 -or $stderr.Result){throw ('Fixed file worker failed: '+$stderr.Result)}
        $operation=ConvertFrom-WelaArrivalJson $stdout.Result
        Assert-WelaFileProbeOperation $operation $State $Nonce $process.Id $launch ([DateTimeOffset][Wela.FileAccessProbe.FileHandle]::UtcNow())
        $operation|Add-Member NoteProperty RecordIdBefore $watermark
        $operation
    }finally{if($process){try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(1000)}}finally{$process.Dispose()}}}
}
function Read-WelaFileProbeEvents {
    param($Operation)
    # Keep out-of-interval candidates for diagnosis; the matcher never credits them.
    $query="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4663 and EventRecordID>$($Operation.RecordIdBefore)]]"
    $reader=$null;$records=New-Object 'System.Collections.Generic.List[string]'
    try {
        $q=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Security',[Diagnostics.Eventing.Reader.PathType]::LogName,$query);$q.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($q);$reader.BatchSize=16
        while($records.Count -lt 256){$event=$reader.ReadEvent([TimeSpan]::FromSeconds(1));if($null -eq $event){break};try{$xml=$event.ToXml();if($xml.Length -gt 131072){throw 'Security event exceeds the XML bound.'};$records.Add($xml)}finally{$event.Dispose()}}
        $status=@($reader.LogStatus|ForEach-Object {[pscustomobject]@{LogName=$_.LogName;StatusCode=$_.StatusCode}});Assert-WelaChannelQueryStatus Security $status
        [pscustomobject]@{Xml=@($records.ToArray());Capped=($records.Count -ge 256);Query=$query;MaximumEvents=256;LogStatus=$status}
    }finally{if($reader){$reader.Dispose()}}
}
function Test-WelaFileProbeEvent {
    param([string]$Xml,$Operation,$State)
    $reader=$null
    try {
        if($Xml.Length -gt 131072){return $false}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','Keywords','EventRecordID','Channel','Computer','TimeCreated','Level','Task','Opcode')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or $system.EventID.InnerText -cne '4663' -or $system.Version.InnerText -cne '1' -or $system.Keywords.InnerText -ine '0x8020000000000000' -or $system.Channel.InnerText -cne 'Security' -or $system.Level.InnerText -cne '0' -or $system.Task.InnerText -cne '12800' -or $system.Opcode.InnerText -cne '0' -or $system.EventRecordID.InnerText -cnotmatch '^[1-9][0-9]*$' -or [long]$system.EventRecordID.InnerText -le $Operation.RecordIdBefore){return $false}
        $computers=@($State.Computer);if($State.Host.DomainJoined){$computers+=$State.Computer+'.'+$State.Host.Domain};if($system.Computer.InnerText -notin $computers){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime');if($time -lt (ConvertTo-WelaArrivalUtc $Operation.Read.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.Read.CompletedUtc)){return $false}
        $data=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e')){return $false};$name=$node.GetAttribute('Name');if(-not $name -or $data.ContainsKey($name) -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$data[$name]=$node.InnerText}
        foreach($name in @('SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectServer','ObjectType','ObjectName','HandleId','AccessList','AccessMask','ProcessId','ProcessName','ResourceAttributes')){if(-not $data.ContainsKey($name)){return $false}}
        if($data.Count -ne 13 -or $data.ObjectServer -cne 'Security' -or $data.ObjectType -cne 'File' -or ($data.ObjectName -ine $State.File.Path -and $data.ObjectName -ine $State.File.NativePath) -or $data.ProcessName -ine $State.Engine -or $data.SubjectUserSid -cne $Operation.BeforeToken.Sid -or $data.AccessList.Trim() -cne '%%4416'){return $false}
        foreach($name in @('SubjectLogonId','AccessMask','ProcessId','HandleId')){if($data[$name] -cnotmatch '^0x[0-9a-fA-F]+$'){return $false}}
        if([Convert]::ToUInt64($data.SubjectLogonId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.BeforeToken.AuthenticationId.Substring(2),16) -or [Convert]::ToUInt64($data.AccessMask.Substring(2),16) -ne 1 -or [Convert]::ToUInt64($data.ProcessId.Substring(2),16) -ne $Operation.ProcessId -or [Convert]::ToUInt64($data.HandleId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.Read.HandleId.Substring(2),16)){return $false}
        $true
    }catch{$false}finally{if($reader){$reader.Dispose()}}
}
function Invoke-WelaFileAccessProbe {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$FilePath,[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    Assert-WelaFileProbePath $FilePath
    if(($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))){throw 'Run requires a new FileProbeOutputPath; Plan creates no output.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaFileAccessProbe';Action=$Action;Status='Unverified';ExitCode=1;RecordedUtc=[datetime]::UtcNow.ToString('o');Before=$null;After=$null;Operation=$null;Candidates=0;Matches=0;Query=$null;Artifacts=@();Diagnostic='';OutputPath=$null;ConfigurationChanges=0;FileDataWrites=0;RetainedContentBytes=0;SigmaEvtxCredit=0;Scope='One current-token local file ReadData success only; failure access, other files/rights/users, inheritance, forwarding and Sigma are unverified. Reads may update native access metadata.'}
    $outputKey=$null;$beforeKey=$null
    try {
        if($Action -eq 'Run'){$report.OutputPath=New-WelaArrivalOutput $OutputPath $script:ScriptRoot;$outputKey=Get-WelaFileProbeOutputKey $report.OutputPath}
        $before=Get-WelaFileProbeState $FilePath;$beforeKey=Get-WelaFileProbeStateKey $before;$report.Before=$before
        if($Action -eq 'Plan'){$report.After=$before;$report.Status='PrerequisitesObserved';$report.ExitCode=0;return $report}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'before.json' ($before|ConvertTo-Json -Depth 24)
        $nonce=[guid]::NewGuid().ToString('N');$intent=[pscustomobject]@{Kind='WelaOneByteFileReadIntent';Nonce=$nonce;Path=$before.File.Path;StateKey=$before.File.StateKey;ExpectedBytes=1;Outcome='Pending; interruption may leave an attempted read without a completion receipt.'}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'intent.json' ($intent|ConvertTo-Json -Depth 8)
        $operation=Start-WelaFileProbeRead $before (Join-Path $report.OutputPath 'before.json') $nonce;$report.Operation=$operation
        if((Get-FileHash -LiteralPath (Join-Path $report.OutputPath 'before.json')).Hash.ToLowerInvariant() -cne $report.Artifacts[0].Sha256){throw 'Worker request evidence changed.'}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'operation.json' ($operation|ConvertTo-Json -Depth 16)
        $timer=[Diagnostics.Stopwatch]::StartNew();$matches=@()
        do{$batch=Read-WelaFileProbeEvents $operation;$report.Candidates=@($batch.Xml).Count;$report.Query=$batch.Query
            if($batch.Capped -isnot [bool] -or $batch.Capped){throw 'Security query reached its 256-event cap or completeness is unknown.'}
            $matches=@($batch.Xml|Where-Object {Test-WelaFileProbeEvent $_ $operation $before});if($matches.Count){break};Start-Sleep -Milliseconds 250
        }while($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        $report.Matches=$matches.Count
        if($matches.Count -ne 1){$i=0;foreach($xml in @($batch.Xml|Select-Object -First 4)){$i++;$report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey ('candidate-'+$i+'.xml') $xml};throw 'Exactly one attributable native4663 was not observed in the precise read interval.'}
        $report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'event.xml' $matches[0]
        if((Get-WelaFileProbeWatermark) -lt $operation.RecordIdBefore){throw 'Security record boundary moved backwards.'}
        $after=Get-WelaFileProbeState $before.File.Path;$report.After=$after
        if((Get-WelaFileProbeStateKey $after) -cne $beforeKey){throw 'File identity/security, policy, channel, host, token or implementation changed during the probe.'}
        $report.Status='FileReadObserved';$report.ExitCode=0
    }catch{$report.Diagnostic=$_.Exception.Message}
    finally{if($report.Before -and -not $report.After){try{$report.After=Get-WelaFileProbeState $report.Before.File.Path}catch{$report.Diagnostic+=' Final observation failed: '+$_.Exception.Message}}}
    if($report.OutputPath -and $outputKey){
        if($report.After){$report.Artifacts+=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'after.json' ($report.After|ConvertTo-Json -Depth 24)}
        $null=Write-WelaFileProbeArtifact $report.OutputPath $outputKey 'manifest.json' ($report|ConvertTo-Json -Depth 28)
    }
    $report
}
