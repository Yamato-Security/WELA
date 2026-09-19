# Fixed, opt-in native telemetry probe. This collector never changes Windows policy.
function Get-WelaProbeState {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) { throw 'Native validation requires 64-bit Windows PowerShell.' }
    $context = Get-WelaDefaultContext
    if (-not (Test-WelaDefaultContextComplete $context)) { throw "Complete native host context is required: $($context.Diagnostic)" }
    $hostContext = Get-WelaHostContext
    if ($hostContext.Build -ne $context.Build) { throw 'Native host readers disagree about the Windows build.' }
    if (($hostContext.Role -eq 'Client' -and $hostContext.Build -notin @(22000,22621,22631,26100,26200)) -or
        ($hostContext.Role -ne 'Client' -and $hostContext.Build -notin @(20348,26100))) { throw 'Host build is outside the reviewed Windows 11 / Server 2022 and 2025 probe scope.' }
    $policies = Get-WelaEffectiveAuditPolicy
    $precedence = Get-WelaRegistryState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
    $commandLine = Get-WelaRegistryState -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'
    $channel = Get-WinEvent -ListLog Security -ErrorAction Stop
    if (@($channel).Count -ne 1 -or $channel.LogName -ne 'Security') { throw 'Exact Security log configuration is unavailable.' }
    [pscustomobject][ordered]@{
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        context = [pscustomobject][ordered]@{computer=[Environment]::MachineName;role=$hostContext.Role;build=$context.Build;patch="$($context.Build).$($context.UBR)";domainJoined=$context.DomainJoined;installedRoles=@($context.InstalledRoles)}
        hostObservation = $context
        auditPolicies = $policies
        auditPrecedence = $precedence
        commandLineCapture = $commandLine
        securityChannelEnabled = [bool]$channel.IsEnabled
    }
}
function Assert-WelaProbePrerequisites {
    param($State)
    $guid = '0cce922b-69ae-11d9-bed3-505054503030'
    if (-not $State -or -not (Test-WelaDefaultContextComplete $State.hostObservation)) { throw 'Complete observed host context is required.' }
    if ($State.context.role -notin @('Client','MemberServer','DomainController','ADCS') -or $State.context.build -ne $State.hostObservation.Build) { throw 'Host context is inconsistent.' }
    $observed=$State.hostObservation
    $roleMatches=switch ($State.context.role) {
        'Client' { $observed.ProductType -eq 1 -and $observed.DomainRole -in @(0,1) }
        'DomainController' { $observed.ProductType -eq 2 -and $observed.DomainRole -in @(4,5) }
        'MemberServer' { $observed.ProductType -eq 3 -and $observed.DomainRole -in @(2,3) }
        'ADCS' { $observed.ProductType -eq 3 -and $observed.DomainRole -in @(2,3) -and $observed.InstalledRoles -contains 'ADCS-Cert-Authority' }
    }
    if (-not $roleMatches -or $State.context.domainJoined -isnot [bool] -or
        $State.context.domainJoined -ne $observed.DomainJoined -or
        $State.context.patch -cne "$($observed.Build).$($observed.UBR)" -or
        $State.context.installedRoles -isnot [array] -or
        (@($State.context.installedRoles | Sort-Object -Unique) -join "`n") -cne (@($observed.InstalledRoles | Sort-Object -Unique) -join "`n")) {
        throw 'Probe role, patch, join or installed-role summary contradicts the detailed host observation.'
    }
    $mask = $State.auditPolicies[$guid]
    if (($mask -isnot [int] -and $mask -isnot [long]) -or $mask -notin @(1,3)) { throw 'Effective Process Creation success auditing is required; no policy was changed.' }
    foreach ($entry in @($State.auditPrecedence,$State.commandLineCapture)) {
        if (-not $entry.ValueExists -or $entry.Type -ne 'DWord' -or ($entry.Value -isnot [int] -and $entry.Value -isnot [long]) -or $entry.Value -ne 1) { throw 'Typed DWORD=1 audit precedence and process command-line capture are required; no policy was changed.' }
    }
    if ($State.securityChannelEnabled -isnot [bool] -or -not $State.securityChannelEnabled) { throw 'Security channel must be observed enabled.' }
}
function Get-WelaProbeStateKey {
    param($State)
    # Timestamps differ; every observed policy and exact host context must remain stable.
    [ordered]@{context=$State.context;host=(Get-WelaDefaultContextKey $State.hostObservation);policies=@($State.auditPolicies.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" });precedence=$State.auditPrecedence;commandLine=$State.commandLineCapture;security=$State.securityChannelEnabled} | ConvertTo-Json -Depth 10 -Compress
}
function Start-WelaProbeProcess {
    $executable = Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Native System32 cmd.exe is unavailable.' }
    $marker = 'WELA_PROBE_' + [guid]::NewGuid().ToString('N')
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$executable; $start.Arguments='/d /c echo ' + $marker
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $began=[DateTime]::UtcNow
    $process=[Diagnostics.Process]::Start($start)
    try {
        $processId=$process.Id
        if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'Fixed benign cmd.exe probe timed out.' }
        $output=$process.StandardOutput.ReadToEnd(); $diagnostic=$process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne 0 -or $output.Trim() -cne $marker) { throw "Fixed benign probe failed: $diagnostic" }
        [pscustomobject]@{ProcessId=$processId;ParentProcessId=$PID;Executable=$executable;Arguments=$start.Arguments;Marker=$marker;StartedUtc=$began.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');ExitCode=$process.ExitCode}
    } finally { $process.Dispose() }
}
function Read-WelaProbeEvents {
    param([DateTime]$StartUtc,[DateTime]$EndUtc,[int]$MaximumEvents=512)
    try {
        $records=@(Get-WinEvent -FilterHashtable @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';Id=4688;StartTime=$StartUtc;EndTime=$EndUtc} -MaxEvents $MaximumEvents -ErrorAction Stop)
        $xml=@(foreach ($record in $records) { try { [string]$record.ToXml() } finally { $record.Dispose() } })
        [pscustomobject]@{Xml=$xml;Capped=($records.Count -ge $MaximumEvents)}
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return [pscustomobject]@{Xml=@();Capped=$false} }
        throw
    }
}
function Test-WelaProbeEvent {
    param([string]$Xml,$Process,$State,[DateTime]$EndUtc)
    $reader=$null
    try {
        $settings=New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null; $settings.MaxCharactersInDocument=4194304
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
        $doc=New-Object Xml.XmlDocument; $doc.XmlResolver=$null; $doc.Load($reader)
        $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable); $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if ($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e')) { return $false }
        if ($doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:UserData',$ns).Count) { return $false }
        $system=@{}
        foreach ($name in @('Provider','EventID','Version','EventRecordID','Channel','Computer','Keywords','TimeCreated')) {
            $nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns)
            if ($nodes.Count -ne 1) { return $false }; $system[$name]=$nodes[0]
        }
        if ($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or
            $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or
            $system.EventID.InnerText -cne '4688' -or $system.Version.InnerText -cne '2' -or $system.Channel.InnerText -cne 'Security' -or
            $system.Keywords.InnerText -ine '0x8020000000000000' -or $system.EventRecordID.InnerText -notmatch '^[1-9][0-9]*$') { return $false }
        $computers=@($State.context.computer)
        if ($State.context.domainJoined) { $computers+= "$($State.context.computer).$($State.hostObservation.Domain)" }
        if ($system.Computer.InnerText -notin $computers) { return $false }
        $eventTime=[DateTimeOffset]::Parse($system.TimeCreated.GetAttribute('SystemTime'),[Globalization.CultureInfo]::InvariantCulture)
        if ($eventTime.UtcDateTime -lt ([DateTimeOffset]::Parse($Process.StartedUtc)).UtcDateTime -or $eventTime.UtcDateTime -gt $EndUtc) { return $false }
        $data=@{}
        foreach ($node in $doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns)) {
            $name=$node.GetAttribute('Name'); if (-not $name -or $data.ContainsKey($name)) { return $false }; $data[$name]=$node.InnerText
        }
        if ($data.NewProcessId -notmatch '^0x[0-9a-f]+$' -or $data.ProcessId -notmatch '^0x[0-9a-f]+$') { return $false }
        if ([Convert]::ToInt64($data.NewProcessId.Substring(2),16) -ne $Process.ProcessId -or [Convert]::ToInt64($data.ProcessId.Substring(2),16) -ne $Process.ParentProcessId -or $data.NewProcessName -ine $Process.Executable) { return $false }
        # Exactly the fixed invocation, permitting the native runtime's image quoting.
        return $data.CommandLine -ieq ($Process.Executable + ' ' + $Process.Arguments) -or $data.CommandLine -ieq ('"' + $Process.Executable + '" ' + $Process.Arguments)
    } catch { return $false } finally { if ($reader) { $reader.Dispose() } }
}
function Write-WelaProbeArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $path=Join-Path $Root $Name
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    [pscustomobject]@{path=$Name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Invoke-WelaNativeValidation {
    param([ValidateSet('Plan','Run')][string]$Action='Plan',[string]$OutputPath,[ValidateRange(1,30)][int]$TimeoutSeconds=15)
    if (($Action -eq 'Run') -ne (-not [string]::IsNullOrWhiteSpace($OutputPath))) { throw 'Run requires a new -ProbeOutputPath directory; Plan does not write artifacts.' }
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaNativeProbeComponents';Probe='security-4688-command-line-v1';Action=$Action;Status='Unverified';ExitCode=0;GeneratedUtc=[DateTime]::UtcNow.ToString('o');PolicyChanges=0;ReadyRuleCredit=0;Scope='Built-in Windows only. Sysmon excluded. Native event collection is not complete-rule or backend validation.';RequiredEvidence=@('Reviewed complete rule and normalization','Backend ingestion','Translated query and successful query result');BeforeState=$null;AfterState=$null;Process=$null;Artifacts=@();Diagnostic='';OutputPath=$null}
    # Reserve a new private directory before any process is launched. New-Item fails on collisions.
    if ($Action -eq 'Run') {
        $full=[IO.Path]::GetFullPath($OutputPath); $parent=Split-Path $full -Parent
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Output parent directory must already exist.' }
        $null=New-Item -ItemType Directory -Path $full -ErrorAction Stop
        $report.OutputPath=$full
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $acl=New-Object Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true,$false)
            foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
            }
            Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
        }
    }
    try {
        $before=Get-WelaProbeState; $report.BeforeState=$before
        $beforeKey=Get-WelaProbeStateKey $before
        if ($Action -eq 'Run') { $report.Artifacts+=Write-WelaProbeArtifact $full 'before-state.json' ($before | ConvertTo-Json -Depth 16) }
        Assert-WelaProbePrerequisites $before
        if ($Action -eq 'Plan') { $report.Status='PrerequisitesObserved'; return $report }
        $fresh=Get-WelaProbeState; Assert-WelaProbePrerequisites $fresh
        if ((Get-WelaProbeStateKey $fresh) -cne $beforeKey) { throw 'Native prerequisite or context drift before probe launch.' }
        $process=Start-WelaProbeProcess; $report.Process=$process
        $report.Artifacts+=Write-WelaProbeArtifact $full 'process.json' ($process | ConvertTo-Json -Depth 6)
        $timer=[Diagnostics.Stopwatch]::StartNew(); $matches=@()
        do {
            $end=[DateTime]::UtcNow
            $batch=Read-WelaProbeEvents -StartUtc ([DateTimeOffset]::Parse($process.StartedUtc).UtcDateTime) -EndUtc $end
            if ($batch.Capped) { throw '4688 query reached its 512-event cap; collection is incomplete. Retry in a quieter isolated environment.' }
            $matches=@($batch.Xml | Where-Object { Test-WelaProbeEvent -Xml $_ -Process $process -State $before -EndUtc $end })
            if ($matches.Count -gt 1) { throw 'Ambiguous native probe events; no event was selected.' }
            if ($matches.Count -eq 1) { break }
            if ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) { Start-Sleep -Milliseconds 250 }
        } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        if ($matches.Count -ne 1) { throw 'No exact native 4688 event with the probe PID, creator PID, path and full command line arrived within the timeout.' }
        $report.Artifacts+=Write-WelaProbeArtifact $full 'event.xml' ([string]$matches[0])
        $after=Get-WelaProbeState; $report.AfterState=$after
        $report.Artifacts+=Write-WelaProbeArtifact $full 'after-state.json' ($after | ConvertTo-Json -Depth 16)
        Assert-WelaProbePrerequisites $after
        if ((Get-WelaProbeStateKey $after) -cne $beforeKey) { throw 'Observed host or policy drift during native probe collection.' }
        $report.Status='NativeEventObserved'
    } catch { $report.Status='Unverified'; $report.ExitCode=1; $report.Diagnostic=$_.Exception.Message }
    if ($Action -eq 'Run') {
        $null=Write-WelaProbeArtifact $full 'manifest.json' ($report | ConvertTo-Json -Depth 20)
    }
    return $report
}
