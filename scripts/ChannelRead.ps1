# Queries the actual current primary token. No credential, impersonation or configuration adapters.
function Get-WelaChannelReadSources {
    $sources=[ordered]@{}
    foreach($path in @('WELA.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','modules/NativeProviders.psm1','config/native_channel_profile.json')) {
        $sources[$path]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Get-WelaChannelReadKey { param($Value) ConvertTo-Json -InputObject $Value -Depth 20 -Compress }
function Get-WelaChannelReader {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'channel-read requires native 64-bit Windows.'}
    $nativeBytes=[IO.File]::ReadAllBytes((Join-Path $script:ScriptRoot 'scripts/ChannelReadNative.cs'))
    $nativeHash=Get-WelaArrivalHash $nativeBytes
    if(-not ('Wela.ChannelRead.Token' -as [type])){
        Add-Type -TypeDefinition ([Text.UTF8Encoding]::new($false,$true).GetString($nativeBytes).TrimStart([char]0xfeff)) -ErrorAction Stop
        [Wela.ChannelRead.Token]::SourceSha256=$nativeHash
    }
    if([Wela.ChannelRead.Token]::SourceSha256 -cne $nativeHash){throw 'Loaded channel-reader helper differs from current source; start a fresh PowerShell process.'}
    $threadIdentity=[Security.Principal.WindowsIdentity]::GetCurrent($true)
    if($null -ne $threadIdentity){$threadIdentity.Dispose();throw 'Impersonated readers are unsupported; launch WELA under the intended primary token.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $stats=[Wela.ChannelRead.Token]::Read($identity.Token)
        [pscustomobject][ordered]@{
            Computer=[Environment]::MachineName;ProcessId=$PID;UserSid=$identity.User.Value;UserName=$identity.Name
            TokenId=$stats.TokenId.ToString();AuthenticationId=$stats.AuthenticationId.ToString();ModifiedId=$stats.ModifiedId.ToString()
            GroupSids=@($identity.Groups|ForEach-Object Value|Sort-Object)
            GroupCount=$stats.GroupCount;PrivilegeCount=$stats.PrivilegeCount
            ElevatedAdministrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            TokenType='Primary';Impersonation='Absent'
        }
    } finally {$identity.Dispose()}
}
function Get-WelaChannelReadHost {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $build=[int]$os.BuildNumber
    if(($os.ProductType -eq 1 -and $build -notin @(22000,22621,22631,26100,26200)) -or ($os.ProductType -in @(2,3) -and $build -notin @(20348,26100)) -or $os.ProductType -notin @(1,2,3)){throw 'Host is outside reviewed Windows 11 / Server 2022 and 2025 builds.'}
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;Build=$build;UBR=$version.UBR;Edition=$version.EditionID;ProductType=[int]$os.ProductType;DomainRole=[int]$computer.DomainRole;DomainJoined=[bool]$computer.PartOfDomain;Domain=[string]$computer.Domain}
}
function Get-WelaChannelReadSelection {
    param([string[]]$Channels)
    $profile=Get-Content -LiteralPath (Join-Path $script:ScriptRoot 'config/native_channel_profile.json') -Raw -ErrorAction Stop|ConvertFrom-Json
    $allowed=@($profile.querySets.Baseline.channels.name)+@($profile.querySets.Suspect.channels.name)
    if(-not $Channels -or $Channels.Count -gt 8){throw 'Select between one and eight reviewed built-in channels.'}
    $seen=@{}
    foreach($channel in $Channels){
        if($channel -cnotin $allowed -or $seen.ContainsKey($channel)){throw 'Unknown, mis-cased or duplicate channel; only exact native WEF inventory names are accepted.'}
        $seen[$channel]=$true
        $channel
    }
}
function Get-WelaChannelReadFailure {
    param([Exception]$Exception)
    $current=$Exception;$code=$null;$absent=$false
    while($current){
        if($current -is [UnauthorizedAccessException]){$code=5;break}
        if($current.PSObject.Properties['ErrorCode']){$code=[int]$current.ErrorCode}
        if($current -is [ComponentModel.Win32Exception]){$code=$current.NativeErrorCode}
        if($current -is [Diagnostics.Eventing.Reader.EventLogNotFoundException]){$absent=$true}
        # Modern EventLogException stores Win32 codes in HRESULT; .NET Framework
        # does not reliably expose its private native code. Never parse localized text.
        if($current -is [Diagnostics.Eventing.Reader.EventLogException]){
            $hr=([long]$current.HResult -band 0xffffffffL)
            if(($hr -band 0xffff0000L) -eq 0x80070000L){$code=[int]($hr -band 0xffffL)}
        }
        $current=$current.InnerException
    }
    $state=if($code -eq 5){'Denied'}elseif($absent -or $code -in @(2,3,15007)){'Absent'}else{'Unknown'}
    [pscustomobject]@{Status=$state;NativeError=$code;Diagnostic=$Exception.Message}
}
function Read-WelaChannelLatest {
    param([string]$Channel)
    $reader=$null;$event=$null
    $result=[pscustomobject][ordered]@{Channel=$Channel;PathType='LogName';Session='Local';XPath='*';ReverseDirection=$true;MaximumEvents=1;ReadTimeoutMs=5000;StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;Status='Unknown';NativeError=$null;LogStatus=@();Event=$null;Diagnostic=''}
    try {
        $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($Channel,[Diagnostics.Eventing.Reader.PathType]::LogName,'*')
        $query.ReverseDirection=$true;$query.TolerateQueryErrors=$false
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query);$reader.BatchSize=1
        $event=$reader.ReadEvent([TimeSpan]::FromMilliseconds(5000))
        $result.LogStatus=@($reader.LogStatus|ForEach-Object{[pscustomobject]@{LogName=$_.LogName;StatusCode=$_.StatusCode}})
        if($result.LogStatus.Count -ne 1 -or $result.LogStatus[0].LogName -cne $Channel -or $result.LogStatus[0].StatusCode -ne 0){throw 'Query status is incomplete, mismatched or failed.'}
        if($null -eq $event){$result.Status='ReadAllowedEmpty'}else{
            if($event.LogName -cne $Channel -or $null -eq $event.RecordId -or $event.RecordId -le 0 -or -not $event.ProviderName -or $event.ProviderName.Length -gt 512 -or -not $event.MachineName -or $event.MachineName.Length -gt 255){throw 'Returned event provenance is incomplete or mismatches the selected local channel.'}
            # Only bounded System metadata is exported. Message, payload and raw XML remain unexported.
            $result.Event=[pscustomobject][ordered]@{Channel=$event.LogName;RecordId=[long]$event.RecordId;Provider=$event.ProviderName;EventId=[int]$event.Id;Version=$event.Version;Computer=$event.MachineName;TimeCreatedUtc=$(if($event.TimeCreated){$event.TimeCreated.ToUniversalTime().ToString('o')}else{$null})}
            $result.Status='EventObserved'
        }
    }catch{
        $failure=Get-WelaChannelReadFailure $_.Exception
        $result.Status=$failure.Status;$result.NativeError=$failure.NativeError;$result.Diagnostic=$failure.Diagnostic;$result.Event=$null
    }finally{if($event){$event.Dispose()};if($reader){$reader.Dispose()};$result.CompletedUtc=[DateTime]::UtcNow.ToString('o')}
    $result
}
function Invoke-WelaChannelRead {
    param([string[]]$Channels,[string]$OutputPath)
    $selected=@(Get-WelaChannelReadSelection $Channels)
    if(-not $OutputPath){throw 'channel-read requires a new ChannelReadOutputPath.'}
    $sources=Get-WelaChannelReadSources;$sourceKey=Get-WelaChannelReadKey $sources
    $hostState=Get-WelaChannelReadHost;$hostKey=Get-WelaChannelReadKey $hostState
    $before=Get-WelaChannelReader;$readerKey=Get-WelaChannelReadKey $before
    $output=New-WelaArrivalOutput -Path $OutputPath -SourcePath $script:ScriptRoot
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaNativeChannelRead';RecordedUtc=[DateTime]::UtcNow.ToString('o');ExitCode=1;Status='Unverified';Host=$hostState;ReaderBefore=$before;ReaderAfter=$null;Sources=$sources;Results=@();Diagnostic='';ReadyRuleCredit=0;ConfigurationChanges=0;Scope='Actual current primary-token local query access at observation time only';EventGeneration='Not tested';Forwarding='Not tested';OutputPath=$output}
    try {
        foreach($channel in $selected){
            if((Get-WelaChannelReadKey (Get-WelaChannelReader)) -cne $readerKey){throw 'Reader token changed before query.'}
            # Channel configuration may require rights the actual event query does not.
            $metadata=Get-WelaNativeChannel -Name $channel
            $query=Read-WelaChannelLatest $channel
            $readerAfter=Get-WelaChannelReader
            $row=[pscustomobject]@{Channel=$channel;ConfigurationObservation=$metadata;Query=$query;AccessVerified=$false;ReaderStable=$false}
            $report.Results+= $row
            if((Get-WelaChannelReadKey $readerAfter) -cne $readerKey){throw 'Reader token changed during query.'}
            $row.ReaderStable=$true
            $row.AccessVerified=$query.Status -in @('ReadAllowedEmpty','EventObserved')
        }
        $report.ReaderAfter=Get-WelaChannelReader
        if((Get-WelaChannelReadKey $report.ReaderAfter) -cne $readerKey -or (Get-WelaChannelReadKey (Get-WelaChannelReadHost)) -cne $hostKey -or (Get-WelaChannelReadKey (Get-WelaChannelReadSources)) -cne $sourceKey){throw 'Reader, host or implementation changed during observation.'}
        $report.Status='Completed'
        $report.ExitCode=if(@($report.Results|Where-Object{-not $_.AccessVerified}).Count){1}else{0}
    }catch{
        $report.Diagnostic=$_.Exception.Message
        foreach($row in $report.Results){$row.AccessVerified=$false}
    }
    $json=$report|ConvertTo-Json -Depth 20
    if([Text.Encoding]::UTF8.GetByteCount($json) -gt 1048576){throw 'Channel-read report exceeds the one MiB bound; no successful evidence was written.'}
    $null=Write-WelaArrivalArtifact $output 'result.json' $json
    $report
}
