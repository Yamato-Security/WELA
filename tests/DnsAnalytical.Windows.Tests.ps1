param([switch]$AllowDisposableDns,[ValidateSet('powershell','pwsh')][string]$TestEngine='powershell')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableDns -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit DNS mutation opt-in on a disposable GitHub-hosted Windows runner is required.'}
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $root 'modules/NativeProviders.psm1') -Force
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/ControlApplicability.ps1')
. (Join-Path $root 'scripts/NativeProviderPacks.ps1')
. (Join-Path $root 'scripts/DnsAnalytical.ps1')
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Throws($Code,$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
$hostOs=Get-CimInstance Win32_OperatingSystem;$hostComputer=Get-CimInstance Win32_ComputerSystem
if($hostOs.ProductType -ne 3 -or [int]$hostOs.BuildNumber -notin @(20348,26100) -or $hostComputer.PartOfDomain -or $hostComputer.DomainRole -ne 2 -or (Get-WindowsFeature DNS).Installed){throw 'This disposable test requires an unjoined Server2022/2025 with no pre-existing DNS role.'}
$engine=(Get-Command $TestEngine -ErrorAction Stop).Source
$nonce=[guid]::NewGuid().ToString('N');$zone='wela-'+$nonce+'.test';$query='probe.'+$zone;$zoneFile=$zone+'.dns'
$private=New-WelaDnsAnalyticalBackup (Join-Path $env:TEMP ('wela-dns-native-'+$nonce))
$beforeFeatures=@(Get-WindowsFeature|Where-Object Installed|ForEach-Object Name);$beforePolicies=Get-WelaEffectiveAuditPolicy
$installed=$false;$zoneCreated=$false;$original=$null;$passed=$false
function Invoke-Cli {
    param([string[]]$Arguments,[int]$Expected=0)
    $ErrorActionPreference='Continue'
    try{$text=@(& $engine -NoProfile -File (Join-Path $root 'WELA.ps1') @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
    $text|ForEach-Object{Write-Host $_};$global:LASTEXITCODE=0
    Assert ($code -eq $Expected) "Public DNS CLI exit $code, expected $Expected."
}
try {
    # Real file-handle/archive behavior uses only owned temporary bytes.
    $source=Join-Path $private 'stream-source.etl';$destination=Join-Path $private 'stream-archive.etl'
    $bytes=New-Object byte[] 131073;for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte]($i%251)};[IO.File]::WriteAllBytes($source,$bytes)
    $archive=Copy-WelaDnsAnalyticalTrace $source $destination 1048576
    Assert ($archive.State -eq 'ArchivedBytes' -and $archive.Length -eq 131073 -and $archive.Sha256 -ceq (Get-FileHash $source).Hash.ToLowerInvariant() -and $archive.Sha256 -ceq $archive.ArchivedSha256) 'Streaming native archive retains exact bytes and hashes.'
    Assert-WelaDnsAnalyticalArchive $archive 1048576
    $observed=Copy-WelaDnsAnalyticalTrace -Source $source -MaximumBytes 1048576
    Assert ($observed.State -eq 'ObservedBytes' -and $observed.Sha256 -ceq $archive.Sha256 -and -not$observed.ArchivePath) 'Native read-only overload preserves bytes without a destination or null-string coercion.'
    foreach($alias in @(($source+':stream'),($source+'.'),($source+' '),(Join-Path $private 'bad?.etl'))){Throws {Resolve-WelaDnsAnalyticalOutput $alias} 'unsupported'}
    Throws {Copy-WelaDnsAnalyticalTrace $source $destination 1048576} 'already exists|exist'
    $lock=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{Throws {Copy-WelaDnsAnalyticalTrace -Source $source -MaximumBytes 1048576} 'absence was not established|another process'}finally{$lock.Dispose()}
    $junctionTarget=Join-Path $private 'junction-target';$junction=Join-Path $private 'junction'
    $null=New-Item -ItemType Directory -Path $junctionTarget
    [IO.File]::WriteAllText((Join-Path $junctionTarget 'trace.etl'),'owned link fixture')
    $null=New-Item -ItemType Junction -Path $junction -Value $junctionTarget
    try{Throws {Copy-WelaDnsAnalyticalTrace -Source (Join-Path $junction 'trace.etl') -MaximumBytes 1048576} 'reparse'}finally{(Get-Item -LiteralPath $junction -Force).Delete()}
    $absent=Copy-WelaDnsAnalyticalTrace -Source (Join-Path $private 'absent.etl') -MaximumBytes 1048576
    Assert ($absent.State -eq 'ObservedAbsent' -and -not $absent.Sha256) 'Native FILE_NOT_FOUND is typed absence without fabricated archive/hash.'
    $empty=Join-Path $private 'empty.etl';[IO.File]::WriteAllBytes($empty,[byte[]]@())
    Throws {Copy-WelaDnsAnalyticalTrace -Source $empty -MaximumBytes 1048576} 'empty archive'
    $large=Join-Path $private 'large.etl';$s=[IO.File]::Create($large);try{$s.SetLength(1048577)}finally{$s.Dispose()}
    Throws {Copy-WelaDnsAnalyticalTrace -Source $large -MaximumBytes 1048576} 'cap'
    Throws {Copy-WelaDnsAnalyticalTrace -Source (Join-Path $private 'missing-parent\trace.etl') -MaximumBytes 1048576} 'find|exist'
    # The DNS role and zone belong exclusively to this disposable runner.
    $installed=$true;$feature=Install-WindowsFeature DNS -IncludeManagementTools -ErrorAction Stop
    if(-not $feature.Success -or [string]$feature.RestartNeeded -ne 'No'){throw 'DNS role installation failed or needs a restart; no native acceptance claim.'}
    Start-Service DNS -ErrorAction Stop
    $definition=Get-WelaDnsAnalyticalDefinition;$original=Get-WelaDnsAnalyticalState $definition
    Write-WelaDnsAnalyticalJson (Join-Path $private 'original-channel.json') $original
    $zoneCreated=$true
    Add-DnsServerPrimaryZone -Name $zone -ZoneFile $zoneFile -DynamicUpdate None -ErrorAction Stop
    Add-DnsServerResourceRecordA -ZoneName $zone -Name probe -IPv4Address '127.0.0.42' -TimeToLive ([TimeSpan]::FromMinutes(1)) -ErrorAction Stop|Out-Null
    $configuredPath=Join-Path $private 'configured.json'
    Invoke-Cli @('dns-analytical','-DnsAction','Configure','-DnsState','Enabled','-DnsRetention','Retain','-AllowDnsTraceReset','-Auto','-BackupPath',(Join-Path $private 'enable-journal'),'-ResultsPath',$configuredPath)
    $configured=Get-Content $configuredPath -Raw -Encoding UTF8|ConvertFrom-Json
    Assert ($configured.Status -eq 'Applied' -and $configured.After.IsEnabled -and $configured.After.LogMode -eq 'Retain' -and $configured.ReadyRuleCredit -eq 0) 'Actual public configure enables only the reviewed analytical channel without readiness credit.'
    Assert ($configured.After.SecurityDescriptor -ceq $original.SecurityDescriptor -and $configured.After.LogFilePath -ceq $original.LogFilePath) 'Native transition preserves ACL and registered local trace path.'
    $repeatPath=Join-Path $private 'repeat.json'
    Invoke-Cli @('dns-analytical','-DnsAction','Configure','-DnsState','Enabled','-DnsRetention','Retain','-AllowDnsTraceReset','-Auto','-BackupPath',(Join-Path $private 'unused-repeat-journal'),'-ResultsPath',$repeatPath)
    $repeat=Get-Content $repeatPath -Raw -Encoding UTF8|ConvertFrom-Json
    Assert ($repeat.Status -eq 'AlreadyCompliant' -and -not(Test-Path (Join-Path $private 'unused-repeat-journal'))) 'Actual repeat neither restarts nor creates misleading recovery evidence.'
    $started=[DateTime]::UtcNow
    $answers=@(Resolve-DnsName -Name $query -Type A -Server '127.0.0.1' -DnsOnly -NoHostsFile -ErrorAction Stop)
    Assert (@($answers|Where-Object IPAddress -eq '127.0.0.42').Count -eq 1) 'Unique authoritative .test query is resolved entirely through loopback.'
    # Stop and archive through the public lifecycle before reading the ETL.
    $disabledPath=Join-Path $private 'disabled.json'
    Invoke-Cli @('dns-analytical','-DnsAction','Configure','-DnsState','Disabled','-AllowDnsTraceReset','-Auto','-BackupPath',(Join-Path $private 'disable-journal'),'-ResultsPath',$disabledPath)
    $disabled=Get-Content $disabledPath -Raw -Encoding UTF8|ConvertFrom-Json
    Assert ($disabled.Status -eq 'Applied' -and -not$disabled.After.IsEnabled -and $disabled.Archive.State -eq 'ArchivedBytes') 'Native disable preserves stopped trace in a hash-verified archive.'
    Assert ($disabled.Archive.SourcePath -ceq $original.LogFilePath -and $disabled.Before.Channel -ceq $definition.Pack.channel -and $disabled.After.Channel -ceq $definition.Pack.channel) 'ETL bytes came from the exact registered analytical trace path and preserved channel state.'
    $events=@(Get-WinEvent -Path $disabled.Archive.ArchivePath -Oldest -MaxEvents 4096 -ErrorAction Stop)
    Assert ($events.Count -lt 4096) 'Archived native event read stays below its explicit completeness cap.'
    $candidateXml=New-Object 'System.Collections.Generic.List[string]'
    $eventSummary=New-Object 'System.Collections.Generic.List[string]'
    $matches=@(foreach($event in $events){
        try{
            $rawXml=$event.ToXml();$xml=[xml]$rawXml;$data=@{};foreach($node in $xml.Event.EventData.Data){$data[[string]$node.Name]=[string]$node.'#text'}
            if($eventSummary.Count -lt 20){$eventSummary.Add("Event $($event.Id), provider $($event.ProviderName), channel '$($xml.Event.System.Channel)', QNAME '$($data.QNAME)', time $($event.TimeCreated.ToUniversalTime().ToString('o'))")}
            if($event.Id -eq 257 -and $candidateXml.Count -lt 8){$candidateXml.Add($rawXml)}
            # Raw ETL rendering can leave System.Channel empty. Do not rewrite it: bind
            # provenance to the verified registered trace path above and exact native manifest link.
            $manifest=@($disabled.Before.Schema.Events|Where-Object {$_.Id -eq $event.Id -and $_.Version -eq $event.Version -and $_.Channel -ceq $definition.Pack.channel})
            $channel=[string]$xml.Event.System.Channel
            if($event.Id -eq 257 -and $event.ProviderName -ceq 'Microsoft-Windows-DNSServer' -and [string]$xml.Event.System.Provider.Guid -ieq '{eb79061a-a566-4698-9119-3ed2807060e7}' -and $manifest.Count -eq 1 -and ($channel -ceq '' -or $channel -ceq $definition.Pack.channel) -and [string]$xml.Event.System.Computer -ieq [Environment]::MachineName -and $event.TimeCreated.ToUniversalTime() -ge $started -and $event.TimeCreated.ToUniversalTime() -le [DateTime]::UtcNow -and [string]$data.QNAME.TrimEnd('.') -ieq $query -and $data.InterfaceIP -ceq '127.0.0.1' -and $data.Destination -ceq '127.0.0.1' -and $data.QTYPE -ceq '1' -and $data.RCODE -ceq '0' -and $data.AA -ceq '1'){$rawXml}
        }finally{if($event -is [IDisposable]){$event.Dispose()}}
    })
    if($matches.Count -ne 1){Write-Host "Expected one event257 for $query since $($started.ToString('o')); matched $($matches.Count) from $($events.Count) events.";$eventSummary|ForEach-Object{Write-Host $_};$candidateXml|ForEach-Object{Write-Host $_};throw 'Exact bounded native DNS257/QNAME evidence was not established.'}
    [IO.File]::WriteAllText((Join-Path $private 'event257.xml'),$matches[0],[Text.UTF8Encoding]::new($false));Write-Host $matches[0]
    $proof=[pscustomobject]@{Kind='WelaDnsAnalyticalNativeProbe';Engine=$TestEngine;Computer=[Environment]::MachineName;Query=$query;StartedUtc=$started.ToString('o');VerifiedUtc=[DateTime]::UtcNow.ToString('o');EventId=257;XmlChannel=[string]([xml]$matches[0]).Event.System.Channel;RegisteredChannel=$definition.Pack.channel;RegisteredTracePath=$original.LogFilePath;ChannelEvidence='Verified registered ETL path and provider event/version manifest link; raw XML channel is retained without normalization.';ArchiveSha256=$disabled.Archive.Sha256;ReadyRuleCredit=0}
    Write-WelaDnsAnalyticalJson (Join-Path $private 'event257-proof.json') $proof
    Write-Host ($proof|ConvertTo-Json -Depth 6)
    Assert ((Get-FileHash $disabled.Archive.ArchivePath).Hash.ToLowerInvariant() -ceq $disabled.Archive.Sha256) 'Collected native ETL retains the recorded archive hash.'
    $passed=$true
    Write-Host "PASS: $script:count DNS native assertions through $TestEngine; exact257 XML observed, no external DNS query or backend/readiness claim."
}catch{Write-Host ('DNS native test failure before cleanup: '+($_|Out-String));Write-Host $_.ScriptStackTrace;throw}
finally {
    $errors=@()
    if($original){try{
        $current=Get-WelaDnsAnalyticalState $definition
        # Fixture cleanup is explicit, confined to the DNS role created above.
        if($current.IsEnabled){Set-WelaDnsAnalyticalNative @('sl',$current.Channel,'/e:false')}
        $preserved=Copy-WelaDnsAnalyticalTrace -Source $current.LogFilePath -Destination (Join-Path $private 'cleanup-trace.etl') -MaximumBytes 1073741824
        Write-WelaDnsAnalyticalJson (Join-Path $private 'cleanup-archive.json') $preserved
        Assert-WelaDnsAnalyticalArchive $preserved 1073741824
        $args=@('sl',$original.Channel,('/ms:'+[string]$original.MaximumSizeInBytes),('/rt:'+([string]($original.LogMode -eq 'Retain')).ToLowerInvariant()),('/e:'+([string]$original.IsEnabled).ToLowerInvariant()),'/q:true')
        Set-WelaDnsAnalyticalNative $args
        if((Get-WelaDnsAnalyticalStateKey (Get-WelaDnsAnalyticalState $definition)) -cne (Get-WelaDnsAnalyticalStateKey $original)){throw 'Exact DNS channel configuration restoration differs.'}
    }catch{$errors+=$_.Exception.Message}}
    if($zoneCreated){try{
        $owned=Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue
        if($owned){if($owned.IsDsIntegrated -or $owned.ZoneType -ne 'Primary'){throw 'Owned DNS zone identity changed; cleanup refused.'};Remove-DnsServerZone -Name $zone -Force -ErrorAction Stop}
        if(Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue){throw 'Owned test zone remains.'}
        $file=Join-Path $env:SystemRoot ('System32\dns\'+$zoneFile);if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -ErrorAction Stop}
    }catch{$errors+=$_.Exception.Message}}
    try{$afterPolicies=Get-WelaEffectiveAuditPolicy;foreach($guid in $beforePolicies.Keys){if($afterPolicies[$guid] -ne $beforePolicies[$guid]){throw 'Native audit policy unexpectedly changed.'}}}catch{$errors+=$_.Exception.Message}
    $removal=[pscustomobject]@{ChannelAndZoneRestored=($errors.Count -eq 0);Attempted=$false;Features=@();Success=$null;RestartNeeded=$null;Boundary='Feature removal can await disposal of this GitHub-hosted VM; no production restart or complete live feature-restoration claim.'}
    if($installed -and $errors.Count -eq 0){try{
        $added=@(Get-WindowsFeature|Where-Object{$_.Installed -and $_.Name -notin $beforeFeatures -and $_.Name -in @('DNS','RSAT-DNS-Server')}|ForEach-Object Name)
        if($added.Count){$removal.Attempted=$true;$removal.Features=$added;$removed=Uninstall-WindowsFeature -Name $added -ErrorAction Stop;$removal.Success=[bool]$removed.Success;$removal.RestartNeeded=[string]$removed.RestartNeeded;if(-not $removed.Success -or $removal.RestartNeeded -notin @('No','Yes')){throw 'Created DNS feature removal failed or restart status is unknown.'}}
    }catch{$errors+=$_.Exception.Message}}
    Write-WelaDnsAnalyticalJson (Join-Path $private 'feature-removal.json') $removal;$removal|ConvertTo-Json -Depth 5|Write-Host
    if($errors.Count){throw "Disposable DNS cleanup failed; receipts retained at $private : $($errors -join '; ')"}
    if($passed){Remove-Item -LiteralPath $private -Recurse -Force}
}
$global:LASTEXITCODE=0
Write-Host 'PASS: exact native channel configuration and audit state restored; owned DNS zone/records removed. Feature removal/disposal boundary recorded separately.'
