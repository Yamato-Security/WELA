$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/NativeProviderPacks.ps1')
. (Join-Path $root 'scripts/DnsAnalytical.ps1')
$count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Throws($Code,$Pattern){$message='';try{& $Code|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Clone($Value){$Value|ConvertTo-Json -Depth 24|ConvertFrom-Json}
function Hash($Bytes){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([byte[]]$Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
$script:definition=Get-WelaDnsAnalyticalDefinition
Assert ($script:definition.Pack.mode -eq 'ManualOnly' -and $script:definition.Rules.Count -eq 3) 'Dedicated adapter preserves existing manual-only ordinary pack and three pinned rules.'
$script:sourceReader=(Get-Command Get-WelaDnsAnalyticalSources).ScriptBlock
function Get-WelaDnsAnalyticalDefinition {Clone $script:definition}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-dns-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
function Reset {
    $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N'));$script:scenario='';$script:nativeCalls=@();$script:trace=[Text.Encoding]::UTF8.GetBytes('original ETL fixture');$script:reads=0;$script:afterArchiveContextReads=0
    $script:state=[pscustomobject]@{Context=[pscustomobject]@{Key='actual-server-build-patch'};Channel='Microsoft-Windows-DNSServer/Analytical';Provider='Microsoft-Windows-DNSServer';ProviderGuid='eb79061a-a566-4698-9119-3ed2807060e7';ChannelType='Analytical';ServiceState='Running';Schema=[pscustomobject]@{Events=@([pscustomobject]@{Id=257;Version=0;TemplateSha256='pinned-template'})};IsEnabled=$false;MaximumSizeInBytes=[long]33554432;LogMode='Circular';SecurityDescriptor='original-ACL';LogFilePath='C:\fixture\DNS.etl';RegisteredLogFilePath='C:\fixture\DNS.etl'}
}
function Get-WelaDnsAnalyticalState {
    param($Definition)
    $script:reads++
    if($script:scenario -eq 'denied-state'){throw 'Denied native metadata'}
    if($script:scenario -eq 'final-drift' -and (Test-Path (Join-Path $script:backup '04-applied.json'))){$script:state.SecurityDescriptor='concurrent-ACL'}
    if(Test-Path (Join-Path $script:backup '03-archive.json')){$script:afterArchiveContextReads++}
    if($script:scenario -eq 'final-context-trace-race' -and $script:afterArchiveContextReads -eq 2){$script:trace=[Text.Encoding]::UTF8.GetBytes('changed during final context observation')}
    Clone $script:state
}
function Get-WelaDnsAnalyticalSources {
    $sources=@(& $script:sourceReader)
    if($script:scenario -eq 'source-race' -and (Test-Path (Join-Path $script:backup '01-before.json'))){$sources[0].Sha256='changed'}
    $sources
}
function Read-Host {
    if($script:scenario -eq 'prompt-race'){$script:state.MaximumSizeInBytes=67108864}
    if($script:scenario -eq 'declined'){return 'n'}
    'y'
}
function Copy-WelaDnsAnalyticalTrace {
    param([string]$Source,[string]$Destination,[long]$MaximumBytes)
    if($script:scenario -eq 'archive-denied'){throw 'Trace access denied; not empty'}
    if($Source -eq $script:state.LogFilePath){
        Assert (-not $script:state.IsEnabled) 'Source archive/verification occurs only while stopped.'
        $bytes=$script:trace
        if($null -eq $bytes){return [pscustomobject]@{State='ObservedAbsent';SourcePath=$Source;Identity=$null;Length=0;Sha256=$null;ArchivePath=$null;ArchivedSha256=$null}}
    }else{$bytes=[IO.File]::ReadAllBytes($Source)}
    if($bytes.Length -gt $MaximumBytes){throw 'Trace exceeds explicit cap'}
    $hash=Hash $bytes
    if($Destination){
        Assert (Test-Path (Join-Path $script:backup '01-before.json')) 'Durable before-state precedes archive.'
        [IO.File]::WriteAllBytes($Destination,$bytes)
        if($script:scenario -eq 'trace-race'){$script:trace=[Text.Encoding]::UTF8.GetBytes('changed ETL')}
        if($script:scenario -eq 'archive-tamper'){[IO.File]::WriteAllText($Destination,'tampered')}
        if($script:scenario -eq 'appeared-trace'){$script:trace=[Text.Encoding]::UTF8.GetBytes('new trace')}
    }
    [pscustomobject]@{State=$(if($Destination){'ArchivedBytes'}else{'ObservedBytes'});SourcePath=$Source;Identity='stable-file-id';Length=$bytes.Length;Sha256=$hash;ArchivePath=$Destination;ArchivedSha256=$(if($Destination){$hash}else{$null})}
}
$script:jsonWriter=(Get-Command Write-WelaDnsAnalyticalJson).ScriptBlock
function Write-WelaDnsAnalyticalJson {
    param($Path,$Value)
    if($script:scenario -eq 'journal-failure' -and (Split-Path $Path -Leaf) -eq '01-before.json'){throw 'Journal write failed'}
    & $script:jsonWriter $Path $Value
}
function Set-WelaDnsAnalyticalNative {
    param([string[]]$Arguments)
    $script:nativeCalls+=,(@($Arguments))
    Assert (Test-Path (Join-Path $script:backup '01-before.json')) 'Every channel mutation follows a durable before-state.'
    if($script:scenario -eq 'native-failure'){throw 'wevtutil failed exit5'}
    if($Arguments -contains '/e:true'){
        Assert (($Arguments -contains '/q:true') -and (Test-Path (Join-Path $script:backup '03-archive.json'))) 'Reset-capable enable has explicit quiet consent and persisted verified archive.'
        $script:state.IsEnabled=$true;$script:trace=[Text.Encoding]::UTF8.GetBytes('new ETL session')
    }
    if($Arguments -contains '/e:false'){$script:state.IsEnabled=$false}
    foreach($arg in $Arguments){if($arg -like '/ms:*'){$script:state.MaximumSizeInBytes=[long]$arg.Substring(4)};if($arg -eq '/rt:true'){$script:state.LogMode='Retain'};if($arg -eq '/rt:false'){$script:state.LogMode='Circular'}}
    if($script:scenario -eq 'write-drift'){$script:state.RegisteredLogFilePath='C:\changed\DNS.etl'}
}
function Configure {
    param([switch]$DryRun,[switch]$Auto)
    Invoke-WelaDnsAnalytical -Action Configure -State Enabled -AllowTraceReset -BackupPath $script:backup -DryRun:$DryRun -Auto:$Auto
}
try {
    $context=[pscustomobject]@{Role='MemberServer';Build=20348}
    $service=[pscustomobject]@{State='Running'}
    $schema=[pscustomobject]@{State='Observed';ChannelType='Analytical';ProviderGuid='eb79061a-a566-4698-9119-3ed2807060e7';Events=@([pscustomobject]@{Id=257;Version=0;Fields=@([pscustomobject]@{Name='QNAME';InType='win:UnicodeString'})})}
    Assert-WelaDnsAnalyticalCapability $script:definition $context $service $schema
    foreach($role in @('Client','Unknown')){$bad=Clone $context;$bad.Role=$role;Throws {Assert-WelaDnsAnalyticalCapability $script:definition $bad $service $schema} 'build/role'}
    $bad=Clone $context;$bad.Build=99999;Throws {Assert-WelaDnsAnalyticalCapability $script:definition $bad $service $schema} 'build/role'
    foreach($state in @('Stopped','Unknown','Not installed')){$bad=Clone $service;$bad.State=$state;Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $bad $schema} 'service'}
    foreach($value in @('Operational','Debug','Unknown')){$bad=Clone $schema;$bad.ChannelType=$value;Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'provider/schema'}
    $bad=Clone $schema;$bad.ProviderGuid=[guid]::Empty.ToString();Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'provider/schema'
    $bad=Clone $schema;$bad.Events=@();Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'event257'
    $bad=Clone $schema;$bad.Events[0].Fields[0].Name='QueryName';Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'QNAME'
    $bad=Clone $schema;$bad.Events[0].Fields[0].InType='win:UInt32';Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'QNAME'
    $bad=Clone $schema;$bad.Events+=Clone $bad.Events[0];$bad.Events[1].Version=1;$bad.Events[1].Fields=@();Throws {Assert-WelaDnsAnalyticalCapability $script:definition $context $service $bad} 'QNAME'
    Reset;$a=Invoke-WelaDnsAnalytical
    Assert ($a.Status -eq 'AlreadyCompliant' -and $a.ReadyRuleCredit -eq 0 -and $script:nativeCalls.Count -eq 0 -and -not(Test-Path $script:backup)) 'Default Audit reads actual state without archives, mutation or readiness credit.'
    $p=Invoke-WelaDnsAnalytical -Action Plan -State Enabled
    Assert ($p.Status -eq 'ChangeRequired' -and $p.RequiresTraceResetConsent) 'Plan exposes reset consent before writes.'
    $r=Configure -DryRun
    Assert ($r.Status -eq 'Skipped' -and -not(Test-Path $script:backup) -and $script:nativeCalls.Count -eq 0) 'DryRun makes no directories, archives or channel changes.'
    $r=Invoke-WelaDnsAnalytical -Action Configure -State Enabled -BackupPath $script:backup -Auto
    Assert ($r.ExitCode -eq 1 -and $r.Diagnostic -match 'AllowDnsTraceReset' -and $script:nativeCalls.Count -eq 0) 'Auto cannot bypass explicit trace-reset consent.'
    $r=Configure -Auto
    Assert ($r.Status -eq 'Applied' -and $r.After.IsEnabled -and $r.Archive.State -eq 'ArchivedBytes' -and $r.After.SecurityDescriptor -ceq 'original-ACL') 'Reviewed channel enable preserves ACL/path with real archive metadata.'
    Assert ([IO.File]::ReadAllText($r.Archive.ArchivePath) -ceq 'original ETL fixture') 'Archived original bytes survive trace reset.'
    $calls=$script:nativeCalls.Count;$again=Configure -Auto
    Assert ($again.Status -eq 'AlreadyCompliant' -and $script:nativeCalls.Count -eq $calls) 'Idempotent configure performs no stop/archive/reset.'
    Reset;$script:state.IsEnabled=$true;$script:state.MaximumSizeInBytes=67108864
    $r=Invoke-WelaDnsAnalytical -Action Configure -State Enabled -Retention Retain -AllowTraceReset -Auto -BackupPath $script:backup
    Assert ($r.Status -eq 'Applied' -and $r.After.MaximumSizeInBytes -eq 67108864 -and $r.After.LogMode -eq 'Retain' -and $script:nativeCalls[0] -contains '/e:false') 'Retention changes stop/archive first and preserve larger buffers.'
    Reset;$script:state.MaximumSizeInBytes=1048576
    $r=Invoke-WelaDnsAnalytical -Action Configure -State Enabled -MinimumBytes 1048577 -AllowTraceReset -Auto -BackupPath $script:backup
    Assert ($r.After.MaximumSizeInBytes -eq 1114112) 'Requested minimum rounds upward by native64KiB units.'
    Reset;$script:state.IsEnabled=$true
    $r=Invoke-WelaDnsAnalytical -Action Configure -State Disabled -AllowTraceReset -Auto -BackupPath $script:backup
    Assert ($r.Status -eq 'Applied' -and -not$r.After.IsEnabled -and $script:nativeCalls.Count -eq 1 -and $r.Archive.State -eq 'ArchivedBytes') 'Explicit disable archives without re-enabling or resizing.'
    Reset;$script:trace=$null;$r=Configure -Auto
    Assert ($r.Status -eq 'Applied' -and $r.Archive.State -eq 'ObservedAbsent' -and -not$r.Archive.Sha256 -and -not(Test-Path (Join-Path $script:backup 'trace-before.etl'))) 'Absent trace is typed native absence, never fabricated empty archive proof.'
    foreach($case in @('prompt-race','source-race','declined','journal-failure')){
        Reset;$script:scenario=$case;$r=Configure
        Assert ($script:nativeCalls.Count -eq 0 -and $r.Status -in @('Failed','Skipped')) "No channel mutation after $case."
    }
    foreach($case in @('archive-denied','trace-race','archive-tamper','final-context-trace-race')){
        Reset;$script:state.IsEnabled=$true;$script:state.MaximumSizeInBytes=1048576;$script:scenario=$case;$r=Configure -Auto
        Assert ($r.Status -eq 'Failed' -and $script:nativeCalls.Count -eq 1 -and -not$r.After.IsEnabled -and -not(Test-Path (Join-Path $script:backup '04-applied.json'))) "$case leaves stopped trace explicitly failed without resetting unarchived evidence."
    }
    foreach($case in @('native-failure','write-drift','final-drift','denied-state')){
        Reset;$script:scenario=$case;$r=Configure -Auto
        Assert ($r.Status -eq 'Failed' -and $r.ExitCode -eq 1) "$case cannot claim applied success."
    }
    Reset;$out=Join-Path $temp 'relative.json';Push-Location $temp
    try{$null=Invoke-WelaDnsAnalytical -ResultsPath 'relative.json'}finally{Pop-Location}
    Assert (Test-Path $out) 'Report relative path follows PowerShell location.'
    Throws {Invoke-WelaDnsAnalytical -ResultsPath $out} 'must be new'
    foreach($suffix in @('base.json:stream','bad*.json','bad?.json','bad[1].json',('bad'+[char]10+'.json'),'trailing.','trailing ')){
        Throws {Resolve-WelaDnsAnalyticalOutput (Join-Path $temp $suffix)} 'unsupported'
    }
    Throws {Invoke-WelaDnsAnalytical -Action Configure} 'explicit DNS state'
    Throws {Invoke-WelaDnsAnalytical -DryRun} 'require DNS Configure'
    $exe=(Get-Process -Id $PID).Path
    foreach($arguments in @(@('configure','-DnsAction','Audit'),@('dns-analytical','-Profile','wela-2.2.0'),@('dns-analytical','-DryRun'))){
        $ErrorActionPreference='Continue';try{$output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
        $plain=($output -join ' ') -replace '\x1b\[[0-9;]*[A-Za-z]','' -replace '[|\r\n]',' '
        Assert ($code -ne 0 -and $plain -match 'No\s+command\s+was\s+run') 'Public guard rejects unrelated/ignored options before any command.'
    }
    Write-Host "PASS: $script:count DNS analytical mocked assertions. No native channel, feature, service, policy or DNS query mutations."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
