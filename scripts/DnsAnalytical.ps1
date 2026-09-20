# Dedicated DNS analytical lifecycle. Ordinary channel setters remain restricted.
function Get-WelaDnsAnalyticalSources {
    foreach($path in @('config/native_provider_packs.json','config/security_rules.json','scripts/NativeProviderPacks.ps1','scripts/Configuration.ps1','scripts/ControlApplicability.ps1','modules/AuditProfiles.psm1','modules/NativeProviders.psm1','scripts/DnsAnalytical.ps1','scripts/DnsAnalyticalArchive.cs')) {
        [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "../$path") -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
    foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../config/provider_rule_sources') -Filter '*.yml' -File | Sort-Object Name)){
        [pscustomobject]@{Path=('config/provider_rule_sources/'+$file.Name);Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
}
function Get-WelaDnsAnalyticalDefinition {
    $sources=@(Get-WelaDnsAnalyticalSources)
    $catalog=Get-WelaProviderPackCatalog
    $pack=@($catalog.packs|Where-Object id -ceq 'dns-server-analytical')
    if($pack.Count -ne 1 -or $pack[0].provider -cne 'Microsoft-Windows-DNSServer' -or $pack[0].channel -cne 'Microsoft-Windows-DNSServer/Analytical' -or $pack[0].requiredService -cne 'DNS'){throw 'Reviewed DNS analytical catalog identity differs.'}
    $definition=[pscustomobject]@{Id='dns-server-analytical';CatalogId=$catalog.id;Pack=$pack[0];Builds=$catalog.buildFamilies.Server;Sources=$sources;RuleCommit=$catalog.ruleCommit;Rules=@($catalog.ruleReviews|Where-Object {$pack[0].ruleIds -contains $_.id})}
    Assert-WelaDnsAnalyticalSources $definition
    $definition
}
function Assert-WelaDnsAnalyticalSources {
    param($Definition)
    $actual=@(Get-WelaDnsAnalyticalSources)
    if($actual.Count -ne $Definition.Sources.Count){throw 'DNS source inventory changed.'}
    for($i=0;$i -lt $actual.Count;$i++){if($actual[$i].Path -cne $Definition.Sources[$i].Path -or $actual[$i].Sha256 -cne $Definition.Sources[$i].Sha256){throw 'Reviewed DNS sources changed; no further writes permitted.'}}
}
function Get-WelaDnsAnalyticalContext {
    $role=Get-WelaHostContext;$detail=Get-WelaDefaultContext
    if(-not(Test-WelaDefaultContextComplete $detail) -or $role.Build -ne $detail.Build){throw 'Complete consistent actual Windows context is required.'}
    $valid=switch($role.Role){MemberServer {$detail.ProductType -eq 3 -and $detail.DomainRole -in @(2,3)} DomainController {$detail.ProductType -eq 2 -and $detail.DomainRole -in @(4,5)} ADCS {$detail.ProductType -eq 3 -and $detail.DomainRole -in @(2,3) -and $detail.InstalledRoles -contains 'ADCS-Cert-Authority'} default {$false}}
    if(-not $valid){throw 'DNS analytical configuration requires a supported actual server role.'}
    [pscustomobject]@{Computer=[Environment]::MachineName;Role=$role.Role;Build=$role.Build;Detail=$detail;Key=([Environment]::MachineName+'|'+$role.Role+'|'+(Get-WelaDefaultContextKey $detail))}
}
function Assert-WelaDnsAnalyticalCapability {
    param($Definition,$Context,$Service,$Schema)
    if($context.Build -notin $Definition.Builds -or $context.Role -notin $Definition.Pack.roles){throw 'Server build/role is outside the reviewed provider profile.'}
    if($service.State -ne 'Running'){throw "DNS service is not running or observable ($($service.State)); no feature/service is installed or started."}
    if($schema.State -ne 'Observed' -or $schema.ChannelType -ne 'Analytical' -or $schema.ProviderGuid -ine 'eb79061a-a566-4698-9119-3ed2807060e7'){throw "Exact DNS analytical provider/schema is not established. $($schema.Diagnostic)"}
    $events=@($schema.Events|Where-Object Id -eq 257)
    if(-not $events.Count){throw 'Native DNS event257 is absent from the exact analytical channel.'}
    foreach($event in $events){$fields=@($event.Fields|Where-Object Name -ceq 'QNAME');if($fields.Count -ne 1 -or $fields[0].InType -notin @('win:UnicodeString','win:AnsiString')){throw 'Native event257 lacks its exact QNAME string schema.'}}
}
function Get-WelaDnsAnalyticalState {
    param($Definition)
    if($env:OS -ne 'Windows_NT' -or -not[Environment]::Is64BitProcess){throw 'DNS analytical operations require native 64-bit Windows.'}
    $context=Get-WelaDnsAnalyticalContext
    $service=Get-WelaNativeService DNS
    $schema=Get-WelaProviderPackSchema $Definition.Pack
    Assert-WelaDnsAnalyticalCapability $Definition $context $service $schema
    $logs=@()
    try {
        $logs=@(Get-WinEvent -ListLog $Definition.Pack.channel -ErrorAction Stop|Where-Object LogName -ceq $Definition.Pack.channel)
        if($logs.Count -ne 1){throw 'Exact DNS analytical channel registration was not returned.'}
        $log=$logs[0]
        if($log.IsEnabled -isnot [bool] -or $log.MaximumSizeInBytes -lt 1048576 -or [string]$log.LogMode -notin @('Circular','Retain') -or -not $log.SecurityDescriptor -or -not $log.LogFilePath){throw 'DNS channel enable/size/retention/ACL/path metadata is unknown or unsupported.'}
        $path=[Environment]::ExpandEnvironmentVariables([string]$log.LogFilePath)
        if($path -notmatch '^[A-Za-z]:\\' -or $path -match '[*?<>|]|[ .](\\|$)' -or $path -match '%[^%]+%' -or $path.Substring(2).Contains(':') -or [IO.Path]::GetFullPath($path) -ine $path){throw 'DNS trace path must be an unambiguous canonical local drive path.'}
        if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($path))).DriveType -ne [IO.DriveType]::Fixed){throw 'DNS trace must reside on a local fixed drive.'}
        [pscustomobject]@{Context=$context;Channel=$Definition.Pack.channel;Provider=$schema.Provider;ProviderGuid=$schema.ProviderGuid;ChannelType=$schema.ChannelType;ServiceState=$service.State;Schema=$schema;IsEnabled=[bool]$log.IsEnabled;MaximumSizeInBytes=[long]$log.MaximumSizeInBytes;LogMode=[string]$log.LogMode;SecurityDescriptor=[string]$log.SecurityDescriptor;LogFilePath=$path;RegisteredLogFilePath=[string]$log.LogFilePath}
    } finally {foreach($log in $logs){if($log -is [IDisposable]){$log.Dispose()}}}
}
function Get-WelaDnsAnalyticalStateKey {
    param($State)
    $parts=@($State.Context.Key,$State.Channel,$State.Provider,$State.ProviderGuid,$State.ChannelType,$State.ServiceState,[string]$State.IsEnabled,[string]$State.MaximumSizeInBytes,$State.LogMode,$State.SecurityDescriptor,$State.LogFilePath,$State.RegisteredLogFilePath)
    foreach($event in @($State.Schema.Events|Sort-Object Id,Version)){$parts+=@([string]$event.Id,[string]$event.Version,$event.TemplateSha256)}
    ($parts|ForEach-Object {[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_))}) -join '|'
}
function Assert-WelaDnsAnalyticalCurrent {
    param($Definition,$Expected)
    Assert-WelaDnsAnalyticalSources $Definition
    $current=Get-WelaDnsAnalyticalState $Definition
    if((Get-WelaDnsAnalyticalStateKey $current) -cne (Get-WelaDnsAnalyticalStateKey $Expected)){throw 'DNS role/schema/channel state changed; no further transition is authorized.'}
    $current
}
function Initialize-WelaDnsTraceArchive {
    if($env:OS -ne 'Windows_NT'){throw 'Native trace archives require Windows.'}
    $path=Join-Path $PSScriptRoot 'DnsAnalyticalArchive.cs';$hash=(Get-FileHash $path -Algorithm SHA256).Hash
    if(-not('Wela.DnsAnalytical.TraceArchive' -as [type])){Add-Type -Path $path -ErrorAction Stop;$script:WelaDnsArchiveSourceHash=$hash}
    if($script:WelaDnsArchiveSourceHash -cne $hash){throw 'Loaded native archive implementation differs from its current source.'}
}
function Copy-WelaDnsAnalyticalTrace {
    param([string]$Source,[string]$Destination,[long]$MaximumBytes)
    Initialize-WelaDnsTraceArchive
    # Separate native entry point avoids PowerShell coercing a null string to empty.
    if($Destination){[Wela.DnsAnalytical.TraceArchive]::Read($Source,$Destination,$MaximumBytes)}
    else{[Wela.DnsAnalytical.TraceArchive]::Inspect($Source,$MaximumBytes)}
}
function Assert-WelaDnsAnalyticalArchive {
    param($Archive,[long]$MaximumBytes)
    $fresh=Copy-WelaDnsAnalyticalTrace -Source $Archive.SourcePath -MaximumBytes $MaximumBytes
    if($Archive.State -eq 'ObservedAbsent') {if($fresh.State -ne 'ObservedAbsent'){throw 'A trace appeared after observed absence; archive it before reset.'};return}
    if($Archive.State -ne 'ArchivedBytes' -or $fresh.State -ne 'ObservedBytes' -or $fresh.Identity -cne $Archive.Identity -or $fresh.Length -ne $Archive.Length -or $fresh.Sha256 -cne $Archive.Sha256){throw 'Source trace changed after its verified archive.'}
    $saved=Copy-WelaDnsAnalyticalTrace -Source $Archive.ArchivePath -MaximumBytes $MaximumBytes
    if($saved.State -ne 'ObservedBytes' -or $saved.Length -ne $Archive.Length -or $saved.Sha256 -cne $Archive.Sha256){throw 'Recovery trace archive is no longer verified.'}
}
function Resolve-WelaDnsAnalyticalOutput {
    param([string]$Path)
    if($Path -match '[\x00-\x1f*?<>|"\[\]]' -or $Path -match '(?<!^[A-Za-z]):' -or @($Path -split '[\\/]'|Where-Object {$_ -notin @('.','..') -and $_ -match '[ .]$'}).Count){throw 'DNS artifact path contains unsupported stream, wildcard, control or trailing-dot/space syntax.'}
    $provider=$null;$drive=$null;$full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if($provider.Name -ne 'FileSystem'){throw 'DNS recovery/report path must use the FileSystem provider.'}
    $full=[IO.Path]::GetFullPath($full)
    if($env:OS -eq 'Windows_NT'){
        if($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')){throw 'DNS artifacts require a local fixed drive path, not a network share or alternate stream.'}
        if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed){throw 'DNS artifacts require a local fixed drive.'}
    }
    if(Test-Path -LiteralPath $full){throw 'DNS recovery/report output must be new.'}
    $parent=Get-Item -LiteralPath (Split-Path $full -Parent) -ErrorAction Stop
    if(-not $parent.PSIsContainer){throw 'DNS output parent must be an existing directory.'}
    while($parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'DNS output parents must not be reparse points.'};$parent=$parent.Parent}
    $full
}
function New-WelaDnsAnalyticalBackup {
    param([string]$Path)
    $full=Resolve-WelaDnsAnalyticalOutput $Path
    $null=New-Item -ItemType Directory -Path $full -ErrorAction Stop
    if($env:OS -eq 'Windows_NT') {
        $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
        Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    }
    $full
}
function Write-WelaDnsAnalyticalJson {
    param([string]$Path,$Value)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24)+[Environment]::NewLine)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Set-WelaDnsAnalyticalNative {
    param([string[]]$Arguments)
    $null=Invoke-WelaNative -FilePath wevtutil.exe -Arguments $Arguments
}
function Invoke-WelaDnsAnalytical {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[ValidateSet('Enabled','Disabled')][string]$State,
        [ValidateSet('Preserve','Circular','Retain')][string]$Retention='Preserve',
        [ValidateRange(1048576,1073741824)][long]$MinimumBytes=33554432,
        [ValidateRange(1048576,4294967296)][long]$ArchiveMaximumBytes=1073741824,
        [switch]$AllowTraceReset,[switch]$Auto,[switch]$DryRun,[string]$BackupPath,[string]$ResultsPath)
    if($Action -eq 'Configure' -and -not $State){throw 'Configure requires an explicit DNS state Enabled or Disabled.'}
    if($Action -ne 'Configure' -and ($AllowTraceReset -or $Auto -or $DryRun -or $BackupPath)){throw 'Reset consent, Auto, DryRun and BackupPath require DNS Configure.'}
    if($Action -eq 'Audit' -and ($State -or $Retention -ne 'Preserve')){throw 'Requested changes require Plan or Configure.'}
    $output=$null;if($ResultsPath){$output=Resolve-WelaDnsAnalyticalOutput $ResultsPath}
    $report=[pscustomobject]@{SchemaVersion=1;Kind='WelaDnsAnalyticalLifecycle';Action=$Action;Status='Unknown';ExitCode=0;CapturedUtc=[DateTime]::UtcNow.ToString('o');Before=$null;Desired=$null;After=$null;Definition=$null;Archive=$null;BackupPath=$null;Diagnostic='';RequiresTraceResetConsent=$false;DryRun=[bool]$DryRun;GenerationReadiness='Unverified';ReadyRuleCredit=0;Limitations=@('Raw stopped ETL archival verifies bytes, not retention completeness.','Circular direct-channel query errors do not imply logging is disabled.','Rule/native channel aliases and backend execution are unverified.','No DNS queries, zones, services, features or audit policies are created/configured by this command.')}
    try {
        $definition=Get-WelaDnsAnalyticalDefinition;$report.Definition=$definition
        $before=Get-WelaDnsAnalyticalState $definition;$report.Before=$before
        Assert-WelaDnsAnalyticalSources $definition
        $desired=($before|ConvertTo-Json -Depth 20|ConvertFrom-Json)
        if($State){$desired.IsEnabled=$State -eq 'Enabled'}
        if($State -eq 'Enabled'){$rounded=[long]([math]::Ceiling($MinimumBytes/65536.0)*65536);$desired.MaximumSizeInBytes=[math]::Max([long]$before.MaximumSizeInBytes,$rounded)}
        if($Retention -ne 'Preserve'){$desired.LogMode=$Retention}
        $report.Desired=$desired
        $change=(Get-WelaDnsAnalyticalStateKey $before) -cne (Get-WelaDnsAnalyticalStateKey $desired)
        $report.RequiresTraceResetConsent=$change
        $report.Status=if($change){'ChangeRequired'}else{'AlreadyCompliant'}
        if($Action -eq 'Configure' -and $change) {
            if($DryRun){$report.Status='Skipped';$report.Diagnostic='Dry run: no channel transition, archive or recovery directory.'}
            elseif(-not $AllowTraceReset){throw 'Explicit -AllowDnsTraceReset is required: stopping creates a collection gap; enable/resize/retention changes can reset existing trace contents.'}
            elseif(-not $Auto -and (Read-Host 'Archive the stopped DNS trace and apply this explicitly selected transition? (y/N)') -cnotin @('y','Y')){$report.Status='Skipped';$report.Diagnostic='Declined.'}
            else {
                if(-not $BackupPath){throw 'An explicit new BackupPath is required before any DNS channel transition.'}
                $backup=New-WelaDnsAnalyticalBackup $BackupPath;$report.BackupPath=$backup
                $current=Assert-WelaDnsAnalyticalCurrent $definition $before
                Write-WelaDnsAnalyticalJson (Join-Path $backup '01-before.json') $report
                $null=Assert-WelaDnsAnalyticalCurrent $definition $current
                if($current.IsEnabled){
                    Set-WelaDnsAnalyticalNative @('sl',$current.Channel,'/e:false')
                    $stopped=($current|ConvertTo-Json -Depth 20|ConvertFrom-Json);$stopped.IsEnabled=$false
                    $current=Assert-WelaDnsAnalyticalCurrent $definition $stopped
                }
                Write-WelaDnsAnalyticalJson (Join-Path $backup '02-stopped.json') $current
                $report.Archive=Copy-WelaDnsAnalyticalTrace -Source $current.LogFilePath -Destination (Join-Path $backup 'trace-before.etl') -MaximumBytes $ArchiveMaximumBytes
                if($report.Archive.State -notin @('ObservedAbsent','ArchivedBytes')){throw 'No verified stopped trace archive or explicit native absence was established.'}
                Write-WelaDnsAnalyticalJson (Join-Path $backup '03-archive.json') $report.Archive
                $null=Assert-WelaDnsAnalyticalCurrent $definition $current
                Assert-WelaDnsAnalyticalArchive $report.Archive $ArchiveMaximumBytes
                $arguments=@('sl',$current.Channel)
                if($desired.MaximumSizeInBytes -ne $current.MaximumSizeInBytes){$arguments+='/ms:'+([string]$desired.MaximumSizeInBytes)}
                if($desired.LogMode -ne $current.LogMode){$arguments+='/rt:'+([string]($desired.LogMode -eq 'Retain')).ToLowerInvariant()}
                if($desired.IsEnabled){$arguments+=@('/e:true','/q:true')}
                $null=Assert-WelaDnsAnalyticalCurrent $definition $current
                if($arguments.Count -gt 2){
                    Assert-WelaDnsAnalyticalArchive $report.Archive $ArchiveMaximumBytes
                    Set-WelaDnsAnalyticalNative $arguments
                }
                $report.After=Assert-WelaDnsAnalyticalCurrent $definition $desired
                $report.Status='Applied'
                Write-WelaDnsAnalyticalJson (Join-Path $backup '04-applied.json') $report
            }
        }
        if($Action -eq 'Configure' -and $report.Status -in @('Applied','AlreadyCompliant')){$report.After=Assert-WelaDnsAnalyticalCurrent $definition $desired}
    }catch{
        $report.ExitCode=1;$report.Status='Failed';$report.Diagnostic=$_.Exception.Message
        if($report.Definition){try{$report.After=Get-WelaDnsAnalyticalState $report.Definition}catch{$report.Diagnostic+=' After-state unknown: '+$_.Exception.Message}}
        if($report.BackupPath){$report.Diagnostic+=' Recovery files are retained. A trace stopped before a failed archive remains stopped; no automatic re-enable risks resetting unarchived evidence.'}
    }
    if($report.BackupPath){Write-WelaDnsAnalyticalJson (Join-Path $report.BackupPath '05-result.json') $report}
    if($output){Write-WelaDnsAnalyticalJson $output $report}
    $report
}
