$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
foreach($file in @('Configuration','FirewallLogging','AuditRecovery','WefArrival','WecUpdate','FirewallLoggingRecovery')){. (Join-Path $repo "scripts/$file.ps1")}
$script:assertions=0;$script:writes=0;$script:mode='';$script:prompt=$null
function Assert($Value,$Message){if(-not $Value){throw "FAIL: $Message"};$script:assertions++}
function Throws($Action,$Pattern){$message='';try{& $Action | Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; received $message"}
function Copy-Fixture($Value){Get-WelaFirewallRecoveryKey $Value | ConvertFrom-Json}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-firewall-fixture-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $root
$journal=Join-Path $root 'before.jsonl';$results=Join-Path $root 'original.json'
# Only the platform output-ACL boundary and native state/setter are replaced.
# Strict input parsing, durable artifact writes and all production orchestration run.
function New-WelaArrivalOutput {param($Path,$SourcePath) if(Test-Path -LiteralPath $Path){throw 'Output exists'};$null=New-Item -ItemType Directory -Path $Path;[IO.Path]::GetFullPath($Path)}
function Snapshot($Name,$Enabled='False',$Size=4096){[pscustomobject][ordered]@{Name=$Name;LogAllowed=$Enabled;LogBlocked=$Enabled;LogMaxSizeKilobytes=$Size;LogFileName="C:\Logs\$Name.log";Enabled='True'}}
function Reset {
    $script:writes=0;$script:mode='';$script:prompt=$null
    $before=[pscustomobject]@{Local=Snapshot Domain;Effective=Snapshot Domain}
    $after=[pscustomobject]@{Local=Snapshot Domain True 16384;Effective=Snapshot Domain True 16384;Access=[pscustomobject]@{State='VerifiedExplicitGrant'}}
    $script:entry=[pscustomobject][ordered]@{Version=1;ComputerName='TEST';RecordedUtc=[DateTime]::UtcNow.ToString('o');Id='FirewallTextLog/Domain';Kind='FirewallTextLog';Target=[pscustomobject]@{Name='Domain';PolicyStore='PersistentStore'};Before=$before;Desired=[pscustomobject]@{LogAllowed='True';LogBlocked='True';MinimumSizeKiB=16384;LogFileName='C:\Logs\Domain.log';PathMode='Preserve'}}
    $script:row=[pscustomobject]@{Id=$entry.Id;Kind=$entry.Kind;Target=Copy-Fixture $entry.Target;Before=Copy-Fixture $entry.Before;Desired=Copy-Fixture $entry.Desired;After=$after;Status='Applied';Diagnostic=''}
    $stores=[ordered]@{}
    foreach($store in @('PersistentStore','ActiveStore')){
        $profiles=[ordered]@{}
        foreach($name in @('Domain','Private','Public')){$profiles[$name]=[pscustomobject]@{Logging=ConvertTo-WelaFirewallRecoveryTuple (Snapshot $name True 16384) -Snapshot;Preserved=[pscustomobject]@{Enabled=$true;DefaultInboundAction='Block';Other='unchanged'}}}
        $stores[$store]=[pscustomobject]$profiles
    }
    $script:state=[pscustomobject][ordered]@{Context=[pscustomobject]@{Computer='TEST';MachineGuid='actual-now';Reader='sid+logon';Engine='test'};Sources=[pscustomobject]@{Code='pinned'};NativeSources=[pscustomobject]@{Module='native'};Profiles=[pscustomobject]$stores;RuleConfiguration=@([pscustomobject]@{Store='PersistentStore';Sha256='rules'})}
    Save
}
function Save {
    [IO.File]::WriteAllText($journal,(Get-WelaFirewallRecoveryKey $entry),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($results,(Get-WelaFirewallRecoveryKey ([pscustomobject]@{DryRun=$false;Scope='firewall-text-logging-only';Results=@($row)})),[Text.UTF8Encoding]::new($false))
}
function Get-WelaFirewallRecoveryState {Copy-Fixture $script:state}
function Read-Host {param($Prompt) if($script:prompt){& $script:prompt};'y'}
function Set-WelaFirewallRecoveryLogging {
    param($Profile,$Tuple)
    Assert ($Profile -ceq 'Domain') 'Setter receives only selected profile'
    $pending=Get-Content -LiteralPath (Join-Path $script:restoreOutput 'pending.json') -Raw | ConvertFrom-Json
    Assert ($pending.Status -ceq 'Pending' -and $pending.RecoverTo.LogAllowed -ceq 'False') 'Durable matching pending receipt precedes setter'
    $script:writes++
    $script:state.Profiles.PersistentStore.Domain.Logging=Copy-Fixture $Tuple
    if($script:mode -ne 'policy'){$script:state.Profiles.ActiveStore.Domain.Logging=Copy-Fixture $Tuple}
    if($script:mode -eq 'throw'){throw 'Injected partial native setter failure'}
    if($script:mode -eq 'enforcement'){$script:state.Profiles.PersistentStore.Domain.Preserved.Enabled=$false}
}
function Plan {
    $out=Join-Path $root ([guid]::NewGuid().ToString('N'))
    $r=Invoke-WelaFirewallLoggingRecovery -Profile Domain -JournalPath $journal -ResultsPath $results -OutputPath $out
    Assert ($r.Status -ceq 'Planned' -and $r.ExitCode -eq 0) "Plan accepted: $($r.Diagnostic)"
    $script:planPath=Join-Path $out 'plan.json';$script:planHash=$r.PlanSha256
}
function Restore([switch]$Prompt,[switch]$DryRun){
    $script:restoreOutput=Join-Path $root ([guid]::NewGuid().ToString('N'))
    $args=@{Action='Restore';PlanPath=$script:planPath;PlanHash=$script:planHash;Auto=(-not $Prompt);DryRun=$DryRun}
    if(-not $DryRun){$args.OutputPath=$script:restoreOutput}
    Invoke-WelaFirewallLoggingRecovery @args
}
try {
    Reset
    $e=Read-WelaFirewallRecoveryEvidence $journal $results Domain TEST
    Assert ($e.RecoverTo.LogMaxSizeKilobytes -eq 4096 -and $e.Expected.LogAllowed -ceq 'True') 'Exact typed local recovery tuple'
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        $entry.Desired.PathMode='CisV4';$entry.Desired.LogFileName='%SystemRoot%\System32\LogFiles\Firewall\domainfw.log';$row.Desired=Copy-Fixture $entry.Desired
        $row.After.Local.LogFileName=$entry.Desired.LogFileName;$row.After.Effective.LogFileName=$entry.Desired.LogFileName;Save
        $migration=Read-WelaFirewallRecoveryEvidence $journal $results Domain TEST
        Assert ($migration.RecoverTo.LogFileName -ceq 'C:\Logs\Domain.log' -and $migration.Expected.LogFileName -ceq $entry.Desired.LogFileName) 'CIS migration preserves the exact original local recovery path'
        Reset
    }
    foreach($bad in @('NotConfigured','true','1')){$v=Copy-Fixture $e.RecoverTo;$v.LogAllowed=$bad;Throws {ConvertTo-WelaFirewallRecoveryTuple $v} 'True/False'}
    foreach($bad in @('4096',0,32768,$true,1.5)){$v=Copy-Fixture $e.RecoverTo;$v.LogMaxSizeKilobytes=$bad;Throws {ConvertTo-WelaFirewallRecoveryTuple $v} 'integer'}
    foreach($path in @('\\host\share\log','C:\Logs\..\other.log','C:\Logs\log:stream','C:\Logs\*.log','%TEMP%\log','C:relative.log','C:\Logs\','C:\Logs\CON.log','C:\Logs\log.','C:\Logs\log ','C:\Logs\\log')){Throws {Resolve-WelaFirewallRecoveryLogPath $path} 'path|unsupported|streams'}
    $v=Copy-Fixture $e.RecoverTo;$v|Add-Member Extra 1;Throws {ConvertTo-WelaFirewallRecoveryTuple $v} 'Unexpected'
    foreach($change in @(
        {$script:row.Status='Failed'},{$script:row.Status=$true},{$script:row.After.Access.State=$true},
        {$script:entry.Target.Name=$true;$script:row.Target=Copy-Fixture $entry.Target},
        {$script:entry.Target.PolicyStore=$true;$script:row.Target=Copy-Fixture $entry.Target},
        {$script:entry.Desired.LogAllowed=$true;$script:row.Desired=Copy-Fixture $entry.Desired},
        {$script:entry.Target.PolicyStore='ActiveStore';$script:row.Target=Copy-Fixture $entry.Target},
        {$script:row.After.Local.LogMaxSizeKilobytes=20000},{$script:row.After.Local.LogFileName='C:\Other.log'},
        {$script:row.After.Access.State='Unknown'},{$script:entry.ComputerName='OTHER'},
        {$script:row.Before.Local.LogBlocked='True'},{$script:entry.Desired.MinimumSizeKiB='16384';$script:row.Desired=Copy-Fixture $entry.Desired}
    )){Reset;& $change;Save;Throws {Read-WelaFirewallRecoveryEvidence $journal $results Domain TEST} 'required|Only|permitted|confirm|wrong-host|mismatch|Unsupported'}
    Reset;[IO.File]::AppendAllText($journal,"`n"+(Get-WelaFirewallRecoveryKey $entry));Throws {Read-WelaFirewallRecoveryEvidence $journal $results Domain TEST} 'duplicate'
    Reset;[IO.File]::WriteAllText($journal,'{"Version":1,"version":1}');Throws {Read-WelaFirewallRecoveryEvidence $journal $results Domain TEST} 'duplicate|Duplicate|collision'
    Reset;Plan;$r=Restore -DryRun;Assert ($r.Status -ceq 'WouldRestore' -and $writes -eq 0 -and -not (Test-Path $restoreOutput)) 'Dry run has no writes or output'
    $r=Restore;Assert ($r.Status -ceq 'LocalLoggingRestored' -and $r.ExitCode -eq 0 -and $writes -eq 1 -and $r.EffectiveMatchesLocal -and $r.ReadyRuleCredit -eq 0) "Exact restoration succeeded: $($r.Diagnostic)"
    $r=Restore;Assert ($r.Status -ceq 'AlreadyRestored' -and $writes -eq 1) 'Idempotence never calls setter'
    foreach($change in @(
        {$script:state.Profiles.PersistentStore.Domain.Logging.LogMaxSizeKilobytes=24576},
        {$script:state.Profiles.PersistentStore.Private.Logging.LogBlocked='False'},
        {$script:state.Profiles.PersistentStore.Domain.Preserved.Enabled=$false},
        {$script:state.RuleConfiguration[0].Sha256='drift'},{$script:state.Context.Reader='another-logon'},
        {$script:state.Sources.Code='changed'},{$script:state.NativeSources.Module='changed'}
    )){Reset;Plan;& $change;$r=Restore;Assert ($r.Status -ceq 'Refused' -and -not $r.WriteAttempted -and $writes -eq 0) 'Current drift blocks every setter'}
    Reset;Plan;$script:prompt={$script:state.Profiles.PersistentStore.Domain.Logging.LogBlocked='False'};$r=Restore -Prompt
    Assert ($r.Status -ceq 'Refused' -and $writes -eq 0 -and (Test-Path (Join-Path $restoreOutput 'pending.json'))) 'Fresh post-prompt guard preserves pending receipt without writing'
    Reset;Plan;$entry.Before.Local.LogMaxSizeKilobytes=2048;$row.Before=Copy-Fixture $entry.Before;Save;$r=Restore
    Assert ($r.Status -ceq 'Refused' -and $writes -eq 0) 'Changed original inputs block restore'
    Reset;Plan;[IO.File]::AppendAllText($planPath,' ');$r=Restore;Assert ($r.Status -ceq 'Refused' -and $writes -eq 0) 'Changed reviewed plan bytes block restore'
    Reset;Plan;$script:mode='throw';$r=Restore
    Assert ($r.Status -ceq 'WriteAttemptedUnverified' -and $r.ExitCode -eq 1 -and $r.WriteAttempted -and (Test-Path (Join-Path $restoreOutput 'pending.json')) -and -not (Test-Path (Join-Path $restoreOutput 'confirmed.json'))) 'Partial setter failure stays unverified with durable intent, never automatic rollback'
    Reset;Plan;$script:mode='enforcement';$r=Restore;Assert ($r.Status -ceq 'WriteAttemptedUnverified') 'Unexpected enforcement drift fails readback'
    Reset;Plan;$script:mode='policy';$r=Restore;Assert ($r.Status -ceq 'LocalLoggingRestored' -and -not $r.EffectiveMatchesLocal) 'Local restoration is separate from unchanged effective override'
    # CIM configuration hashes must retain enforcement/condition data and typed nulls.
    $cim=[pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_NetFirewallRule'};CimInstanceProperties=@([pscustomobject]@{Name='Enabled';Value=1;CimType='UInt16'},[pscustomobject]@{Name='Status';Value='volatile';CimType='String'})}
    $key=ConvertTo-WelaFirewallRecoveryCim $cim @('Status');Assert ($key.Enabled.Type -eq 'UInt16' -and -not $key.PSObject.Properties['Status']) 'Rule hash preserves typed configuration while excluding named diagnostics'
    $cim.CimInstanceProperties[0].Value=[DateTime]::UtcNow;Throws {ConvertTo-WelaFirewallRecoveryCim $cim} 'Unsupported native property type'
    # A prerequisite read must not connect to WMI while its services are stopped.
    $script:providerReads=0;$script:serviceStatus='Stopped'
    function Get-WelaChannelReader {[pscustomobject]@{ElevatedAdministrator=$true}}
    function Get-Service {param($Name,$ErrorAction) foreach($n in $Name){[pscustomobject]@{Name=$n;Status=$script:serviceStatus}}}
    function Get-CimInstance {$script:providerReads++;throw 'Native provider boundary reached'}
    Throws {Get-WelaFirewallRecoveryContext} 'must already be running'
    Assert ($providerReads -eq 0) 'Stopped services are refused before any native provider connection'
    $script:serviceStatus='Running';Throws {Get-WelaFirewallRecoveryContext} 'Native provider boundary reached'
    Assert ($providerReads -eq 1) 'Running services permit the first native provider read'
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
$global:LASTEXITCODE=0
Write-Host "Firewall logging recovery: $script:assertions assertions passed."
