# One selected completed firewall text-log operation; never replay enforcement or rules.
function Get-WelaFirewallRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress}

function ConvertTo-WelaFirewallRecoveryTuple {
    param($Value,[switch]$Snapshot)
    $fields=@('LogAllowed','LogBlocked','LogMaxSizeKilobytes','LogFileName')
    if($Snapshot){$fields=@('Name')+$fields+@('Enabled')}
    Assert-WelaArrivalObject $Value $fields
    if($Value.LogAllowed -isnot [string] -or $Value.LogAllowed -cnotin @('True','False') -or
        $Value.LogBlocked -isnot [string] -or $Value.LogBlocked -cnotin @('True','False')){throw 'Only explicit local True/False logging switches are recoverable; GPO NotConfigured requires manual review.'}
    $size=$Value.LogMaxSizeKilobytes
    if(($size -isnot [int] -and $size -isnot [long] -and $size -isnot [uint64] -and $size -isnot [uint32]) -or $size -lt 1 -or $size -gt 32767){throw 'Firewall logging size must be an integer from 1 through 32767 KiB.'}
    $null=Resolve-WelaFirewallRecoveryLogPath $Value.LogFileName
    if($Snapshot -and ($Value.Name -isnot [string] -or $Value.Name -cnotin @('Domain','Private','Public') -or $Value.Enabled -isnot [string] -or $Value.Enabled -cnotin @('True','False','NotConfigured'))){throw 'Invalid profile snapshot identity or enabled observation.'}
    [pscustomobject][ordered]@{LogAllowed=$Value.LogAllowed;LogBlocked=$Value.LogBlocked;LogMaxSizeKilobytes=[long]$size;LogFileName=$Value.LogFileName}
}

function Resolve-WelaFirewallRecoveryLogPath {
    param($Path)
    if($Path -isnot [string] -or -not $Path -or $Path.Length -gt 260 -or $Path -match '[\x00-\x1f*?\[\]]' -or $Path -match '(^|[\\/])\.\.?([\\/]|$)'){throw 'A bounded ordinary local firewall log path is required.'}
    # Only native Windows directory variables have reviewed meaning in old paths.
    $expanded=[regex]::Replace($Path,'(?i)%(systemroot|windir)%',[Text.RegularExpressions.MatchEvaluator]{param($m) [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)})
    if($expanded -notmatch '^[A-Za-z]:\\' -or $expanded -match '%' -or $expanded.Substring(2).Contains(':') -or $expanded.EndsWith('\') -or $expanded.Contains('/')){throw 'UNC/device/relative paths, unknown variables and alternate streams are unsupported.'}
    foreach($segment in $expanded.Substring(3).Split([char]'\')){
        if(-not $segment -or $segment -match '[ .]$' -or $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)'){throw 'Ambiguous path segments and Windows device aliases are unsupported.'}
    }
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){$null=Resolve-WelaArrivalPath $expanded}
    $expanded
}

function Get-WelaFirewallRecoverySources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/FirewallLoggingRecovery.ps1','scripts/FirewallLogging.ps1','scripts/Configuration.ps1','scripts/AuditRecovery.ps1','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs')) {
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    [pscustomobject]$sources
}

function Get-WelaFirewallRecoveryContext {
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'Firewall recovery requires the actual non-impersonated elevated administrator.'}
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $build=[int]$os.BuildNumber
    if(($os.ProductType -eq 1 -and $build -notin @(22000,22621,22631,26100,26200)) -or
        ($os.ProductType -in @(2,3) -and $build -notin @(20348,26100)) -or $os.ProductType -notin @(1,2,3)){throw 'Unreviewed Windows host for firewall recovery.'}
    $machine=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid
    $guid=[guid]::Empty
    if(-not $machine.ValueExists -or $machine.Type -cne 'String' -or -not [guid]::TryParse([string]$machine.Value,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Actual machine identity is unavailable.'}
    $revision=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;MachineGuid=$guid.ToString();Build=$build;UBR=$revision.UBR;ProductType=[int]$os.ProductType;DomainRole=[int]$computer.DomainRole;Domain=[string]$computer.Domain;DomainJoined=[bool]$computer.PartOfDomain
        Reader=[pscustomobject]@{UserSid=$reader.UserSid;UserName=$reader.UserName;AuthenticationId=$reader.AuthenticationId;GroupSids=$reader.GroupSids;ElevatedAdministrator=$reader.ElevatedAdministrator;Impersonation=$reader.Impersonation}
        Engine=$PSVersionTable.PSVersion.ToString()}
}

function Get-WelaFirewallRecoveryNativeSources {
    $base=[IO.Path]::GetFullPath((Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/Modules/NetSecurity'))
    $commands=@('Get-NetFirewallProfile','Set-NetFirewallProfile','Get-NetFirewallRule')+@('Port','Address','Application','Service','Interface','InterfaceType','Security' | ForEach-Object {"Get-NetFirewall${_}Filter"})
    foreach($name in $commands){
        $command=@(Get-Command "NetSecurity\$name" -ErrorAction Stop)
        if($command.Count -ne 1 -or $command[0].Name -cne $name -or [IO.Path]::GetFullPath($command[0].Module.ModuleBase) -ine $base){throw "Native NetSecurity command source is unverified: $name"}
    }
    $files=@(Get-ChildItem -LiteralPath $base -File -Recurse -ErrorAction Stop | Where-Object Extension -in @('.psd1','.psm1','.cdxml','.dll','.ps1xml') | Sort-Object FullName)
    if($files.Count -lt 1 -or $files.Count -gt 160){throw 'Unexpected native firewall module inventory.'}
    $hashes=[ordered]@{}
    foreach($file in $files){if($file.Length -gt 16MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsupported firewall module source.'};$hashes[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash}
    [pscustomobject]$hashes
}

function ConvertTo-WelaFirewallRecoveryCim {
    param($Value,[string[]]$Exclude=@())
    if(-not $Value.CimClass.CimClassName -or -not $Value.CimInstanceProperties){throw 'Native firewall CIM configuration is missing.'}
    $properties=@($Value.CimInstanceProperties | Sort-Object Name)
    if($properties.Count -gt 160){throw 'Native firewall property bound exceeded.'}
    $result=[ordered]@{Class=[string]$Value.CimClass.CimClassName}
    foreach($property in $properties){
        if($property.Name -in $Exclude){continue}
        if($result.Contains($property.Name)){throw 'Duplicate native firewall property.'}
        $valueData=$property.Value
        if(@($valueData).Count -gt 256){throw 'Native firewall property array bound exceeded.'}
        foreach($item in @($valueData)){
            if($null -ne $item -and $item -isnot [string] -and $item -isnot [bool] -and $item -isnot [byte] -and
                $item -isnot [uint16] -and $item -isnot [uint32] -and $item -isnot [uint64] -and $item -isnot [int16] -and $item -isnot [int] -and $item -isnot [long]){throw "Unsupported native property type: $($property.Name)"}
            if($item -is [string] -and $item.Length -gt 32768){throw 'Native firewall property string bound exceeded.'}
        }
        $result[$property.Name]=[pscustomobject]@{Type=$property.CimType.ToString();Value=$valueData}
    }
    [pscustomobject]$result
}

function Get-WelaFirewallRecoveryRuleDigest {
    param([ValidateSet('PersistentStore','ActiveStore')][string]$Store)
    # Hash configuration fields; volatile operational diagnostics are not policy.
    $volatile=@('PrimaryStatus','Status','StatusDescriptions','EnforcementStatus','OperationalStatus','CommunicationStatus','HealthState','OperatingStatus','DetailedStatus','TimeOfLastStateChange','InstallDate')
    foreach($kind in @('Rule','PortFilter','AddressFilter','ApplicationFilter','ServiceFilter','InterfaceFilter','InterfaceTypeFilter','SecurityFilter')){
        $command="NetSecurity\Get-NetFirewall$kind"
        $items=@(& $command -PolicyStore $Store -ErrorAction Stop | Select-Object -First 4097)
        if($items.Count -gt 4096){throw "Firewall $Store $kind inventory exceeded 4096 objects; recovery is unverified."}
        $keys=@(foreach($item in $items){Get-WelaFirewallRecoveryKey (ConvertTo-WelaFirewallRecoveryCim $item $volatile)}) | Sort-Object
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Get-WelaFirewallRecoveryKey @($keys)))
        if($bytes.Length -gt 16MB){throw 'Firewall configuration inventory exceeds the byte bound.'}
        [pscustomobject]@{Store=$Store;Kind=$kind;Count=$items.Count;Sha256=Get-WelaArrivalHash $bytes}
    }
}

function Get-WelaFirewallRecoveryState {
    $context=Get-WelaFirewallRecoveryContext
    $moduleSources=Get-WelaFirewallRecoveryNativeSources
    $stores=[ordered]@{};$digests=@()
    foreach($store in @('PersistentStore','ActiveStore')){
        $profiles=@(NetSecurity\Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Sort-Object Name)
        if($profiles.Count -ne 3 -or @($profiles.Name | Sort-Object -Unique).Count -ne 3){throw 'Expected exactly three native firewall profiles.'}
        $byName=[ordered]@{}
        foreach($profile in $profiles){
            $snapshot=ConvertTo-WelaFirewallLoggingSnapshot $profile
            $logging=ConvertTo-WelaFirewallRecoveryTuple $snapshot -Snapshot
            $byName[$snapshot.Name]=[pscustomobject]@{Logging=$logging;Preserved=ConvertTo-WelaFirewallRecoveryCim $profile @('LogAllowed','LogBlocked','LogMaxSizeKilobytes','LogFileName')}
        }
        $stores[$store]=[pscustomobject]$byName
        $digests+=@(Get-WelaFirewallRecoveryRuleDigest $store)
    }
    [pscustomobject][ordered]@{Context=$context;Sources=Get-WelaFirewallRecoverySources;NativeSources=$moduleSources;Profiles=[pscustomobject]$stores;RuleConfiguration=$digests}
}

function Get-WelaFirewallRecoveryInvariant {
    param($State,[string]$Profile)
    $copy=Get-WelaFirewallRecoveryKey $State | ConvertFrom-Json
    $copy.Profiles.PersistentStore.$Profile.Logging=$null
    $copy.Profiles.ActiveStore.$Profile.Logging=$null
    Get-WelaFirewallRecoveryKey $copy
}

function Read-WelaFirewallRecoveryEvidence {
    param([string]$JournalPath,[string]$ResultsPath,[ValidateSet('Domain','Private','Public')][string]$Profile,[string]$Computer)
    $journal=Read-WelaWecUpdateFile $JournalPath;$resultFile=Read-WelaWecUpdateFile $ResultsPath
    $entries=@($journal.Text -split '\r?\n' | Where-Object {$_ -match '\S'} | ForEach-Object {ConvertFrom-WelaRecoveryJson $_})
    $results=ConvertFrom-WelaRecoveryJson $resultFile.Text
    if($entries.Count -lt 1 -or $entries.Count -gt 3 -or $results.Scope -isnot [string] -or $results.Scope -cne 'firewall-text-logging-only' -or $results.DryRun -isnot [bool] -or $results.DryRun -or $results.Results -isnot [array] -or $results.Results.Count -lt 1 -or $results.Results.Count -gt 3){throw 'Dedicated completed non-dry-run firewall configuration evidence is required.'}
    $seen=@{};$final=@{}
    foreach($entry in $entries){
        if(($entry.Version -isnot [int] -and $entry.Version -isnot [long]) -or $entry.Version -ne 1 -or $entry.Kind -isnot [string] -or $entry.Kind -cne 'FirewallTextLog' -or
            $entry.Id -cnotin @('FirewallTextLog/Domain','FirewallTextLog/Private','FirewallTextLog/Public') -or $seen.ContainsKey($entry.Id) -or $entry.ComputerName -isnot [string] -or $entry.ComputerName -ine $Computer){throw 'Unknown, duplicate or wrong-host firewall journal entry.'}
        if((ConvertTo-WelaArrivalUtc $entry.RecordedUtc) -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Journal timestamp is in the future.'}
        $seen[$entry.Id]=$entry
    }
    foreach($row in $results.Results){
        if($row.Kind -isnot [string] -or $row.Kind -cne 'FirewallTextLog' -or $row.Id -cnotin @('FirewallTextLog/Domain','FirewallTextLog/Private','FirewallTextLog/Public') -or $final.ContainsKey($row.Id)){throw 'Unknown or duplicate firewall result.'}
        $final[$row.Id]=$row
    }
    $id="FirewallTextLog/$Profile"
    if(-not $seen.ContainsKey($id) -or -not $final.ContainsKey($id) -or $final[$id].Status -isnot [string] -or $final[$id].Status -cne 'Applied'){throw 'One selected completed Applied firewall operation is required; partial/failed writes need manual review.'}
    $entry=$seen[$id];$row=$final[$id]
    foreach($field in @('Before','Desired','Target')){if((Get-WelaFirewallRecoveryKey $entry.$field) -cne (Get-WelaFirewallRecoveryKey $row.$field)){throw "Journal/result $field mismatch."}}
    Assert-WelaArrivalObject $entry.Target @('Name','PolicyStore')
    if($entry.Target.Name -isnot [string] -or $entry.Target.PolicyStore -isnot [string] -or $entry.Target.Name -cne $Profile -or $entry.Target.PolicyStore -cne 'PersistentStore'){throw 'Only the exact selected local PersistentStore profile is recoverable.'}
    Assert-WelaArrivalObject $entry.Desired @('LogAllowed','LogBlocked','MinimumSizeKiB','LogFileName','PathMode')
    $desired=$entry.Desired
    if($desired.LogAllowed -isnot [string] -or $desired.LogBlocked -isnot [string] -or $desired.LogAllowed -cne 'True' -or $desired.LogBlocked -cne 'True' -or ($desired.MinimumSizeKiB -isnot [int] -and $desired.MinimumSizeKiB -isnot [long]) -or $desired.MinimumSizeKiB -lt 16384 -or $desired.MinimumSizeKiB -gt 32767 -or $desired.PathMode -cnotin @('Preserve','CisV4')){throw 'Unsupported original firewall desired state.'}
    foreach($snapshot in @($entry.Before.Local,$entry.Before.Effective,$row.After.Local,$row.After.Effective)){
        $null=ConvertTo-WelaFirewallRecoveryTuple $snapshot -Snapshot
        if($snapshot.Name -cne $Profile){throw 'Original snapshot profile differs from selected profile.'}
    }
    $before=ConvertTo-WelaFirewallRecoveryTuple $entry.Before.Local -Snapshot
    $expected=ConvertTo-WelaFirewallRecoveryTuple $row.After.Local -Snapshot
    $effective=ConvertTo-WelaFirewallRecoveryTuple $row.After.Effective -Snapshot
    $requiredSize=[Math]::Max([long]$desired.MinimumSizeKiB,[Math]::Max([long]$entry.Before.Local.LogMaxSizeKilobytes,[long]$entry.Before.Effective.LogMaxSizeKilobytes))
    $path=if($desired.PathMode -ceq 'CisV4'){'%SystemRoot%\System32\LogFiles\Firewall\'+$Profile.ToLowerInvariant()+'fw.log'}else{$before.LogFileName}
    if($expected.LogAllowed -cne 'True' -or $expected.LogBlocked -cne 'True' -or $expected.LogMaxSizeKilobytes -ne $requiredSize -or $expected.LogFileName -cne $path){throw 'Recorded local After is not the permitted original logging-only change.'}
    $desiredPath=Resolve-WelaFirewallRecoveryLogPath $desired.LogFileName
    $plannedPath=if($desired.PathMode -ceq 'CisV4'){Resolve-WelaFirewallRecoveryLogPath $path}else{Resolve-WelaFirewallRecoveryLogPath $entry.Before.Effective.LogFileName}
    if($desiredPath -ine $plannedPath -or $effective.LogAllowed -cne 'True' -or $effective.LogBlocked -cne 'True' -or $effective.LogMaxSizeKilobytes -lt $desired.MinimumSizeKiB -or
        (Resolve-WelaFirewallRecoveryLogPath $effective.LogFileName) -ine $desiredPath -or $row.After.Access.State -isnot [string] -or $row.After.Access.State -cne 'VerifiedExplicitGrant'){throw 'Recorded effective After does not confirm the original logging configuration.'}
    if((Get-WelaFirewallRecoveryKey $before) -ceq (Get-WelaFirewallRecoveryKey $expected)){throw 'Selected evidence records no local logging change.'}
    [pscustomobject][ordered]@{Id=$id;Profile=$Profile;Journal=[pscustomobject]@{Path=$journal.Path;Sha256=$journal.Hash};OriginalResults=[pscustomobject]@{Path=$resultFile.Path;Sha256=$resultFile.Hash};Expected=$expected;RecoverTo=$before}
}

function Set-WelaFirewallRecoveryLogging {
    param([ValidateSet('Domain','Private','Public')][string]$Profile,$Tuple)
    $values=ConvertTo-WelaFirewallRecoveryTuple $Tuple
    NetSecurity\Set-NetFirewallProfile -Name $Profile -PolicyStore PersistentStore -LogAllowed $values.LogAllowed -LogBlocked $values.LogBlocked -LogMaxSizeKilobytes ([uint64]$values.LogMaxSizeKilobytes) -LogFileName $values.LogFileName -Confirm:$false -ErrorAction Stop
}

function Assert-WelaFirewallRecoveryInputs {
    param($Plan,[string]$PlanPath,[string]$PlanHash)
    if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Reviewed recovery plan bytes changed.'}
    $rebuilt=Read-WelaFirewallRecoveryEvidence $Plan.Control.Journal.Path $Plan.Control.OriginalResults.Path $Plan.Profile $Plan.State.Context.Computer
    if((Get-WelaFirewallRecoveryKey $rebuilt) -cne (Get-WelaFirewallRecoveryKey $Plan.Control)){throw 'Original recovery evidence changed or no longer matches the plan.'}
}

function Invoke-WelaFirewallLoggingRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$Profile,[string]$JournalPath,[string]$ResultsPath,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$Auto,[switch]$DryRun)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if($Profile -cnotin @('Domain','Private','Public') -or -not $JournalPath -or -not $ResultsPath -or -not $OutputPath -or $PlanPath -or $PlanHash -or $Auto -or $DryRun){throw 'Plan requires one profile, original journal/results and new output only.'}
    }elseif($Profile -or $JournalPath -or $ResultsPath -or -not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or ($DryRun -and $OutputPath) -or (-not $DryRun -and -not $OutputPath)){throw 'Restore requires a reviewed plan/hash and new output, or DryRun without output.'}
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaFirewallLoggingRecovery';Action=$Action;Status='Refused';ExitCode=1;WriteAttempted=$false;Before=$null;After=$null;EffectiveMatchesLocal=$null;OutputPath=$null;Artifacts=@();PlanSha256=$null;Diagnostic='';ReadyRuleCredit=0;Scope='Restore four PersistentStore logging fields on one profile only; effective policy and event generation are separate.'}
    try {
        if($Action -eq 'Plan'){
            $state=Get-WelaFirewallRecoveryState
            $control=Read-WelaFirewallRecoveryEvidence $JournalPath $ResultsPath $Profile $state.Context.Computer
            $local=$state.Profiles.PersistentStore.$Profile.Logging
            if((Get-WelaFirewallRecoveryKey $local) -cne (Get-WelaFirewallRecoveryKey $control.Expected)){throw 'Current local logging tuple differs from the completed original After state.'}
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaFirewallLoggingRecoveryPlan';Profile=$Profile;Control=$control;State=$state;HistoricalIdentity='Version-1 configuration journals record only ComputerName; current MachineGuid and operator/logon bind this recovery plan, not historical authorship.'}
            if((Get-WelaFirewallRecoveryKey (Get-WelaFirewallRecoveryState)) -cne (Get-WelaFirewallRecoveryKey $state)){throw 'Current firewall context changed during planning.'}
            $report.OutputPath=New-WelaArrivalOutput $OutputPath $script:ScriptRoot
            $planText=Get-WelaFirewallRecoveryKey $plan
            if([Text.UTF8Encoding]::new($false).GetByteCount($planText) -gt 4MB){throw 'Recovery plan exceeds its input byte bound.'}
            $artifact=Write-WelaWecUpdateArtifact $report.OutputPath 'plan.json' $planText;$report.Artifacts+=$artifact;$report.PlanSha256=$artifact.Sha256
            $report.Before=$state;$report.Status='Planned';$report.ExitCode=0
        }else{
            $source=Read-WelaWecUpdateFile $PlanPath
            if($source.Hash -cne $PlanHash){throw 'Reviewed plan SHA256 differs from the selected file.'}
            $plan=ConvertFrom-WelaRecoveryJson $source.Text
            Assert-WelaArrivalObject $plan @('SchemaVersion','Kind','Profile','Control','State','HistoricalIdentity')
            if(($plan.SchemaVersion -isnot [int] -and $plan.SchemaVersion -isnot [long]) -or $plan.SchemaVersion -ne 1 -or $plan.Kind -isnot [string] -or $plan.Kind -cne 'WelaFirewallLoggingRecoveryPlan' -or $plan.Profile -cnotin @('Domain','Private','Public')){throw 'Unsupported firewall recovery plan.'}
            $report.PlanSha256=$source.Hash
            Assert-WelaFirewallRecoveryInputs $plan $source.Path $source.Hash
            $current=Get-WelaFirewallRecoveryState;$report.Before=$current
            $invariant=Get-WelaFirewallRecoveryInvariant $plan.State $plan.Profile
            if((Get-WelaFirewallRecoveryInvariant $current $plan.Profile) -cne $invariant){throw 'Host, operator, source, enforcement, other profile or rule configuration changed since planning.'}
            $local=$current.Profiles.PersistentStore.($plan.Profile).Logging
            $already=(Get-WelaFirewallRecoveryKey $local) -ceq (Get-WelaFirewallRecoveryKey $plan.Control.RecoverTo)
            if(-not $already -and (Get-WelaFirewallRecoveryKey $local) -cne (Get-WelaFirewallRecoveryKey $plan.Control.Expected)){throw 'Selected local logging tuple drifted from the confirmed original After state.'}
            if($DryRun){$report.Status=if($already){'AlreadyRestored'}else{'WouldRestore'};$report.ExitCode=0;return $report}
            $report.OutputPath=New-WelaArrivalOutput $OutputPath $script:ScriptRoot
            $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'reviewed-plan.json' $source.Text
            if(-not $already){
                if(-not $Auto -and (Read-Host "Restore only $($plan.Profile) firewall logging fields to the reviewed original values? (y/N)") -cnotin @('y','Y')){throw 'Recovery declined; no setter was called.'}
                $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'pending.json' (Get-WelaFirewallRecoveryKey ([pscustomobject]@{Status='Pending';RecordedUtc=[DateTime]::UtcNow.ToString('o');PlanSha256=$source.Hash;Before=$current;RecoverTo=$plan.Control.RecoverTo}))
                Assert-WelaFirewallRecoveryInputs $plan $source.Path $source.Hash
                $fresh=Get-WelaFirewallRecoveryState
                if((Get-WelaFirewallRecoveryKey $fresh) -cne (Get-WelaFirewallRecoveryKey $current)){throw 'Context changed after confirmation/intent receipt; no recovery setter was called.'}
                foreach($artifact in $report.Artifacts){if((Get-FileHash -LiteralPath (Join-Path $report.OutputPath $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Durable recovery evidence changed before the setter.'}}
                $report.WriteAttempted=$true
                Set-WelaFirewallRecoveryLogging $plan.Profile $plan.Control.RecoverTo
            }
            $after=Get-WelaFirewallRecoveryState;$report.After=$after
            if((Get-WelaFirewallRecoveryInvariant $after $plan.Profile) -cne $invariant -or
                (Get-WelaFirewallRecoveryKey $after.Profiles.PersistentStore.($plan.Profile).Logging) -cne (Get-WelaFirewallRecoveryKey $plan.Control.RecoverTo)){throw 'Local logging restoration or preserved firewall context did not verify.'}
            Assert-WelaFirewallRecoveryInputs $plan $source.Path $source.Hash
            $report.EffectiveMatchesLocal=(Get-WelaFirewallRecoveryKey $after.Profiles.ActiveStore.($plan.Profile).Logging) -ceq (Get-WelaFirewallRecoveryKey $after.Profiles.PersistentStore.($plan.Profile).Logging)
            $report.Artifacts+=Write-WelaWecUpdateArtifact $report.OutputPath 'confirmed.json' (Get-WelaFirewallRecoveryKey ([pscustomobject]@{Status='LocalReadbackVerified';PlanSha256=$source.Hash;After=$after;WriteAttempted=$report.WriteAttempted;EffectiveMatchesLocal=$report.EffectiveMatchesLocal}))
            $final=Get-WelaFirewallRecoveryState;$report.After=$final
            if((Get-WelaFirewallRecoveryKey $final) -cne (Get-WelaFirewallRecoveryKey $after)){throw 'Final firewall context drifted after readback.'}
            Assert-WelaFirewallRecoveryInputs $plan $source.Path $source.Hash
            $report.Status=if($already){'AlreadyRestored'}else{'LocalLoggingRestored'};$report.ExitCode=0
        }
    }catch{$report.Status=if($report.WriteAttempted){'WriteAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message}
    if($report.OutputPath){$null=Write-WelaWecUpdateArtifact $report.OutputPath 'result.json' (Get-WelaFirewallRecoveryKey $report)}
    $report
}
