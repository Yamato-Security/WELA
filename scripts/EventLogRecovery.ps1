# Restore one completed profile size/mode write; never replay arbitrary wevtutil arguments.
function Get-WelaEventRecoverySources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/EventLogRecovery.ps1','scripts/EventLogConfiguration.ps1','modules/EventLogSettings.psm1','config/eventlog_profiles.json','scripts/Configuration.ps1','scripts/AuditRecovery.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    $sources|ConvertTo-Json -Compress
}
function Get-WelaEventRecoveryContext {
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'An elevated native Windows operator is required.'}
    [pscustomobject][ordered]@{Host=(Get-WelaRecoveryHost);Reader=[ordered]@{Sid=$reader.UserSid;Logon=$reader.AuthenticationId;Groups=$reader.GroupSids}}
}
function Read-WelaEventRecoveryChannel {
    param([string]$Log)
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($Log)
    try {
        if($channel.LogName -cne $Log -or [string]$channel.LogType -notin @('Administrative','Operational')){throw 'An exact administrative or operational channel is required.'}
        [pscustomobject][ordered]@{
            Log=$channel.LogName;MaximumSizeInBytes=[long]$channel.MaximumSizeInBytes;LogMode=[string]$channel.LogMode
            Guard=[ordered]@{IsEnabled=[bool]$channel.IsEnabled;LogType=[string]$channel.LogType;Isolation=[string]$channel.LogIsolation;Path=[string]$channel.LogFilePath;SecurityDescriptor=[string]$channel.SecurityDescriptor;Provider=[string]$channel.OwningProviderName;Classic=[bool]$channel.IsClassicLog}
        }
    }finally{$channel.Dispose()}
}
function Assert-WelaEventRecoveryState {
    param($State,[string]$Log)
    if($State.Log -cne $Log -or $State.ReadStatus -cne 'Available' -or $State.Diagnostic -cne '' -or $State.IsEnabled -isnot [bool] -or
        ($State.MaximumSizeInBytes -isnot [int] -and $State.MaximumSizeInBytes -isnot [long]) -or $State.MaximumSizeInBytes -lt 1048576 -or $State.MaximumSizeInBytes -gt 2199023255552 -or $State.MaximumSizeInBytes % 65536 -ne 0 -or $State.LogMode -cnotin @('Circular','Retain','AutoBackup')){throw 'Original channel state is unavailable, mistyped or unsupported.'}
}
function Get-WelaEventRecoveryPair {param($Value) [pscustomobject][ordered]@{MaximumSizeInBytes=[long]$Value.MaximumSizeInBytes;LogMode=[string]$Value.LogMode}}
function Get-WelaEventRecoveryDefinition {
    param([string]$JournalPath,[string]$ResultsPath,[string]$Log)
    $catalog=Import-WelaEventLogProfiles
    if($Log -cnotin @($catalog.profiles.controls.log)){throw 'Select an exact channel in the bundled event-log profiles.'}
    $context=Get-WelaEventRecoveryContext
    $journal=Read-WelaWecUpdateFile $JournalPath;$resultFile=Read-WelaWecUpdateFile $ResultsPath
    $entries=@($journal.Text -split '\r?\n'|Where-Object {$_ -match '\S'}|ForEach-Object {ConvertFrom-WelaArrivalJson $_})
    if($entries.Count -lt 1 -or $entries.Count -gt 1024){throw 'Expected 1-1024 bounded journal entries.'}
    $result=ConvertFrom-WelaArrivalJson $resultFile.Text
    if($result.DryRun -isnot [bool] -or $result.DryRun -or $result.Results -isnot [array] -or $result.Results.Count -gt 2048 -or $result.Scope -cnotin @('native-windows-configuration','event-log-size-and-mode-only')){throw 'Expected original non-dry-run event-log configuration results.'}
    $id='EventLog/'+$Log+'/ProfileSettings'
    $rows=@($result.Results|Where-Object Id -eq $id);$matching=@($entries|Where-Object Id -eq $id)
    if($rows.Count -ne 1 -or $matching.Count -ne 2){throw 'Exactly one result and its original/immediate-prewrite journal pair are required.'}
    $row=$rows[0];$initial=$matching[0];$fresh=$matching[1]
    if($initial.PSObject.Properties['Phase'] -or $fresh.Phase -cne 'ImmediatePreWrite' -or $row.Status -cne 'Applied' -or $row.Kind -cne 'EventLog' -or $row.Id -cne $id){throw 'Only completed Applied profile writes with ordered immediate-prewrite evidence are supported.'}
    foreach($entry in $matching){
        if(($entry.Version -isnot [int] -and $entry.Version -isnot [long]) -or $entry.Version -ne 1 -or $entry.ComputerName -ine $context.Host.Computer -or $entry.Kind -cne 'EventLog' -or $entry.Id -cne $id){throw 'Unknown or wrong-host event-log journal.'}
        $time=ConvertTo-WelaArrivalUtc $entry.RecordedUtc;if($time -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Future journal timestamp.'}
    }
    if((ConvertTo-WelaArrivalUtc $fresh.RecordedUtc) -lt (ConvertTo-WelaArrivalUtc $initial.RecordedUtc)){throw 'Journal times are reversed.'}
    foreach($field in @('Before','Target','Desired')){if((Get-WelaRecoveryKey $initial.$field) -cne (Get-WelaRecoveryKey $row.$field)){throw "Original/result $field differs."}}
    Assert-WelaArrivalObject $initial.Target @('Log','Profile');Assert-WelaArrivalObject $fresh.Target @('Log')
    if($initial.Target.Log -cne $Log -or $fresh.Target.Log -cne $Log -or $initial.Target.Profile -isnot [string]){throw 'Contradictory channel identity.'}
    $profile=Get-WelaEventLogProfile $initial.Target.Profile;$control=@($profile.controls|Where-Object log -ceq $Log)
    if($control.Count -ne 1){throw 'Channel is not selected by the original bundled profile.'}
    Assert-WelaArrivalObject $initial.Desired @('MaximumSizeInBytes','SizeMode','LogMode')
    if((Get-WelaRecoveryKey $initial.Desired) -cne (Get-WelaRecoveryKey $fresh.Desired) -or $initial.Desired.SizeMode -cnotin @('Exact','Minimum') -or ($null -ne $initial.Desired.LogMode -and $initial.Desired.LogMode -cne $control[0].mode) -or
        ($initial.Desired.MaximumSizeInBytes -isnot [int] -and $initial.Desired.MaximumSizeInBytes -isnot [long]) -or $initial.Desired.MaximumSizeInBytes -ne (ConvertTo-WelaEventLogBytes $control[0].minimumBytes)){throw 'Desired configuration differs from the canonical profile operation.'}
    foreach($state in @($initial.Before,$fresh.Before,$row.After)){Assert-WelaEventRecoveryState $state $Log}
    if((Get-WelaRecoveryKey $fresh.Before) -cne (Get-WelaRecoveryKey $row.BeforeWrite)){throw 'Immediate prewrite and final BeforeWrite evidence differ.'}
    if($row.After.IsEnabled -ne $fresh.Before.IsEnabled){throw 'Channel enable state changed during original operation.'}
    $bytes=if($initial.Desired.SizeMode -ceq 'Exact'){$initial.Desired.MaximumSizeInBytes}else{[math]::Max([long]$fresh.Before.MaximumSizeInBytes,[long]$initial.Desired.MaximumSizeInBytes)}
    $mode=if($null -ne $initial.Desired.LogMode){$initial.Desired.LogMode}else{$fresh.Before.LogMode}
    if($row.After.MaximumSizeInBytes -ne $bytes -or $row.After.LogMode -cne $mode){throw 'Final state includes unexplained drift beyond the original size/mode write.'}
    $expected=Get-WelaEventRecoveryPair $row.After;$recover=Get-WelaEventRecoveryPair $fresh.Before
    if((Get-WelaRecoveryKey $expected) -ceq (Get-WelaRecoveryKey $recover)){throw 'No completed size/mode change exists to recover.'}
    [pscustomobject][ordered]@{
        Log=$Log;Profile=$profile.id;Journal=[ordered]@{Path=$journal.Path;Hash=$journal.Hash};OriginalResults=[ordered]@{Path=$resultFile.Path;Hash=$resultFile.Hash}
        Expected=$expected;RecoverTo=$recover;ExpectedEnabled=$row.After.IsEnabled
        RequiresShrinkConsent=($recover.MaximumSizeInBytes -lt $expected.MaximumSizeInBytes);RequiresModeConsent=($recover.LogMode -cne $expected.LogMode)
        HistoricalIdentity='Version1 records bind historical ComputerName only. Current host/logon and source hashes do not authenticate historical ownership or configuration.'
    }
}
function Assert-WelaEventRecoveryCurrent {
    param($Definition,$Observed,$Guard)
    if($Observed.Log -cne $Definition.Log -or $Observed.Guard.IsEnabled -ne $Definition.ExpectedEnabled -or
        (Get-WelaRecoveryKey (Get-WelaEventRecoveryPair $Observed)) -cne (Get-WelaRecoveryKey $Definition.Expected) -or
        ($null -ne $Guard -and (Get-WelaRecoveryKey $Observed.Guard) -cne (Get-WelaRecoveryKey $Guard))){throw 'Current channel size, mode, identity or preserved properties differ from reviewed post-configuration state.'}
}
function Set-WelaEventRecoveryChannel {
    param($Definition)
    $arguments=@('sl',$Definition.Log)
    if($Definition.RecoverTo.MaximumSizeInBytes -ne $Definition.Expected.MaximumSizeInBytes){$arguments+='/ms:'+ $Definition.RecoverTo.MaximumSizeInBytes}
    if($Definition.RecoverTo.LogMode -cne $Definition.Expected.LogMode){
        switch($Definition.RecoverTo.LogMode){'Circular'{$arguments+=@('/rt:false','/ab:false')};'Retain'{$arguments+=@('/rt:true','/ab:false')};'AutoBackup'{$arguments+=@('/rt:true','/ab:true')};default{throw 'Unsupported recovery mode.'}}
    }
    if($arguments.Count -le 2){throw 'No fixed recovery argument was selected.'}
    $null=Invoke-WelaNative -FilePath (Join-Path ([Environment]::GetFolderPath('System')) 'wevtutil.exe') -Arguments $arguments
}
function Invoke-WelaEventLogRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$JournalPath,[string]$OriginalResultsPath,[string]$Log,[string]$PlanPath,[string]$PlanHash,[Parameter(Mandatory)][string]$OutputPath,[switch]$AllowShrink,[switch]$AllowRetentionChange)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $JournalPath -or -not $OriginalResultsPath -or -not $Log -or $PlanPath -or $PlanHash -or $AllowShrink -or $AllowRetentionChange){throw 'Plan requires original journal/results, exact channel and new output; restore-only options are not accepted.'}
        $source=Read-WelaWecUpdateFile $JournalPath
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or $JournalPath -or $OriginalResultsPath -or $Log){throw 'Restore requires only reviewed plan path/hash, new output and applicable explicit loss/retention consent.'}
        $source=Read-WelaWecUpdateFile $PlanPath
    }
    $output=New-WelaArrivalOutput $OutputPath $source.Path
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaEventLogRecovery';Action=$Action;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$null;NativeWriteAttempted=$false;After=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Scope='One completed profile size/mode operation. Shrinking or changing retention may discard events or stop archival; existing records and sustained retention are not proven. Sysmon excluded.'}
    try{
        $context=Get-WelaEventRecoveryContext;$contextKey=Get-WelaRecoveryKey $context;$sources=Get-WelaEventRecoverySources
        if($Action -eq 'Plan'){
            $definition=Get-WelaEventRecoveryDefinition $JournalPath $OriginalResultsPath $Log
            $observed=Read-WelaEventRecoveryChannel $Log;Assert-WelaEventRecoveryCurrent $definition $observed $null
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaEventLogRecoveryPlan';Definition=$definition;ContextKey=$contextKey;Sources=$sources;Guard=$observed.Guard}
            if((Get-WelaRecoveryKey (Get-WelaEventRecoveryDefinition $JournalPath $OriginalResultsPath $Log)) -cne (Get-WelaRecoveryKey $definition) -or (Get-WelaRecoveryKey (Get-WelaEventRecoveryContext)) -cne $contextKey -or (Get-WelaEventRecoverySources) -cne $sources){throw 'Input, host or code changed while planning.'}
            Assert-WelaEventRecoveryCurrent $definition (Read-WelaEventRecoveryChannel $Log) $plan.Guard
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' ($plan|ConvertTo-Json -Depth 20);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            if($source.Hash -cne $PlanHash){throw 'Reviewed plan hash differs.'}
            $plan=ConvertFrom-WelaArrivalJson $source.Text;Assert-WelaArrivalObject $plan @('SchemaVersion','Kind','Definition','ContextKey','Sources','Guard')
            if(($plan.SchemaVersion -isnot [int] -and $plan.SchemaVersion -isnot [long]) -or $plan.SchemaVersion -ne 1 -or $plan.Kind -cne 'WelaEventLogRecoveryPlan' -or $plan.ContextKey -cne $contextKey -or $plan.Sources -cne $sources){throw 'Reviewed plan schema, context or code differs.'}
            $definition=Get-WelaEventRecoveryDefinition $plan.Definition.Journal.Path $plan.Definition.OriginalResults.Path $plan.Definition.Log
            if((Get-WelaRecoveryKey $definition) -cne (Get-WelaRecoveryKey $plan.Definition)){throw 'Recovery plan differs from independently rebuilt original evidence.'}
            if($definition.RequiresShrinkConsent -and -not $AllowShrink){throw 'Restoring the original smaller buffer requires explicit AllowShrink; existing events may be discarded.'}
            if($definition.RequiresModeConsent -and -not $AllowRetentionChange){throw 'Restoring a different retention mode requires explicit AllowRetentionChange.'}
            Assert-WelaEventRecoveryCurrent $definition (Read-WelaEventRecoveryChannel $definition.Log) $plan.Guard
            $report.PlanHash=$PlanHash;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $source.Text
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'before-restore.json' ([ordered]@{Status='Pending';Definition=$definition;Guard=$plan.Guard;Context=$context;AllowShrink=[bool]$AllowShrink;AllowRetentionChange=[bool]$AllowRetentionChange;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 20)
            if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaEventRecoverySources) -cne $sources -or (Get-WelaRecoveryKey (Get-WelaEventRecoveryContext)) -cne $contextKey -or (Get-WelaRecoveryKey (Get-WelaEventRecoveryDefinition $definition.Journal.Path $definition.OriginalResults.Path $definition.Log)) -cne (Get-WelaRecoveryKey $definition)){throw 'Plan, source, context or original evidence changed immediately before restore.'}
            foreach($artifact in $report.Artifacts){if((Read-WelaWecUpdateFile (Join-Path $output $artifact.Name)).Hash -cne $artifact.Sha256){throw 'Saved recovery evidence changed before write.'}}
            Assert-WelaEventRecoveryCurrent $definition (Read-WelaEventRecoveryChannel $definition.Log) $plan.Guard
            $report.NativeWriteAttempted=$true;Set-WelaEventRecoveryChannel $definition
            $report.After=Read-WelaEventRecoveryChannel $definition.Log
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.json' ($report.After|ConvertTo-Json -Depth 12)
            if((Get-WelaRecoveryKey (Get-WelaEventRecoveryPair $report.After)) -cne (Get-WelaRecoveryKey $definition.RecoverTo) -or (Get-WelaRecoveryKey $report.After.Guard) -cne (Get-WelaRecoveryKey $plan.Guard) -or (Get-WelaRecoveryKey (Get-WelaEventRecoveryContext)) -cne $contextKey -or (Get-WelaEventRecoverySources) -cne $sources -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Restored size/mode or preserved properties, context or sources differ.'}
            $report.Status='RestoredAndVerified';$report.ExitCode=0
        }
    }catch{$report.Status=if($report.NativeWriteAttempted){'RestoreAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24)
    $report
}
