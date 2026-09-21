# Restore one completed canonical channel-settings operation; never replay arbitrary arguments.
function Get-WelaChannelRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Assert-WelaChannelRecoveryText {param($Value,[string[]]$Names) foreach($name in $Names){if($Value.$name -isnot [string]){throw "Missing or mistyped channel recovery text: $name"}}}
function Get-WelaChannelRecoveryDescriptorKey {
    param([string]$Sddl)
    if(-not $Sddl -or $Sddl.Length -gt 131072){throw 'A bounded full channel descriptor is required.'}
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $bytes=New-Object byte[] $descriptor.BinaryLength;$descriptor.GetBinaryForm($bytes,0)
    $round=[Security.AccessControl.RawSecurityDescriptor]::new($descriptor.GetSddlForm('All'))
    $other=New-Object byte[] $round.BinaryLength;$round.GetBinaryForm($other,0)
    if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($other)){throw 'Channel descriptor cannot round-trip losslessly.'}
    [Convert]::ToBase64String($bytes)
}
function Get-WelaChannelRecoveryTuple {
    param($Value)
    [pscustomobject][ordered]@{IsEnabled=$Value.IsEnabled;MaximumSizeInBytes=$Value.MaximumSizeInBytes;LogMode=$Value.LogMode;SecurityDescriptor=$Value.SecurityDescriptor}
}
function Get-WelaChannelRecoveryTupleKey {
    param($Value)
    Get-WelaChannelRecoveryKey ([ordered]@{IsEnabled=$Value.IsEnabled;MaximumSizeInBytes=$Value.MaximumSizeInBytes;LogMode=$Value.LogMode;Descriptor=(Get-WelaChannelRecoveryDescriptorKey $Value.SecurityDescriptor)})
}
function Assert-WelaChannelRecoverySnapshot {
    param($Value,[string]$Channel)
    Assert-WelaArrivalObject $Value @('Name','State','IsEnabled','LogMode','SecurityDescriptor','MaximumSizeInBytes','ProviderNames','MetadataErrors','Error')
    Assert-WelaChannelRecoveryText $Value @('Name','State','LogMode','SecurityDescriptor')
    if($Value.Name -cne $Channel -or $Value.IsEnabled -isnot [bool] -or $Value.State -cne $(if($Value.IsEnabled){'Enabled'}else{'Disabled'}) -or
        ($Value.MaximumSizeInBytes -isnot [int] -and $Value.MaximumSizeInBytes -isnot [long]) -or $Value.MaximumSizeInBytes -lt 1048576 -or $Value.MaximumSizeInBytes -gt 2199023255552 -or
        $Value.LogMode -cnotin @('Circular','Retain','AutoBackup') -or $null -ne $Value.Error -or $null -eq $Value.MetadataErrors -or @($Value.MetadataErrors.PSObject.Properties).Count -ne 0 -or ($Value.ProviderNames -isnot [array] -and $Value.ProviderNames -isnot [string]) -or @($Value.ProviderNames).Count -gt 64){throw 'Original channel snapshot is incomplete, mistyped or unsupported.'}
    foreach($name in $Value.ProviderNames){if($name -isnot [string] -or -not $name -or $name.Length -gt 512){throw 'Invalid original provider name.'}}
    $null=Get-WelaChannelRecoveryDescriptorKey $Value.SecurityDescriptor
}
function Get-WelaChannelRecoverySources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/ChannelRecovery.ps1','scripts/NativeChannelConfiguration.ps1','modules/NativeChannelAccess.psm1','modules/NativeProviders.psm1','modules/EventLogSettings.psm1','config/native_channel_profile.json','scripts/Configuration.ps1','scripts/AuditRecovery.ps1','scripts/ControlApplicability.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1')){
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){foreach($path in @((Join-Path ([Environment]::SystemDirectory) 'wevtutil.exe'),[Diagnostics.Eventing.Reader.EventLogConfiguration].Assembly.Location)){$sources[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}}
    Get-WelaChannelRecoveryKey $sources
}
function Get-WelaChannelRecoveryContext {
    foreach($name in @('EventLog','Winmgmt')){if((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running'){throw 'EventLog and Winmgmt must already be running; recovery starts no services.'}}
    $reader=Get-WelaChannelReader
    if(-not $reader.ElevatedAdministrator){throw 'The actual non-impersonated elevated administrator is required.'}
    [pscustomobject][ordered]@{Host=(Get-WelaRecoveryHost);ReviewedHost=(Get-WelaChannelReadHost);Reader=[ordered]@{Sid=$reader.UserSid;Logon=$reader.AuthenticationId;Groups=$reader.GroupSids};Engine=$PSVersionTable.PSVersion.ToString()}
}
function Read-WelaChannelRecoveryState {
    param([string]$Channel)
    $native=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($Channel)
    try {
        if($native.LogName -cne $Channel -or [string]$native.LogType -cnotin @('Administrative','Operational')){throw 'An exact built-in administrative or operational channel is required.'}
        $guard=[ordered]@{}
        foreach($name in @('LogType','LogIsolation','LogFilePath','OwningProviderName','IsClassicLog','ProviderLevel','ProviderKeywords','ProviderBufferSize','ProviderMinimumNumberOfBuffers','ProviderMaximumNumberOfBuffers','ProviderLatency','ProviderControlGuid')){
            $value=$native.$name;$guard[$name]=if($null -eq $value){$null}else{[string]$value}
        }
        $tuple=[pscustomobject][ordered]@{IsEnabled=[bool]$native.IsEnabled;MaximumSizeInBytes=[long]$native.MaximumSizeInBytes;LogMode=[string]$native.LogMode;SecurityDescriptor=[string]$native.SecurityDescriptor}
        $null=Get-WelaChannelRecoveryDescriptorKey $tuple.SecurityDescriptor
        [pscustomobject][ordered]@{Channel=$native.LogName;Settings=$tuple;Guard=[pscustomobject]$guard}
    }finally{$native.Dispose()}
}
function Get-WelaChannelRecoveryDefinition {
    param([string]$JournalPath,[string]$OriginalResultsPath,[string]$Channel)
    $profile=Get-WelaNativeChannelProfile;$controls=@($profile.controls|Where-Object channel -ceq $Channel)
    if($controls.Count -ne 1){throw 'Select one exact channel from the bundled Microsoft WEF Appendix C profile.'};$control=$controls[0]
    $context=Get-WelaChannelRecoveryContext
    $journal=Read-WelaWecUpdateFile $JournalPath;$file=Read-WelaWecUpdateFile $OriginalResultsPath
    $entries=@($journal.Text -split '\r?\n'|Where-Object {$_ -match '\S'}|ForEach-Object {ConvertFrom-WelaArrivalJson $_})
    if($entries.Count -lt 1 -or $entries.Count -gt 1024){throw 'Expected 1-1024 bounded journal entries.'}
    $result=ConvertFrom-WelaArrivalJson $file.Text
    Assert-WelaChannelRecoveryText $result @('Scope','Action','ChannelProfile')
    if($result.Scope -cne 'native-channel-settings-only' -or $result.Action -cne 'Configure' -or $result.ChannelProfile -cne $profile.id -or $result.DryRun -isnot [bool] -or $result.DryRun -or $result.GrantEventLogReadersRequested -isnot [bool] -or $result.Results -isnot [array] -or $result.Results.Count -gt 64){throw 'Expected original non-dry-run public channel-settings Configure results.'}
    foreach($name in @('ExitCode','Failed','Skipped')){if(($result.$name -isnot [int] -and $result.$name -isnot [long]) -or $result.$name -lt 0){throw 'Original result counters must be nonnegative integers.'}}
    $id='NativeChannel/'+$Channel+'/Settings';$seen=@{}
    foreach($row in $result.Results){Assert-WelaChannelRecoveryText $row @('Id');if($seen.ContainsKey($row.Id)){throw 'Duplicate original result ID.'};$seen[$row.Id]=$true}
    $rows=@($result.Results|Where-Object Id -ceq $id);$matching=@($entries|Where-Object Id -ceq $id)
    if($rows.Count -ne 1 -or $matching.Count -ne 1){throw 'Exactly one completed result and its original journal entry are required.'}
    $row=$rows[0];$entry=$matching[0]
    Assert-WelaChannelRecoveryText $row @('Id','Kind','Status','Diagnostic');Assert-WelaChannelRecoveryText $entry @('ComputerName','Id','Kind')
    if($row.Kind -cne 'NativeChannel' -or $row.Status -cne 'Applied' -or $entry.Kind -cne 'NativeChannel' -or $entry.PSObject.Properties['Phase'] -or
        ($entry.Version -isnot [int] -and $entry.Version -isnot [long]) -or $entry.Version -ne 1 -or $entry.ComputerName -ine $context.Host.Computer){throw 'Only one completed Applied native-channel operation on this named host is recoverable.'}
    if((ConvertTo-WelaArrivalUtc $entry.RecordedUtc) -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Future journal timestamp.'}
    foreach($field in @('Before','Desired','Target')){if((Get-WelaChannelRecoveryKey $entry.$field) -cne (Get-WelaChannelRecoveryKey $row.$field)){throw "Original journal/result $field differs."}}
    Assert-WelaArrivalObject $row.Target @('Channel','Profile');Assert-WelaChannelRecoveryText $row.Target @('Channel','Profile')
    if($row.Target.Channel -cne $Channel -or $row.Target.Profile -cne $profile.id){throw 'Original target does not match the canonical channel/profile.'}
    foreach($state in @($row.Before,$row.After)){Assert-WelaChannelRecoverySnapshot $state $Channel}
    $desired=$row.Desired;Assert-WelaArrivalObject $desired @('IsEnabled','SourceExampleBytes','RoundedMinimumBytes','MaximumSizeInBytes','LogMode','SecurityDescriptor','AccessChangeRequested')
    Assert-WelaChannelRecoveryText $desired @('LogMode','SecurityDescriptor')
    foreach($name in @('SourceExampleBytes','RoundedMinimumBytes','MaximumSizeInBytes')){if($desired.$name -isnot [int] -and $desired.$name -isnot [long]){throw 'Desired byte counts must be integers.'}}
    if($desired.IsEnabled -isnot [bool] -or $desired.AccessChangeRequested -isnot [bool]){throw 'Desired switches must be Booleans.'}
    $minimum=ConvertTo-WelaEventLogBytes $control.sourceExampleBytes
    $acl=$row.Before.SecurityDescriptor;$revoke=$false;$accessRequested=[bool]($result.GrantEventLogReadersRequested -and $control.readerSid)
    if($accessRequested){
        $access=Get-WelaChannelAccessPlan $acl
        if($access.State -cnotin @('GrantPresent','GrantRequired')){throw 'Original descriptor has no reviewed read-grant transformation.'}
        if($access.State -ceq 'GrantRequired'){$acl=$access.ProposedDescriptor;$revoke=$true}
    }
    $expected=[pscustomobject][ordered]@{IsEnabled=$(if($null -eq $control.enabled){$row.Before.IsEnabled}else{$control.enabled});MaximumSizeInBytes=[math]::Max([long]$row.Before.MaximumSizeInBytes,[long]$minimum);LogMode=$row.Before.LogMode;SecurityDescriptor=$acl}
    if($desired.SourceExampleBytes -ne $control.sourceExampleBytes -or $desired.RoundedMinimumBytes -ne $minimum -or $desired.AccessChangeRequested -ne $accessRequested -or
        (Get-WelaChannelRecoveryTupleKey $desired) -cne (Get-WelaChannelRecoveryTupleKey $expected) -or (Get-WelaChannelRecoveryTupleKey $row.After) -cne (Get-WelaChannelRecoveryTupleKey $expected) -or
        (Get-WelaChannelRecoveryKey $row.Before.ProviderNames) -cne (Get-WelaChannelRecoveryKey $row.After.ProviderNames)){throw 'Completed operation includes an unexplained change beyond canonical enable/size/read-grant settings.'}
    $recover=Get-WelaChannelRecoveryTuple $row.Before;$fields=@()
    if($recover.MaximumSizeInBytes -ne $expected.MaximumSizeInBytes){$fields+='MaximumSizeInBytes'}
    if((Get-WelaChannelRecoveryDescriptorKey $recover.SecurityDescriptor) -cne (Get-WelaChannelRecoveryDescriptorKey $expected.SecurityDescriptor)){$fields+='SecurityDescriptor'}
    if($recover.IsEnabled -ne $expected.IsEnabled){$fields+='IsEnabled'}
    if(-not $fields.Count){throw 'No completed channel setting change exists to recover.'}
    [pscustomobject][ordered]@{Channel=$Channel;Profile=$profile.id;Journal=[ordered]@{Path=$journal.Path;Hash=$journal.Hash};OriginalResults=[ordered]@{Path=$file.Path;Hash=$file.Hash};Expected=$expected;RecoverTo=$recover;Fields=$fields
        RequiresShrinkConsent=($recover.MaximumSizeInBytes -lt $expected.MaximumSizeInBytes);RequiresDisableConsent=($expected.IsEnabled -and -not $recover.IsEnabled);RequiresRevokeConsent=$revoke
        HistoricalIdentity='Version1 journals bind historical ComputerName only. Current identity/source guards do not authenticate historical ownership. Recovery requires unchanged recorded post-state; no unrelated ACE is removed.'}
}
function Assert-WelaChannelRecoveryCurrent {
    param($Definition,$Observed,$Expected,$Guard)
    if($Observed.Channel -cne $Definition.Channel -or (Get-WelaChannelRecoveryTupleKey $Observed.Settings) -cne (Get-WelaChannelRecoveryTupleKey $Expected) -or
        ($null -ne $Guard -and (Get-WelaChannelRecoveryKey $Observed.Guard) -cne (Get-WelaChannelRecoveryKey $Guard))){throw 'Current channel settings, descriptor or preserved metadata differ from the reviewed state.'}
}
function Set-WelaChannelRecoveryField {
    param($Definition,[string]$Field)
    $argument=switch -CaseSensitive ($Field){
        'MaximumSizeInBytes' {'/ms:'+$Definition.RecoverTo.MaximumSizeInBytes}
        'SecurityDescriptor' {'/ca:'+$Definition.RecoverTo.SecurityDescriptor}
        'IsEnabled' {'/e:'+$Definition.RecoverTo.IsEnabled.ToString().ToLowerInvariant()}
        default {throw 'Unsupported channel recovery field.'}
    }
    $null=Invoke-WelaNative -FilePath (Join-Path ([Environment]::SystemDirectory) 'wevtutil.exe') -Arguments @('sl',$Definition.Channel,$argument)
}
function Invoke-WelaChannelRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$JournalPath,[string]$OriginalResultsPath,[string]$Channel,[string]$PlanPath,[string]$PlanHash,[Parameter(Mandatory)][string]$OutputPath,[switch]$AllowShrink,[switch]$AllowDisable,[switch]$AllowRevoke)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $JournalPath -or -not $OriginalResultsPath -or -not $Channel -or $PlanPath -or $PlanHash -or $AllowShrink -or $AllowDisable -or $AllowRevoke){throw 'Plan requires original journal/results, exact channel and new output only.'}
        $source=Read-WelaWecUpdateFile $JournalPath
    }else{
        if(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or $JournalPath -or $OriginalResultsPath -or $Channel){throw 'Restore requires reviewed plan/hash, new output and applicable explicit consent only.'}
        $source=Read-WelaWecUpdateFile $PlanPath
    }
    $output=New-WelaArrivalOutput $OutputPath $source.Path
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaChannelRecovery';Action=$Action;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$null;NativeWriteAttempted=$false;ConfirmedFields=@();After=$null;Artifacts=@();Diagnostic='';ReadyRuleCredit=0;Scope='One completed channel-settings operation. Shrink can discard events; disable stops generation; read-grant removal can interrupt readers. No automatic rollback, event/retention/forwarding proof or Sigma credit. Sysmon excluded.'}
    try {
        $context=Get-WelaChannelRecoveryContext;$contextKey=Get-WelaChannelRecoveryKey $context;$sources=Get-WelaChannelRecoverySources
        if($Action -eq 'Plan'){
            $definition=Get-WelaChannelRecoveryDefinition $JournalPath $OriginalResultsPath $Channel
            $observed=Read-WelaChannelRecoveryState $Channel;Assert-WelaChannelRecoveryCurrent $definition $observed $definition.Expected $null
            $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaChannelRecoveryPlan';Definition=$definition;ContextKey=$contextKey;Sources=$sources;Guard=$observed.Guard}
        }else{
            if($source.Hash -cne $PlanHash){throw 'Reviewed plan hash differs.'}
            $plan=ConvertFrom-WelaArrivalJson $source.Text;Assert-WelaArrivalObject $plan @('SchemaVersion','Kind','Definition','ContextKey','Sources','Guard');Assert-WelaChannelRecoveryText $plan @('Kind','ContextKey','Sources')
            if(($plan.SchemaVersion -isnot [int] -and $plan.SchemaVersion -isnot [long]) -or $plan.SchemaVersion -ne 1 -or $plan.Kind -cne 'WelaChannelRecoveryPlan' -or $plan.ContextKey -cne $contextKey -or $plan.Sources -cne $sources){throw 'Reviewed plan schema, context or sources differ.'}
            $definition=Get-WelaChannelRecoveryDefinition $plan.Definition.Journal.Path $plan.Definition.OriginalResults.Path $plan.Definition.Channel
            if((Get-WelaChannelRecoveryKey $definition) -cne (Get-WelaChannelRecoveryKey $plan.Definition)){throw 'Plan differs from independently rebuilt original evidence.'}
            if($definition.RequiresShrinkConsent -and -not $AllowShrink){throw 'Explicit AllowShrink is required; shrinking can discard events.'}
            if($definition.RequiresDisableConsent -and -not $AllowDisable){throw 'Explicit AllowDisable is required; disabling stops channel generation.'}
            if($definition.RequiresRevokeConsent -and -not $AllowRevoke){throw 'Explicit AllowRevoke is required; removing the added read ACE can interrupt readers.'}
        }
        if((Get-WelaChannelRecoveryKey (Get-WelaChannelRecoveryDefinition $definition.Journal.Path $definition.OriginalResults.Path $definition.Channel)) -cne (Get-WelaChannelRecoveryKey $definition) -or (Get-WelaChannelRecoveryKey (Get-WelaChannelRecoveryContext)) -cne $contextKey -or (Get-WelaChannelRecoverySources) -cne $sources){throw 'Original evidence, actual host/operator or source changed.'}
        Assert-WelaChannelRecoveryCurrent $definition (Read-WelaChannelRecoveryState $definition.Channel) $definition.Expected $plan.Guard
        if($Action -eq 'Plan'){
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' ($plan|ConvertTo-Json -Depth 24);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256;$report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            $report.PlanHash=$PlanHash;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $source.Text
            $expected=Get-WelaChannelRecoveryTuple $definition.Expected;$token=Get-WelaChannelRecoveryKey (Get-WelaChannelReader);$index=0
            foreach($field in $definition.Fields){
                $index++;$pendingName=('pending-{0}-{1}.json' -f $index,$field)
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output $pendingName ([ordered]@{Status='Pending';Field=$field;Expected=$expected;RecoverTo=$definition.RecoverTo;Guard=$plan.Guard;PlanHash=$PlanHash;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 16)
                if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash -or (Get-WelaChannelRecoverySources) -cne $sources -or (Read-WelaWecUpdateFile $definition.Journal.Path).Hash -cne $definition.Journal.Hash -or (Read-WelaWecUpdateFile $definition.OriginalResults.Path).Hash -cne $definition.OriginalResults.Hash){throw 'Reviewed plan, sources or original evidence changed before write.'}
                foreach($artifact in $report.Artifacts){if((Read-WelaWecUpdateFile (Join-Path $output $artifact.Name)).Hash -cne $artifact.Sha256){throw 'Saved recovery evidence changed before write.'}}
                Assert-WelaChannelRecoveryCurrent $definition (Read-WelaChannelRecoveryState $definition.Channel) $expected $plan.Guard
                if((Get-WelaChannelRecoveryKey (Get-WelaChannelReader)) -cne $token){throw 'Actual current token changed before native write.'}
                $report.NativeWriteAttempted=$true;Set-WelaChannelRecoveryField $definition $field
                $expected.$field=$definition.RecoverTo.$field
                $report.After=Read-WelaChannelRecoveryState $definition.Channel
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output ('observed-'+$index+'.json') ($report.After|ConvertTo-Json -Depth 16)
                Assert-WelaChannelRecoveryCurrent $definition $report.After $expected $plan.Guard
                if((Get-WelaChannelRecoveryKey (Get-WelaChannelReader)) -cne $token -or (Get-WelaChannelRecoverySources) -cne $sources){throw 'Actual token or source changed during native write/readback.'}
                $report.Artifacts+=Write-WelaWecUpdateArtifact $output ('confirmed-'+$index+'.json') ([ordered]@{Status='Confirmed';Field=$field;After=$report.After;RecordedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 16)
                $report.ConfirmedFields+=$field
            }
            Assert-WelaChannelRecoveryCurrent $definition (Read-WelaChannelRecoveryState $definition.Channel) $definition.RecoverTo $plan.Guard
            if((Get-WelaChannelRecoveryKey (Get-WelaChannelReader)) -cne $token){throw 'Actual token changed before final confirmation.'}
            if((Get-WelaChannelRecoveryKey (Get-WelaChannelRecoveryContext)) -cne $contextKey -or (Get-WelaChannelRecoverySources) -cne $sources -or (Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Final host/operator, source or reviewed plan changed.'}
            if((Read-WelaWecUpdateFile $definition.Journal.Path).Hash -cne $definition.Journal.Hash -or (Read-WelaWecUpdateFile $definition.OriginalResults.Path).Hash -cne $definition.OriginalResults.Hash){throw 'Original historical evidence changed during restoration.'}
            foreach($artifact in $report.Artifacts){if((Read-WelaWecUpdateFile (Join-Path $output $artifact.Name)).Hash -cne $artifact.Sha256){throw 'Saved recovery evidence changed during restoration.'}}
            $report.Status='RestoredAndVerified';$report.ExitCode=0
        }
    }catch{
        $report.Status=if($report.NativeWriteAttempted){'RestoreAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message
        if($report.NativeWriteAttempted){try{$report.After=Read-WelaChannelRecoveryState $definition.Channel;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'failure-state.json' ($report.After|ConvertTo-Json -Depth 16)}catch{}}
    }
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' ($report|ConvertTo-Json -Depth 24);$report
}
