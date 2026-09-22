# Reviewed removal of one proven, parent-only WMI success audit ACE.
function Get-WelaWmiRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 40 -Compress}
function Assert-WelaWmiRecoveryText {param($Value,[string[]]$Fields) foreach($field in $Fields){if($Value.$field -isnot [string]){throw "Missing or mistyped WMI recovery text: $field"}}}
function Assert-WelaWmiRecoveryInteger {param($Value) if($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint32]){throw 'WMI recovery requires an integer.'}}
function Get-WelaWmiRecoverySources {
    $sources=[ordered]@{}
    foreach($path in @('WELA.ps1','scripts/WmiSaclRecovery.ps1','scripts/WmiNamespaceAuditing.ps1','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/Configuration.ps1','scripts/ChannelRead.ps1','scripts/ChannelReadNative.cs','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','scripts/ControlApplicability.ps1','modules/AuditProfiles.psm1','scripts/CustomAuditProfiles.ps1','config/audit_profiles.json')){
        $sources[$path]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    if(Test-Path -LiteralPath (Join-Path $script:ScriptRoot 'scripts/WmiNamespaceDescendants.ps1')){$sources['scripts/WmiNamespaceDescendants.ps1']=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot 'scripts/WmiNamespaceDescendants.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()}
    [pscustomobject]$sources
}
function Get-WelaWmiRecoveryTokenKey {Initialize-WelaWmiProbeNative;Get-WelaWmiProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot())}
function Get-WelaWmiRecoveryContext {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'WMI SACL recovery requires native 64-bit Windows.'}
    $services=[ordered]@{}
    foreach($name in @('Winmgmt','EventLog')){if((Get-Service $name -ErrorAction Stop).Status -ne 'Running'){throw 'Winmgmt and EventLog must already be running; recovery starts no services.'};$services[$name]='Running'}
    $hostState=Get-WelaChannelReadHost
    $machine=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid;$guid=[guid]::Empty
    if(-not $machine.ValueExists -or $machine.Type -cne 'String' -or -not [guid]::TryParse([string]$machine.Value,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Actual machine identity is unavailable.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'WMI SACL recovery requires an elevated operator.'}}finally{$identity.Dispose()}
    $masks=Get-WelaEffectiveAuditPolicy;$orderedMasks=[ordered]@{};foreach($id in @($masks.Keys|Sort-Object)){$orderedMasks[$id]=$masks[$id]}
    if($orderedMasks.Count -ne 59){throw 'Complete 59-subcategory audit policy observation is required.'}
    $engine=(Get-Process -Id $PID -ErrorAction Stop).Path
    [pscustomobject][ordered]@{Host=$hostState;MachineGuid=$guid.ToString();Services=[pscustomobject]$services;AuditMasks=[pscustomobject]$orderedMasks;Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Engine=$engine;EngineHash=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant();TokenKey=(Get-WelaWmiRecoveryTokenKey)}
}
function ConvertFrom-WelaWmiRecoveryDescriptor {
    param($Snapshot,[string]$Namespace)
    Assert-WelaArrivalObject $Snapshot @('Namespace','DescriptorJson','DescriptorMof','SaclReadPrivilege')
    Assert-WelaWmiRecoveryText $Snapshot @('Namespace','DescriptorJson','DescriptorMof','SaclReadPrivilege')
    if($Snapshot.Namespace -cne $Namespace -or -not $Snapshot.DescriptorMof -or $Snapshot.DescriptorMof.Length -gt 1048576 -or -not $Snapshot.DescriptorJson -or $Snapshot.DescriptorJson.Length -gt 1048576 -or $Snapshot.SaclReadPrivilege -cne 'SeSecurityPrivilege enabled'){throw 'A complete original privileged namespace snapshot is required.'}
    $value=ConvertFrom-WelaArrivalJson $Snapshot.DescriptorJson
    if($value -isnot [pscustomobject] -or @($value.PSObject.Properties).Count -gt 32){throw 'Invalid namespace descriptor.'}
    foreach($name in @('ControlFlags','Owner','Group','DACL','SACL')){if(-not $value.PSObject.Properties[$name]){throw 'Incomplete namespace descriptor fields.'}}
    Assert-WelaWmiRecoveryInteger $value.ControlFlags
    if($value.ControlFlags -lt 0 -or $value.ControlFlags -gt 65535 -or ($value.ControlFlags -band 768) -ne 0){throw 'Unknown or propagation-request descriptor controls require manual recovery.'}
    foreach($name in @('DACL','SACL')){if($null -ne $value.$name -and ($value.$name -isnot [array] -or $value.$name.Count -gt 1024)){throw 'Descriptor ACL must be a bounded array or null.'}}
    if($null -ne $value.SACL){foreach($ace in $value.SACL){if($null -eq $ace -or $ace -isnot [pscustomobject]){throw 'Null or mistyped SACL entries require manual recovery.'}}}
    $value
}
function Get-WelaWmiRecoveryDescriptorOutsideKey {
    param($Descriptor,[switch]$Addition)
    $outside=[ordered]@{}
    foreach($p in $Descriptor.PSObject.Properties){if($p.Name -ceq 'SACL'){continue};$outside[$p.Name]=if($p.Name -ceq 'ControlFlags' -and $Addition){[uint32]$p.Value -bor 16}else{$p.Value}}
    Get-WelaWmiRecoveryKey $outside
}
function Get-WelaWmiRecoveryAddition {
    param($Before,$After,[array]$Definitions)
    if((Get-WelaWmiRecoveryDescriptorOutsideKey $Before -Addition) -cne (Get-WelaWmiRecoveryDescriptorOutsideKey $After)){throw 'Original operation changed descriptor fields outside the permitted SACL addition.'}
    $missing=@(Get-WelaWmiMissingAces $Before $Definitions)
    if($missing.Count -ne 1 -or $missing[0].AceFlags -ne 64 -or $missing[0].AceType -ne 2){throw 'Exactly one missing parent-only ordinary success audit ACE is recoverable.'}
    if(@(Get-WelaWmiMissingAces $After $Definitions).Count){throw 'Completed descriptor lacks a requested audit ACE.'}
    $remaining=New-Object 'System.Collections.Generic.List[string]'
    foreach($ace in @($After.SACL)){$remaining.Add((Get-WelaWmiRecoveryKey $ace))}
    foreach($ace in @($Before.SACL|Where-Object {$null -ne $_})){if(-not $remaining.Remove((Get-WelaWmiRecoveryKey $ace))){throw 'An original SACL entry was removed or modified.'}}
    if($remaining.Count -ne 1){throw 'Completed operation must add exactly one unchanged explicit audit ACE.'}
    $added=ConvertFrom-WelaArrivalJson $remaining[0]
    if(-not (Test-WelaWmiAceMatch $added $missing[0]) -or @($Before.SACL|Where-Object {(Get-WelaWmiRecoveryKey $_) -ceq $remaining[0]}).Count -ne 0 -or @($After.SACL|Where-Object {(Get-WelaWmiRecoveryKey $_) -ceq $remaining[0]}).Count -ne 1){throw 'Added ACE identity or multiplicity is ambiguous.'}
    foreach($name in @('AceType','AceFlags','AccessMask')){Assert-WelaWmiRecoveryInteger $added.$name}
    foreach($p in $added.PSObject.Properties){if($p.Name -cnotin @('AccessMask','AceFlags','AceType','GuidObjectType','GuidInheritedObjectType','Trustee','TIME_CREATED')){throw 'Unknown added ACE fields require manual recovery.'}}
    if($added.Trustee -isnot [pscustomobject] -or $added.AceFlags -ne 64 -or $added.AceType -ne 2 -or $added.AccessMask -lt 1 -or $added.GuidObjectType -or $added.GuidInheritedObjectType -or $added.TIME_CREATED){throw 'Only one ordinary, explicit, parent-only audit addition is supported.'}
    $added
}
function Get-WelaWmiRecoveryExpectedDescriptor {
    param($Current,[string]$AddedAceJson)
    $target=ConvertFrom-WelaArrivalJson (Get-WelaWmiRecoveryKey $Current);$indices=@()
    for($i=0;$i -lt @($Current.SACL).Count;$i++){if((Get-WelaWmiRecoveryKey $Current.SACL[$i]) -ceq $AddedAceJson){$indices+=,$i}}
    if($indices.Count -ne 1){throw 'Current SACL must contain the exact added ACE once.'}
    $target.SACL=@(for($i=0;$i -lt $Current.SACL.Count;$i++){if($i -ne $indices[0]){$Current.SACL[$i]}})
    $target
}
function Assert-WelaWmiRecoveryRemoved {
    param($Expected,$Actual)
    if((Get-WelaWmiRecoveryDescriptorOutsideKey $Actual) -cne (Get-WelaWmiRecoveryDescriptorOutsideKey $Expected)){throw 'WMI recovery changed a preserved descriptor property.'}
    # A provider may represent a newly empty present SACL as null. Do not claim
    # historical descriptor equality; null sent to SetSecurityDescriptor is never used.
    if(@($Expected.SACL).Count -eq 0 -and $null -eq $Actual.SACL){return}
    if((Get-WelaWmiRecoveryKey $Actual.SACL) -cne (Get-WelaWmiRecoveryKey $Expected.SACL)){throw 'WMI recovery failed to remove only the proven ACE while preserving all remaining ACEs and their order.'}
}
function New-WelaWmiRecoveryPlan {
    param([string]$JournalPath,[string]$OriginalResultsPath,[string]$Namespace)
    Assert-WelaWmiProbeNamespace $Namespace
    $definitions=@(Get-WelaWmiAuditDefinitions -Namespace @($Namespace))
    if(-not $definitions.Count -or @($definitions|Where-Object {$_.AceFlags -ne 64 -or $_.Namespace -cne $Namespace}).Count){throw 'Select one exact canonical parent-only namespace.'}
    $context=Get-WelaWmiRecoveryContext;$sources=Get-WelaWmiRecoverySources
    $journal=Read-WelaWecUpdateFile $JournalPath;$file=Read-WelaWecUpdateFile $OriginalResultsPath
    if($journal.Path -ieq $file.Path){throw 'Original journal and completed results must be distinct files.'}
    $lines=@($journal.Text -split '\r?\n'|Where-Object {$_ -match '\S'})
    if($lines.Count -lt 1 -or $lines.Count -gt 128){throw 'Expected a bounded original configuration journal.'}
    $entries=@($lines|ForEach-Object {ConvertFrom-WelaArrivalJson $_});$result=ConvertFrom-WelaArrivalJson $file.Text
    Assert-WelaWmiRecoveryText $result @('Scope','BackupPath')
    foreach($field in @('ExitCode','Failed','Skipped')){Assert-WelaWmiRecoveryInteger $result.$field}
    if($result.Scope -cne 'wmi-namespace-sacl-only' -or $result.ExitCode -ne 0 -or $result.Failed -ne 0 -or $result.Skipped -ne 0 -or $result.DryRun -isnot [bool] -or $result.DryRun -or $result.Results -isnot [array] -or $result.Results.Count -lt 1 -or $result.Results.Count -gt 5){throw 'Require successful completed, non-dry-run WMI-only configuration results.'}
    if((Resolve-WelaArrivalPath (Join-Path $result.BackupPath 'before.jsonl')) -ine $journal.Path){throw 'Journal path differs from the recorded backup directory.'}
    $id='WmiNamespace/'+$Namespace+'/SACL';$seen=@{}
    foreach($row in $result.Results){Assert-WelaWmiRecoveryText $row @('Id');if($seen.ContainsKey($row.Id)){throw 'Duplicate original result ID.'};$seen[$row.Id]=$true}
    $rows=@($result.Results|Where-Object Id -ceq $id);$matching=@($entries|Where-Object Id -ceq $id)
    if($rows.Count -ne 1 -or $matching.Count -ne 1){throw 'Exactly one completed Applied namespace result and original journal entry are required.'}
    $row=$rows[0];$entry=$matching[0]
    Assert-WelaArrivalObject $row @('Id','Kind','Target','Desired','Before','After','Status','Diagnostic')
    Assert-WelaArrivalObject $entry @('Version','ComputerName','RecordedUtc','Id','Kind','Target','Before','Desired')
    Assert-WelaWmiRecoveryText $row @('Id','Kind','Status','Diagnostic');Assert-WelaWmiRecoveryText $entry @('ComputerName','RecordedUtc','Id','Kind');Assert-WelaWmiRecoveryInteger $entry.Version
    if($row.Kind -cne 'WmiNamespaceSacl' -or $row.Status -cne 'Applied' -or $entry.Kind -cne 'WmiNamespaceSacl' -or $entry.Version -ne 1 -or $entry.ComputerName -ine $context.Host.Computer -or (ConvertTo-WelaArrivalUtc $entry.RecordedUtc) -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Original operation is not a completed Applied namespace addition on this host.'}
    foreach($field in @('Before','Desired','Target')){if((Get-WelaWmiRecoveryKey $entry.$field) -cne (Get-WelaWmiRecoveryKey $row.$field)){throw 'Original journal and result evidence disagree.'}}
    Assert-WelaArrivalObject $row.Target @('Namespace','Computer','Operation');Assert-WelaWmiRecoveryText $row.Target @('Namespace','Computer','Operation')
    if($row.Target.Namespace -cne $Namespace -or $row.Target.Computer -cne 'Local' -or $row.Target.Operation -cne 'Append audit ACEs only' -or $row.Desired -isnot [array] -or (Get-WelaWmiRecoveryKey $row.Desired) -cne (Get-WelaWmiRecoveryKey $definitions)){throw 'Original target/definitions differ from the current canonical parent-only profile.'}
    $before=ConvertFrom-WelaWmiRecoveryDescriptor $row.Before $Namespace;$after=ConvertFrom-WelaWmiRecoveryDescriptor $row.After $Namespace
    $added=Get-WelaWmiRecoveryAddition $before $after $definitions
    $current=Get-WelaWmiNamespaceSnapshot $Namespace;$currentData=ConvertFrom-WelaWmiRecoveryDescriptor $current $Namespace
    if((Get-WelaWmiRecoveryKey $currentData) -cne (Get-WelaWmiRecoveryKey $after)){throw 'Current full namespace descriptor differs from completed After; manual assessment is required.'}
    $plan=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWmiSaclRecoveryPlan';Namespace=$Namespace;Context=$context;Sources=$sources;Journal=[pscustomobject]@{Path=$journal.Path;Sha256=$journal.Hash};OriginalResults=[pscustomobject]@{Path=$file.Path;Sha256=$file.Hash};BeforeAddition=$row.Before;Expected=$current;AddedAce=$added;RequiresAuditReductionConsent=$true;HistoricalBinding='Version1 journals record ComputerName, not durable namespace identity, historical operator or source hashes. Hashes do not authenticate an untrusted receipt author. Identical namespace recreation and concurrent descriptor writes are not excluded.';Outcome='Remove one proven explicit parent-only success audit ACE. Preserve every remaining descriptor property and ACE; empty present SACL representation can differ from the pre-addition descriptor.';ReadyRuleCredit=0}
    Assert-WelaWmiRecoveryBindings $plan
    $plan
}
function Assert-WelaWmiRecoveryBindings {
    param($Plan)
    if((Get-WelaWmiRecoveryKey (Get-WelaWmiRecoveryContext)) -cne (Get-WelaWmiRecoveryKey $Plan.Context) -or (Get-WelaWmiRecoveryKey (Get-WelaWmiRecoverySources)) -cne (Get-WelaWmiRecoveryKey $Plan.Sources)){throw 'Current host, logon, token, policy, service or installed source changed.'}
    foreach($inputFile in @($Plan.Journal,$Plan.OriginalResults)){if((Read-WelaWecUpdateFile $inputFile.Path).Hash -cne $inputFile.Sha256){throw 'Original recovery evidence changed.'}}
}
function Remove-WelaWmiRecoveryAce {
    param($Plan,$State)
    Initialize-WelaWmiInterop
    $token=Get-WelaWmiRecoveryTokenKey;$privilege=$null;$connection=$null;$updated=$null
    try {
        $privilege=New-Object Wela.WmiSecurityPrivilege;$connection=New-WelaWmiConnection $Plan.Namespace
        $descriptor=Get-WelaWmiNativeDescriptor $connection;$data=ConvertTo-WelaWmiData $descriptor
        if((Get-WelaWmiRecoveryKey $data) -cne (Get-WelaWmiRecoveryKey (ConvertFrom-WelaArrivalJson $Plan.Expected.DescriptorJson))){throw 'Held native namespace descriptor changed immediately before removal.'}
        $aceKey=Get-WelaWmiRecoveryKey $Plan.AddedAce;$expected=Get-WelaWmiRecoveryExpectedDescriptor $data $aceKey
        $remaining=@($descriptor.SACL|Where-Object {(Get-WelaWmiRecoveryKey (ConvertTo-WelaWmiData $_)) -cne $aceKey})
        $updated=$descriptor.Clone();$updated.SACL=[System.Management.ManagementBaseObject[]]$remaining
        if($null -eq $updated.SACL){throw 'Native provider did not retain the explicit empty SACL array; null cannot remove an ACE.'}
        $updated.DACL=$null;$updated.Owner=$null;$updated.Group=$null
        $updated.ControlFlags=([uint32]$descriptor.ControlFlags -band [uint32]4294967291) -bor [uint32]16
        $parameters=$connection.GetMethodParameters('SetSecurityDescriptor');$parameters.Descriptor=$updated
        $State.WriteAttempted=$true
        $response=$connection.InvokeMethod('SetSecurityDescriptor',$parameters,$null)
        Assert-WelaWmiReturnCode $response 'SetSecurityDescriptor'
        $readback=Get-WelaWmiNativeDescriptor $connection;$after=ConvertTo-WelaWmiData $readback
        $State.After=[pscustomobject]@{Namespace=$Plan.Namespace;DescriptorJson=(ConvertTo-WelaWmiJson $after);DescriptorMof=$readback.GetText([System.Management.TextFormat]::Mof);SaclReadPrivilege='SeSecurityPrivilege enabled'}
        Assert-WelaWmiRecoveryRemoved $expected $after
    }finally{
        try{if($updated){$updated.Dispose()};if($connection){$connection.Dispose()}}finally{if($privilege){$privilege.Dispose()}}
        if((Get-WelaWmiRecoveryTokenKey) -cne $token){throw 'Native recovery did not preserve the full original token authorization and privileges.'}
    }
}
function Invoke-WelaWmiSaclRecovery {
    param([ValidateSet('Plan','Recover')][string]$Action='Plan',[string]$JournalPath,[string]$OriginalResultsPath,[string]$Namespace,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$AllowAuditReduction)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $JournalPath -or -not $OriginalResultsPath -or -not $Namespace -or -not $OutputPath -or $PlanPath -or $PlanHash -or $AllowAuditReduction){throw 'Plan requires original journal/results, exact namespace and a new output directory only.'}
    }elseif(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or -not $OutputPath -or $JournalPath -or $OriginalResultsPath -or $Namespace){throw 'Recover requires only reviewed plan/hash, a new output directory and explicit audit-reduction consent.'}
    $output=New-WelaArrivalOutput $OutputPath $script:ScriptRoot
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaWmiSaclRecovery';Action=$Action;Status='Refused';ExitCode=1;PlanHash=$null;WriteAttempted=$false;Before=$null;After=$null;HistoricalDescriptorMatches=$false;Artifacts=@();OutputPath=$output;Diagnostic='';ReadyRuleCredit=0;PolicyChanges=0;Scope='One proven explicit parent-only WMI success audit ACE. No whole-descriptor rollback, durable historical namespace identity, descendant propagation, event or Sigma claim.'}
    $state=[pscustomobject]@{WriteAttempted=$false;After=$null}
    try {
        if($Action -eq 'Plan'){
            $plan=New-WelaWmiRecoveryPlan $JournalPath $OriginalResultsPath $Namespace
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' (Get-WelaWmiRecoveryKey $plan);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256
            Assert-WelaWmiRecoveryBindings $plan
            if((Get-WelaWmiNamespaceSnapshot $plan.Namespace).DescriptorJson -cne $plan.Expected.DescriptorJson){throw 'Namespace descriptor changed while saving the review plan.'}
            $report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            $inputFile=Read-WelaWecUpdateFile $PlanPath
            if($inputFile.Hash -cne $PlanHash){throw 'Reviewed plan hash differs.'}
            $plan=ConvertFrom-WelaArrivalJson $inputFile.Text
            Assert-WelaWmiRecoveryText $plan @('Kind','Namespace')
            if($plan.Kind -cne 'WelaWmiSaclRecoveryPlan'){throw 'Unsupported WMI recovery plan kind.'}
            $rebuilt=New-WelaWmiRecoveryPlan $plan.Journal.Path $plan.OriginalResults.Path $plan.Namespace
            if((Get-WelaWmiRecoveryKey $plan) -cne (Get-WelaWmiRecoveryKey $rebuilt)){throw 'Reviewed recovery plan is stale or modified.'}
            if(-not $AllowAuditReduction){throw 'Recover requires explicit AllowAuditReduction; the proven audit ACE will be removed.'}
            $report.PlanHash=$PlanHash;$report.Before=$plan.Expected
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' $inputFile.Text
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'pending.json' (Get-WelaWmiRecoveryKey ([pscustomobject]@{Kind='WelaWmiSaclRecoveryIntent';State='Pending';PlanHash=$PlanHash;Namespace=$plan.Namespace;Expected=$plan.Expected;RemoveAce=$plan.AddedAce;AllowAuditReduction=[bool]$AllowAuditReduction;RecordedUtc=[DateTime]::UtcNow.ToString('o')}))
            Assert-WelaWmiRecoveryBindings $plan
            if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Reviewed plan changed before native removal.'}
            foreach($artifact in $report.Artifacts){if((Read-WelaWecUpdateFile (Join-Path $output $artifact.Name)).Hash -cne $artifact.Sha256){throw 'Saved recovery evidence changed before native removal.'}}
            Remove-WelaWmiRecoveryAce $plan $state
            $report.After=$state.After
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.json' (Get-WelaWmiRecoveryKey $state.After)
            Assert-WelaWmiRecoveryBindings $plan
            $current=Get-WelaWmiNamespaceSnapshot $plan.Namespace
            if($current.DescriptorJson -cne $state.After.DescriptorJson){throw 'Full namespace descriptor changed after native readback.'}
            $expected=Get-WelaWmiRecoveryExpectedDescriptor (ConvertFrom-WelaArrivalJson $plan.Expected.DescriptorJson) (Get-WelaWmiRecoveryKey $plan.AddedAce)
            Assert-WelaWmiRecoveryRemoved $expected (ConvertFrom-WelaWmiRecoveryDescriptor $current $plan.Namespace)
            if((Read-WelaWecUpdateFile $PlanPath).Hash -cne $PlanHash){throw 'Reviewed plan changed after native removal.'}
            foreach($artifact in $report.Artifacts){if((Read-WelaWecUpdateFile (Join-Path $output $artifact.Name)).Hash -cne $artifact.Sha256){throw 'Saved recovery evidence changed after native removal.'}}
            $report.HistoricalDescriptorMatches=$current.DescriptorJson -ceq $plan.BeforeAddition.DescriptorJson
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'confirmed.json' (Get-WelaWmiRecoveryKey ([pscustomobject]@{Kind='WelaWmiSaclRecoveryConfirmation';State='Confirmed';PlanHash=$PlanHash;After=$current;RecordedUtc=[DateTime]::UtcNow.ToString('o')}))
            $report.Status='AddedAceRemoved';$report.ExitCode=0
        }
    }catch{
        $report.Status=if($state.WriteAttempted){'WriteAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message
        if($state.WriteAttempted){try{$state.After=Get-WelaWmiNamespaceSnapshot $plan.Namespace;$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'failure-state.json' (Get-WelaWmiRecoveryKey $state.After)}catch{$report.Diagnostic+=' Final failure-state read also failed: '+$_.Exception.Message}}
    }
    $report.WriteAttempted=$state.WriteAttempted;if($null -ne $state.After){$report.After=$state.After}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' (Get-WelaWmiRecoveryKey $report)
    $report
}
