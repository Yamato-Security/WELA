# One proven selected-root audit ACE, only with empty historical/current descendants.
function Get-WelaRegistryRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 32 -Compress}
function Assert-WelaRegistryRecoveryText {param($Value,[string[]]$Names) foreach($name in $Names){if($Value.$name -isnot [string]){throw ('Missing or mistyped registry recovery text: '+$name)}}}
function Assert-WelaRegistryRecoveryNumber {param($Value) if($Value -isnot [int] -and $Value -isnot [long]){throw 'Registry recovery requires an integer.'}}
function Initialize-WelaRegistryRecoveryNative {
    $bytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'RegistrySaclRecoveryNative.cs'));$hash=Get-WelaArrivalHash $bytes
    if(-not ('Wela.RegistrySaclRecovery.Descriptor' -as [type])){
        $source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff);$marker='__WELA_REGISTRY_SACL_RECOVERY_SOURCE_SHA256__'
        if(($source.Split(@($marker),[StringSplitOptions]::None)).Count -ne 2){throw 'Unexpected native registry recovery source binding.'}
        Add-Type -TypeDefinition $source.Replace($marker,$hash) -ErrorAction Stop
    }
    if([Wela.RegistrySaclRecovery.Descriptor]::SourceSha256 -cne $hash){throw 'Loaded registry recovery code differs; start a fresh PowerShell process.'}
}
function Get-WelaRegistryRecoverySources {
    $sources=[ordered]@{}
    foreach($name in @('WELA.ps1','scripts/RegistrySaclRecovery.ps1','scripts/RegistrySaclRecoveryNative.cs','scripts/SelectedSaclConfiguration.ps1','scripts/SelectedSaclNative.cs','scripts/SelectedSaclDescendants.ps1','scripts/TargetedSaclPlanning.ps1','scripts/Configuration.ps1','scripts/ControlApplicability.ps1','scripts/CustomAuditProfiles.ps1','scripts/AuditRecovery.ps1','scripts/EvtxRecovery.ps1','scripts/WefArrival.ps1','scripts/WecUpdate.ps1','modules/AuditProfiles.psm1','modules/AuditCatalog.psm1','modules/NativeProviders.psm1','config/audit_profiles.json','config/audit_sacl_targets.json','config/control_applicability.json','config/baselines.json')){
        $sources[$name]=(Get-FileHash -LiteralPath (Join-Path $script:ScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Assert-WelaRegistryRecoverySources {
    param($Sources)
    if($Sources -isnot [array]){throw 'Original source inventory must be an array.'}
    foreach($entry in $Sources){Assert-WelaEvtxObject $entry @('Path','Sha256');Assert-WelaRegistryRecoveryText $entry @('Path','Sha256');if($entry.Sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Original source fingerprint is malformed.'}}
    Assert-WelaSelectedSaclSources $Sources
}
function Get-WelaRegistryRecoveryContext {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Registry SACL recovery requires native 64-bit Windows.'}
    foreach($name in @('Winmgmt','EventLog')){if((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running'){throw 'Native observation services must already be running.'}}
    Initialize-WelaRegistryRecoveryNative
    $token=[Wela.RegistrySaclRecovery.TokenReader]::Snapshot();$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Registry SACL recovery requires an elevated operator.'}}finally{$identity.Dispose()}
    $actualMasks=Get-WelaEffectiveAuditPolicy;$masks=[ordered]@{};foreach($id in @($actualMasks.Keys|Sort-Object)){$masks[$id]=$actualMasks[$id]}
    [pscustomobject][ordered]@{Host=(Get-WelaRecoveryHost);Selected=(Get-WelaSelectedSaclContext);Token=$token;AuditMasks=$masks;Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy)}
}
function Read-WelaRegistryRecoveryInput {
    param([string]$Path)
    $file=Read-WelaWecUpdateFile $Path 4194304
    if(-not $file.Text){throw 'Original recovery evidence is empty.'}
    [pscustomobject]@{Path=$file.Path;Sha256=$file.Hash;Data=(ConvertFrom-WelaEvtxJson $file.Text)}
}
function Assert-WelaRegistryRecoverySnapshot {
    param($Snapshot,$Definition)
    Assert-WelaEvtxObject $Snapshot @('Path','Kind','Identity','IsDirectory','DescriptorBase64','Owner','Group','DaclBase64','ControlFlags','SecurityInformation','DescriptorScope','Aces')
    Assert-WelaRegistryRecoveryText $Snapshot @('Path','Kind','Identity','DescriptorBase64','DescriptorScope')
    $path=Resolve-WelaSelectedSaclNativePath $Definition
    if($Snapshot.Kind -cne 'Registry' -or $Snapshot.Path -cne $path -or $Snapshot.IsDirectory -isnot [bool] -or $Snapshot.IsDirectory -or $Snapshot.Identity -cnotmatch ('^'+[regex]::Escape($path)+':[0-9]+$') -or $Snapshot.Aces -isnot [array]){throw 'Only exact historical registry snapshots are supported.'}
    foreach($name in @('ControlFlags','SecurityInformation')){Assert-WelaRegistryRecoveryNumber $Snapshot.$name}
    foreach($ace in $Snapshot.Aces){
        Assert-WelaEvtxObject $ace @('Binary','Type','Flags','Mask','Sid','Ordinary');Assert-WelaRegistryRecoveryText $ace @('Binary')
        if($ace.Ordinary -isnot [bool] -or ($null -ne $ace.Sid -and $ace.Sid -isnot [string])){throw 'Mistyped historical ACE metadata.'}
        foreach($name in @('Type','Flags','Mask')){Assert-WelaRegistryRecoveryNumber $ace.$name}
    }
    $parsed=Get-WelaRegistryRecoveryDescriptorObservation $Snapshot
    if((Get-WelaSelectedSaclSnapshotKey $parsed) -cne (Get-WelaSelectedSaclSnapshotKey $Snapshot)){throw 'Historical metadata differs from its native descriptor bytes.'}
}
function Get-WelaRegistryRecoveryDescriptorObservation {param($Snapshot) Initialize-WelaRegistryRecoveryNative;[Wela.RegistrySaclRecovery.Descriptor]::Observe($Snapshot.Path,$Snapshot.Identity,[Convert]::FromBase64String($Snapshot.DescriptorBase64))}
function Assert-WelaRegistryRecoveryEmpty {
    param($Inventory,$Root)
    Assert-WelaEvtxObject $Inventory @('Status','Maximum','MaximumDepth','StartedUtc','CompletedUtc','Root','Entries','Diagnostics')
    Assert-WelaRegistryRecoveryText $Inventory @('Status');Assert-WelaRegistryRecoveryNumber $Inventory.Maximum;Assert-WelaRegistryRecoveryNumber $Inventory.MaximumDepth
    if($Inventory.Status -cne 'Complete' -or $Inventory.Maximum -ne 128 -or $Inventory.MaximumDepth -ne 16 -or $Inventory.Entries -isnot [array] -or $Inventory.Entries.Count -ne 0 -or $Inventory.Diagnostics -isnot [array] -or $Inventory.Diagnostics.Count -ne 0 -or (Get-WelaSelectedSaclSnapshotKey $Inventory.Root) -cne (Get-WelaSelectedSaclSnapshotKey $Root)){throw 'Recovery requires complete exact empty historical/current descendants.'}
    $start=ConvertTo-WelaArrivalUtc $Inventory.StartedUtc;$end=ConvertTo-WelaArrivalUtc $Inventory.CompletedUtc
    if($start -gt $end -or $end -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Descendant timestamps are invalid.'}
}
function Assert-WelaRegistryRecoveryDescendantOutcome {
    param($Value)
    Assert-WelaEvtxObject $Value @('Status','Scope','Ownership','Outcomes','Diagnostics');Assert-WelaRegistryRecoveryText $Value @('Status','Scope','Ownership')
    if($Value.Status -cne 'Observed' -or $Value.Outcomes -isnot [array] -or $Value.Outcomes.Count -ne 0 -or $Value.Diagnostics -isnot [array] -or $Value.Diagnostics.Count -ne 0){throw 'Historical descendant verification is incomplete or nonempty.'}
}
function Get-WelaRegistryRecoverySnapshot {
    param($Definition)
    if($Definition.Kind -isnot [string] -or $Definition.Kind -cne 'Registry'){throw 'Only registry targets are supported.'}
    Initialize-WelaRegistryRecoveryNative;$target=[Wela.RegistrySaclRecovery.Target]::new((Resolve-WelaSelectedSaclNativePath $Definition))
    try{$target.Read()}finally{$target.Dispose()}
}
function Get-WelaRegistryRecoveryAddition {param($Before,$After,$Ace) Initialize-WelaRegistryRecoveryNative;[Wela.RegistrySaclRecovery.Descriptor]::AddedAce($Before.DescriptorBase64,$After.DescriptorBase64,$Ace.Sid,$Ace.Mask,$Ace.Flags)}
function Assert-WelaRegistryRecoveryEmptyCatalog {
    param($Value)
    # The original selected command's empty subexpression serializes as {} in
    # Windows PowerShell 5.1 and null in PowerShell 7. Neither contains targets.
    if($null -eq $Value -or ($Value -is [array] -and $Value.Count -eq 0) -or ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq 0)){return}
    throw 'Original selected plan catalog must be empty.'
}
function New-WelaRegistryRecoveryPlan {
    param([string]$OriginalPlanPath,[string]$PendingPath,[string]$ConfirmedPath,[string]$ResultsPath)
    $context=Get-WelaRegistryRecoveryContext;$sources=Get-WelaRegistryRecoverySources
    $files=[ordered]@{};foreach($entry in @(@('OriginalPlan',$OriginalPlanPath),@('Pending',$PendingPath),@('Confirmed',$ConfirmedPath),@('Results',$ResultsPath))){$files[$entry[0]]=Read-WelaRegistryRecoveryInput $entry[1]}
    if(@($files.Values.Path|Sort-Object -Unique).Count -ne 4){throw 'Four distinct original evidence files are required.'}
    $plan=$files.OriginalPlan.Data;$pending=$files.Pending.Data;$confirmed=$files.Confirmed.Data;$result=$files.Results.Data
    $planFields=@('SchemaVersion','Kind','CapturedUtc','Profile','IncludeOptional','IncludeChildren','Context','Sources','Rows','GenerationReadiness','UsableRuleCredit','Catalog','UserInventory')
    $rowFields=@('Id','DefinitionKey','Definition','Before','Ace','Status','Diagnostic','After','DescendantsBefore','DescendantsAfter','DescendantVerification')
    Assert-WelaEvtxObject $plan $planFields
    foreach($value in @($plan,$pending,$confirmed,$result)){Assert-WelaRegistryRecoveryNumber $value.SchemaVersion;if($value.SchemaVersion -ne 1){throw 'Unsupported original schema.'};Assert-WelaRegistryRecoveryText $value @('Kind')}
    Assert-WelaRegistryRecoveryText $plan @('Profile','GenerationReadiness')
    if($plan.Kind -cne 'WelaSelectedSaclPlan' -or $plan.IncludeChildren -isnot [bool] -or -not $plan.IncludeChildren -or $plan.IncludeOptional -isnot [bool] -or $plan.Rows -isnot [array] -or $plan.Rows.Count -ne 1){throw 'Require one original selected registry target with explicit child consent.'}
    Assert-WelaRegistryRecoveryEmptyCatalog $plan.Catalog
    $row=$plan.Rows[0];Assert-WelaEvtxObject $row $rowFields;Assert-WelaRegistryRecoveryText $row @('Id','DefinitionKey','Status','Diagnostic')
    Assert-WelaRegistryRecoveryText $row.Definition @('Kind','Path','Inheritance','Propagation')
    if($row.Status -cne 'ChangeRequired' -or $row.Diagnostic -cne '' -or $null -ne $row.After -or $null -ne $row.DescendantsAfter -or $null -ne $row.DescendantVerification -or $row.Id -cnotmatch '^sacl-[a-f0-9]{24}$' -or $row.Definition.Kind -cne 'Registry' -or $row.Definition.Inheritance -cnotin @('None','ContainerInherit') -or $row.Definition.Propagation -cne 'None'){throw 'Original plan is not one supported registry root audit addition.'}
    Assert-WelaRegistryRecoverySources $plan.Sources
    Assert-WelaRegistryRecoveryText $plan.Context @('Key','Computer')
    if((Get-WelaRegistryRecoveryKey $plan.Context) -cne (Get-WelaRegistryRecoveryKey $context.Selected) -or $plan.Context.Computer -cne $context.Host.Computer){throw 'Original host context differs from the actual recovery host.'}
    $catalog=Get-WelaSelectedSaclCatalog -Profile $plan.Profile -IncludeOptional:$plan.IncludeOptional -Context $context.Selected
    $selection=@($catalog.Rows|Where-Object Id -CEQ $row.Id)
    if($selection.Count -ne 1 -or $selection[0].DefinitionKey -cne $row.DefinitionKey -or (Get-WelaSelectedSaclDefinitionKey $row.Definition) -cne $row.DefinitionKey -or (Get-WelaRegistryRecoveryKey $selection[0].Definition) -cne (Get-WelaRegistryRecoveryKey $row.Definition)){throw 'Original target is not the exact currently source-bound catalog selection.'}
    Assert-WelaRegistryRecoverySnapshot $row.Before $row.Definition;Assert-WelaRegistryRecoveryEmpty $row.DescendantsBefore $row.Before
    $ace=Get-WelaSelectedSaclAce $row.Definition $row.Before -IncludeChildren
    Assert-WelaEvtxObject $row.Ace @('Sid','Mask','Flags','RequiredPolicyMask');Assert-WelaRegistryRecoveryText $row.Ace @('Sid');foreach($name in @('Mask','Flags','RequiredPolicyMask')){Assert-WelaRegistryRecoveryNumber $row.Ace.$name}
    if((Get-WelaRegistryRecoveryKey $ace) -cne (Get-WelaRegistryRecoveryKey $row.Ace) -or $ace.Flags -notin @(64,128,192,66,130,194) -or (Test-WelaSelectedSaclAce $row.Before $ace)){throw 'Original ACE is mistyped, inherited or already covered.'}
    $receiptFields=@('SchemaVersion','Kind','State','RecordedUtc','Computer','ContextKey','Id','Sources','Definition','Before','Ace','After','DescendantsBefore','DescendantsAfter','DescendantVerification','Ownership')
    foreach($receipt in @($pending,$confirmed)){
        Assert-WelaEvtxObject $receipt $receiptFields;Assert-WelaRegistryRecoveryText $receipt @('Kind','State','Computer','ContextKey','Id','Ownership')
        if($receipt.Kind -cne 'WelaSelectedSaclReceipt' -or $receipt.Computer -cne $context.Host.Computer -or $receipt.ContextKey -cne $context.Selected.Key -or $receipt.Id -cne $row.Id -or $receipt.Ownership -cne 'Only the verified explicit selected-root addition; never descendant ACE ownership or bulk rollback authority.'){throw 'Original receipt scope or ownership differs.'}
        Assert-WelaRegistryRecoverySources $receipt.Sources
        foreach($name in @('Definition','Ace')){if((Get-WelaRegistryRecoveryKey $receipt.$name) -cne (Get-WelaRegistryRecoveryKey $row.$name)){throw 'Original receipt differs from selected plan.'}}
        Assert-WelaRegistryRecoverySnapshot $receipt.Before $row.Definition
        if((Get-WelaSelectedSaclSnapshotKey $receipt.Before) -cne (Get-WelaSelectedSaclSnapshotKey $row.Before)){throw 'Original before-state differs across records.'}
        Assert-WelaRegistryRecoveryEmpty $receipt.DescendantsBefore $receipt.Before
    }
    if($pending.State -cne 'Pending' -or $null -ne $pending.After -or $null -ne $pending.DescendantsAfter -or $null -ne $pending.DescendantVerification -or $confirmed.State -cne 'Confirmed' -or $null -eq $confirmed.After -or (ConvertTo-WelaArrivalUtc $pending.RecordedUtc) -ne (ConvertTo-WelaArrivalUtc $confirmed.RecordedUtc)){throw 'A matching original Pending and Confirmed pair is required.'}
    Assert-WelaRegistryRecoverySnapshot $confirmed.After $row.Definition;Assert-WelaRegistryRecoveryEmpty $confirmed.DescendantsAfter $confirmed.After;Assert-WelaRegistryRecoveryDescendantOutcome $confirmed.DescendantVerification
    # Last-write metadata can change during the original SACL write; current state must match its exact observed After.
    $added=Get-WelaRegistryRecoveryAddition $row.Before $confirmed.After $ace
    Assert-WelaEvtxObject $result @('SchemaVersion','Kind','ExitCode','DryRun','BackupPath','Plan','Results','GenerationReadiness','UsableRuleCredit');Assert-WelaRegistryRecoveryNumber $result.ExitCode;Assert-WelaRegistryRecoveryText $result @('BackupPath','GenerationReadiness')
    if($result.Kind -cne 'WelaSelectedSaclResult' -or $result.ExitCode -ne 0 -or $result.DryRun -isnot [bool] -or $result.DryRun -or $result.Results -isnot [array] -or $result.Results.Count -ne 1){throw 'Require one completed successful, non-dry-run operation.'}
    $applied=$result.Results[0];Assert-WelaEvtxObject $applied $rowFields;Assert-WelaRegistryRecoveryText $applied @('Id','DefinitionKey','Status','Diagnostic')
    Assert-WelaEvtxObject $result.Plan $planFields;Assert-WelaRegistryRecoveryText $result.Plan @('Kind');Assert-WelaRegistryRecoveryNumber $result.Plan.SchemaVersion;if($result.Plan.SchemaVersion -ne 1){throw 'Unsupported completed plan schema.'}
    foreach($value in @($plan,$result.Plan,$result)){Assert-WelaRegistryRecoveryText $value @('GenerationReadiness');Assert-WelaRegistryRecoveryNumber $value.UsableRuleCredit;if($value.GenerationReadiness -cne 'Conditional' -or $value.UsableRuleCredit -ne 0){throw 'Original evidence carries unsupported generation credit.'}}
    if($applied.Status -cne 'Applied' -or $applied.Diagnostic -cne '' -or $result.Plan.Kind -cne 'WelaSelectedSaclPlan' -or $result.Plan.Rows -isnot [array] -or $result.Plan.Rows.Count -ne 1 -or (Get-WelaRegistryRecoveryKey $applied) -cne (Get-WelaRegistryRecoveryKey $result.Plan.Rows[0]) -or $applied.Id -cne $row.Id -or $applied.DefinitionKey -cne $row.DefinitionKey){throw 'Completed result status, rows or scope disagree.'}
    foreach($name in @('Definition','Ace')){if((Get-WelaRegistryRecoveryKey $applied.$name) -cne (Get-WelaRegistryRecoveryKey $row.$name)){throw 'Completed selection differs from original plan.'}}
    foreach($name in @('Before','After')){Assert-WelaRegistryRecoverySnapshot $applied.$name $row.Definition;if((Get-WelaSelectedSaclSnapshotKey $applied.$name) -cne (Get-WelaSelectedSaclSnapshotKey $confirmed.$name)){throw 'Completed descriptor evidence disagrees.'}}
    Assert-WelaRegistryRecoveryEmpty $applied.DescendantsBefore $applied.Before;Assert-WelaRegistryRecoveryEmpty $applied.DescendantsAfter $applied.After;Assert-WelaRegistryRecoveryDescendantOutcome $applied.DescendantVerification
    foreach($name in @('Profile','IncludeOptional','IncludeChildren','Context','Sources')){if((Get-WelaRegistryRecoveryKey $result.Plan.$name) -cne (Get-WelaRegistryRecoveryKey $plan.$name)){throw 'Completed plan context differs from original selection.'}}
    $backup=Resolve-WelaArrivalPath $result.BackupPath
    if($files.Pending.Path -ine (Join-Path $backup ($row.Id+'.pending.json')) -or $files.Confirmed.Path -ine (Join-Path $backup ($row.Id+'.confirmed.json'))){throw 'Receipt paths do not match recorded backup directory.'}
    $originalTime=ConvertTo-WelaArrivalUtc $plan.CapturedUtc;$configuredTime=ConvertTo-WelaArrivalUtc $result.Plan.CapturedUtc;$receiptTime=ConvertTo-WelaArrivalUtc $pending.RecordedUtc
    if($originalTime -gt $configuredTime -or $configuredTime -gt $receiptTime -or $receiptTime -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Original timestamps are reversed or in the future.'}
    $current=Get-WelaRegistryRecoverySnapshot $row.Definition
    if((Get-WelaSelectedSaclSnapshotKey $current) -cne (Get-WelaSelectedSaclSnapshotKey $confirmed.After)){throw 'Current registry last-write identity or full descriptor differs from completed After; value changes also require manual assessment.'}
    $inputFiles=[ordered]@{};foreach($name in $files.Keys){$inputFiles[$name]=[pscustomobject]@{Path=$files[$name].Path;Sha256=$files[$name].Sha256}}
    $recovery=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaRegistrySaclRecoveryPlan';Id=$row.Id;Context=$context;Sources=$sources;OriginalFiles=[pscustomobject]$inputFiles;Definition=$row.Definition;BeforeAddition=$row.Before;Expected=$current;AddedAce=$added;RequiresAuditReductionConsent=$true;RequiresInheritanceConsent=$true;HistoricalBinding='Original version1 records contain host context/source hashes, not authenticated historical operator identity. Registry path/last-write metadata cannot prove durable key identity.';Outcome='Remove one proven explicit registry-root audit ACE; preserve all other descriptor components and ACE order. Empty or null present SACL can remain. Empty-child observations are not an atomic tree guarantee.';ReadyRuleCredit=0}
    Assert-WelaRegistryRecoveryFresh $recovery
    $recovery
}
function Assert-WelaRegistryRecoveryBindings {
    param($Plan)
    if((Get-WelaRegistryRecoveryKey (Get-WelaRegistryRecoverySources)) -cne (Get-WelaRegistryRecoveryKey $Plan.Sources) -or (Get-WelaRegistryRecoveryKey (Get-WelaRegistryRecoveryContext)) -cne (Get-WelaRegistryRecoveryKey $Plan.Context)){throw 'Recovery source, host, logon, token or audit policy changed.'}
    foreach($entry in $Plan.OriginalFiles.PSObject.Properties){if((Read-WelaRegistryRecoveryInput $entry.Value.Path).Sha256 -cne $entry.Value.Sha256){throw 'Original recovery evidence changed.'}}
}
function Assert-WelaRegistryRecoveryFresh {param($Plan) Assert-WelaRegistryRecoveryBindings $Plan;if((Get-WelaSelectedSaclSnapshotKey (Get-WelaRegistryRecoverySnapshot $Plan.Definition)) -cne (Get-WelaSelectedSaclSnapshotKey $Plan.Expected)){throw 'Reviewed registry identity/descriptor changed before removal.'}}
function Open-WelaRegistryRecoveryTarget {param($Definition) Initialize-WelaRegistryRecoveryNative;[Wela.RegistrySaclRecovery.Target]::new((Resolve-WelaSelectedSaclNativePath $Definition))}
function Invoke-WelaRegistrySaclRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$OriginalPlanPath,[string]$PendingPath,[string]$ConfirmedPath,[string]$OriginalResultsPath,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$AllowAuditReduction,[switch]$AllowInheritance)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $OriginalPlanPath -or -not $PendingPath -or -not $ConfirmedPath -or -not $OriginalResultsPath -or -not $OutputPath -or $PlanPath -or $PlanHash -or $AllowAuditReduction -or $AllowInheritance){throw 'Plan requires four original evidence paths and a new output directory only.'}
    }elseif(-not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or -not $OutputPath -or $OriginalPlanPath -or $PendingPath -or $ConfirmedPath -or $OriginalResultsPath){throw 'Restore requires only reviewed plan path/hash, new output and both explicit consents.'}
    $output=New-WelaArrivalOutput $OutputPath $script:ScriptRoot
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaRegistrySaclRecovery';Action=$Action;Status='Refused';ExitCode=1;PlanHash=$null;WriteAttempted=$false;Before=$null;After=$null;OriginalDescriptorBytesMatch=$false;Artifacts=@();OutputPath=$output;Diagnostic='';ReadyRuleCredit=0;PolicyChanges=0;Scope='One proven registry-root audit ACE; complete empty historical/current descendants only. No full descriptor rollback, historical key identity, atomic-tree, event or Sigma claim.'}
    $target=$null
    try {
        if($Action -eq 'Plan'){
            $plan=New-WelaRegistryRecoveryPlan $OriginalPlanPath $PendingPath $ConfirmedPath $OriginalResultsPath
            $artifact=Write-WelaWecUpdateArtifact $output 'plan.json' (Get-WelaRegistryRecoveryKey $plan);$report.Artifacts+=$artifact;$report.PlanHash=$artifact.Sha256
            Assert-WelaRegistryRecoveryFresh $plan
            $report.Status='ReviewRequired';$report.ExitCode=0
        }else{
            $inputFile=Read-WelaRegistryRecoveryInput $PlanPath
            if($inputFile.Sha256 -cne $PlanHash){throw 'Reviewed recovery plan hash differs.'}
            $plan=$inputFile.Data;Assert-WelaRegistryRecoveryText $plan @('Kind')
            if($plan.Kind -cne 'WelaRegistrySaclRecoveryPlan'){throw 'Unsupported recovery plan kind.'}
            $inputs=$plan.OriginalFiles;$rebuilt=New-WelaRegistryRecoveryPlan $inputs.OriginalPlan.Path $inputs.Pending.Path $inputs.Confirmed.Path $inputs.Results.Path
            if((Get-WelaRegistryRecoveryKey $plan) -cne (Get-WelaRegistryRecoveryKey $rebuilt)){throw 'Reviewed recovery plan is stale or modified.'}
            if(-not $AllowAuditReduction -or -not $AllowInheritance){throw 'Restore requires explicit AllowAuditReduction and AllowInheritance: selected auditing is reduced and concurrent children can be affected.'}
            $report.PlanHash=$PlanHash;$report.Before=$plan.Expected
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'reviewed-plan.json' (Get-WelaRegistryRecoveryKey $plan)
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'pending.json' (Get-WelaRegistryRecoveryKey ([pscustomobject]@{Kind='WelaRegistrySaclRecoveryIntent';State='Pending';PlanHash=$PlanHash;Before=$plan.Expected;RemoveAce=$plan.AddedAce;AllowAuditReduction=[bool]$AllowAuditReduction;AllowInheritance=[bool]$AllowInheritance;RecordedUtc=[DateTime]::UtcNow.ToString('o')}))
            Assert-WelaRegistryRecoveryFresh $plan
            if((Read-WelaRegistryRecoveryInput $PlanPath).Sha256 -cne $PlanHash){throw 'Reviewed recovery plan changed immediately before write.'}
            foreach($artifact in $report.Artifacts){if((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Saved recovery receipt changed before write.'}}
            $target=Open-WelaRegistryRecoveryTarget $plan.Definition
            try{$report.After=$target.Remove($plan.Expected.Identity,$plan.Expected.DescriptorBase64,$plan.AddedAce)}finally{$report.WriteAttempted=$target.WriteAttempted;if($target.AfterObservation){$report.After=$target.AfterObservation}}
            $target.Dispose();$target=$null
            if($null -ne $report.After){$report.Artifacts+=Write-WelaWecUpdateArtifact $output 'after.json' (Get-WelaRegistryRecoveryKey $report.After)}
            Assert-WelaRegistryRecoveryBindings $plan
            if((Get-WelaSelectedSaclSnapshotKey (Get-WelaRegistryRecoverySnapshot $plan.Definition)) -cne (Get-WelaSelectedSaclSnapshotKey $report.After)){throw 'Final registry identity/descriptor or empty-child state differs after removal.'}
            if((Read-WelaRegistryRecoveryInput $PlanPath).Sha256 -cne $PlanHash){throw 'Reviewed plan changed after write.'}
            foreach($artifact in $report.Artifacts){if((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256){throw 'Saved recovery receipt changed after write.'}}
            $report.OriginalDescriptorBytesMatch=$report.After.DescriptorBase64 -ceq $plan.BeforeAddition.DescriptorBase64
            $report.Artifacts+=Write-WelaWecUpdateArtifact $output 'confirmed.json' (Get-WelaRegistryRecoveryKey ([pscustomobject]@{Kind='WelaRegistrySaclRecoveryConfirmation';State='Confirmed';PlanHash=$PlanHash;Before=$plan.Expected;After=$report.After;RemoveAce=$plan.AddedAce;RecordedUtc=[DateTime]::UtcNow.ToString('o')}))
            $report.Status='AddedAceRemoved';$report.ExitCode=0
        }
    }catch{$report.Status=if($report.WriteAttempted){'WriteAttemptedUnverified'}else{'Refused'};$report.Diagnostic=$_.Exception.Message}
    finally{if($target){try{$target.Dispose()}catch{$report.Status='WriteAttemptedUnverified';$report.ExitCode=1;$report.Diagnostic+=' Native cleanup failed: '+$_.Exception.Message}}}
    $null=Write-WelaWecUpdateArtifact $output 'manifest.json' (Get-WelaRegistryRecoveryKey $report)
    $report
}
