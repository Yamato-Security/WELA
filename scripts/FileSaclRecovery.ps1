# Recovery is limited to a single proven explicit addition on an existing leaf file.
function Get-WelaFileSaclRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 30 -Compress}
function Initialize-WelaFileSaclRecoveryNative {
    $path=Join-Path $PSScriptRoot 'FileSaclRecoveryNative.cs';$bytes=[IO.File]::ReadAllBytes($path);$hash=Get-WelaArrivalHash $bytes
    if (-not ('Wela.FileSaclRecovery.Descriptor' -as [type])) {
        $source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
        $marker='__WELA_FILE_SACL_RECOVERY_SOURCE_SHA256__'
        if (($source.Split(@($marker),[StringSplitOptions]::None)).Count -ne 2) {throw 'Unexpected native recovery source binding.'}
        Add-Type -TypeDefinition $source.Replace($marker,$hash) -ErrorAction Stop
    }
    if ([Wela.FileSaclRecovery.Descriptor]::SourceSha256 -cne $hash) {throw 'Loaded file recovery helper differs from current source; start a fresh PowerShell process.'}
}
function Get-WelaFileSaclRecoverySources {
    $sources=[ordered]@{}
    foreach ($path in @('WELA.ps1','scripts/FileSaclRecovery.ps1','scripts/FileSaclRecoveryNative.cs','scripts/SelectedSaclConfiguration.ps1','scripts/SelectedSaclNative.cs','scripts/SelectedSaclDescendants.ps1','scripts/TargetedSaclPlanning.ps1','scripts/ControlApplicability.ps1','scripts/Configuration.ps1','config/control_applicability.json','modules/NativeProviders.psm1','scripts/EvtxRecovery.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1','modules/AuditCatalog.psm1','config/audit_profiles.json','config/audit_sacl_targets.json')) {
        $sources[$path]=(Get-FileHash -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) $path) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    [pscustomobject]$sources
}
function Get-WelaFileSaclRecoveryOperator {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'File SACL recovery requires native 64-bit Windows.'}
    $thread=[Security.Principal.WindowsIdentity]::GetCurrent($true)
    if ($thread) {$thread.Dispose();throw 'Impersonated recovery is unsupported.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'File SACL recovery requires the actual elevated operator.'}
        $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Cryptography',$false)
        if (-not $key) {throw 'Machine identity is unavailable.'}
        try {$machine=$key.GetValue('MachineGuid');if ($key.GetValueKind('MachineGuid') -ne 'String' -or $machine -isnot [string]) {throw 'Machine identity is mistyped.'}} finally {$key.Dispose()}
        [guid]$parsed=[guid]::Empty;if (-not [guid]::TryParse($machine,[ref]$parsed) -or $parsed -eq [guid]::Empty) {throw 'Machine identity is invalid.'}
        [pscustomobject][ordered]@{Computer=[Environment]::MachineName;MachineGuid=$parsed.ToString();UserSid=$identity.User.Value;Groups=@($identity.Groups|ForEach-Object Value|Sort-Object);ElevatedAdministrator=$true;Impersonation='Absent'}
    } finally {$identity.Dispose()}
}
function Read-WelaFileSaclRecoveryInput {
    param([string]$Path)
    $full=Resolve-WelaArrivalPath $Path
    $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 4194304) {throw 'Recovery JSON must contain 1 byte through four MiB.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while ($offset -lt $bytes.Length) {$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if ($count -eq 0) {throw 'Recovery input changed during reading.'};$offset+=$count}
        if ($stream.Length -ne $bytes.Length) {throw 'Recovery input length changed.'}
    } finally {$stream.Dispose()}
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
    [pscustomobject]@{Path=$full;Sha256=(Get-WelaArrivalHash $bytes);Bytes=$bytes.Length;Data=(ConvertFrom-WelaEvtxJson $text)}
}
function Assert-WelaFileSaclRecoverySnapshot {
    param($Snapshot,$Definition)
    Assert-WelaEvtxObject $Snapshot @('Path','Kind','Identity','IsDirectory','DescriptorBase64','Owner','Group','DaclBase64','ControlFlags','SecurityInformation','DescriptorScope','Aces')
    if ($Snapshot.Kind -cne 'FileSystem' -or $Snapshot.IsDirectory -isnot [bool] -or $Snapshot.IsDirectory -or $Snapshot.Path -cne $Definition.Path -or $Snapshot.Identity -cnotmatch '^[0-9]+:[0-9]+:[0-9]+:[0-9]+$' -or $Snapshot.Aces -isnot [array]) {throw 'Only exact historical leaf-file snapshots are supported.'}
    $null=Get-WelaSelectedSaclSnapshotKey $Snapshot
    foreach ($ace in $Snapshot.Aces) {
        Assert-WelaEvtxObject $ace @('Binary','Type','Flags','Mask','Sid','Ordinary')
        if ($ace.Ordinary -isnot [bool]) {throw 'Mistyped ACE metadata.'}
        foreach ($name in @('Type','Flags','Mask')) {if ($ace.$name -isnot [int] -and $ace.$name -isnot [long]) {throw 'Mistyped ACE metadata.'}}
    }
    Initialize-WelaFileSaclRecoveryNative
    $parsed=[Wela.FileSaclRecovery.Descriptor]::Observe($Snapshot.Path,$Snapshot.Identity,[Convert]::FromBase64String($Snapshot.DescriptorBase64))
    if ((Get-WelaSelectedSaclSnapshotKey $parsed) -cne (Get-WelaSelectedSaclSnapshotKey $Snapshot)) {throw 'Historical snapshot metadata differs from its actual descriptor bytes.'}
}
function Get-WelaFileSaclRecoverySnapshot {
    param($Definition)
    if ($Definition.Kind -cne 'FileSystem') {throw 'Only leaf FileSystem targets are supported.'}
    $path=Resolve-WelaSelectedSaclNativePath $Definition;Initialize-WelaFileSaclRecoveryNative
    $target=[Wela.FileSaclRecovery.Target]::new($path)
    try {$target.Read()} finally {$target.Dispose()}
}
function Get-WelaFileSaclRecoveryAddition {
    param($Before,$After,$Ace)
    Initialize-WelaFileSaclRecoveryNative
    [Wela.FileSaclRecovery.Descriptor]::AddedAce($Before.DescriptorBase64,$After.DescriptorBase64,$Ace.Sid,$Ace.Mask,$Ace.Flags)
}
function New-WelaFileSaclRecoveryPlan {
    param([string]$OriginalPlanPath,[string]$PendingPath,[string]$ConfirmedPath,[string]$ResultsPath)
    $operator=Get-WelaFileSaclRecoveryOperator;$context=Get-WelaSelectedSaclContext;$sources=Get-WelaFileSaclRecoverySources
    $files=[ordered]@{};foreach ($entry in @(@('OriginalPlan',$OriginalPlanPath),@('Pending',$PendingPath),@('Confirmed',$ConfirmedPath),@('Results',$ResultsPath))) {$files[$entry[0]]=Read-WelaFileSaclRecoveryInput $entry[1]}
    if (@($files.Values.Path|Sort-Object -Unique).Count -ne 4) {throw 'Four distinct original evidence files are required.'}
    $plan=$files.OriginalPlan.Data;$pending=$files.Pending.Data;$confirmed=$files.Confirmed.Data;$result=$files.Results.Data
    Assert-WelaEvtxObject $plan @('SchemaVersion','Kind','CapturedUtc','Profile','IncludeOptional','IncludeChildren','Context','Sources','Rows','GenerationReadiness','UsableRuleCredit','Catalog','UserInventory')
    foreach ($value in @($plan,$pending,$confirmed,$result)) {if (($value.SchemaVersion -isnot [int] -and $value.SchemaVersion -isnot [long]) -or $value.SchemaVersion -ne 1) {throw 'Unsupported original evidence schema.'}}
    if ($plan.Kind -cne 'WelaSelectedSaclPlan' -or $plan.IncludeChildren -isnot [bool] -or $plan.IncludeChildren -or $plan.IncludeOptional -isnot [bool] -or $plan.Rows -isnot [array] -or $plan.Rows.Count -ne 1) {throw 'Require one original selected target, without child consent.'}
    $row=$plan.Rows[0]
    if ($row.Status -cne 'ChangeRequired' -or $row.After -or $row.DescendantsBefore -or $row.DescendantsAfter -or $row.DescendantVerification -or $row.Id -cnotmatch '^sacl-[a-f0-9]{24}$' -or $row.Definition.Kind -cne 'FileSystem' -or $row.Definition.Inheritance -cne 'None' -or $row.Definition.Propagation -cne 'None') {throw 'Original plan must describe one explicit leaf-file addition without inheritance.'}
    Assert-WelaSelectedSaclSources $plan.Sources
    if ($plan.Context.Key -cne $context.Key -or $plan.Context.Computer -cne $operator.Computer) {throw 'Original host context differs from the actual recovery host.'}
    $catalog=Get-WelaSelectedSaclCatalog -Profile $plan.Profile -IncludeOptional:$plan.IncludeOptional -Context $context
    $selected=@($catalog.Rows|Where-Object Id -CEQ $row.Id)
    if ($selected.Count -ne 1 -or $selected[0].DefinitionKey -cne $row.DefinitionKey -or (Get-WelaSelectedSaclDefinitionKey $row.Definition) -cne $row.DefinitionKey -or (Get-WelaFileSaclRecoveryKey $selected[0].Definition) -cne (Get-WelaFileSaclRecoveryKey $row.Definition)) {throw 'Original target is not the exact currently source-bound catalog selection.'}
    Assert-WelaFileSaclRecoverySnapshot $row.Before $row.Definition
    $ace=Get-WelaSelectedSaclAce $row.Definition $row.Before
    if ((Get-WelaFileSaclRecoveryKey $ace) -cne (Get-WelaFileSaclRecoveryKey $row.Ace) -or $ace.Flags -notin @(64,128,192) -or (Test-WelaSelectedSaclAce $row.Before $ace)) {throw 'Original selected audit ACE is mistyped, inherited or already covered.'}
    $receiptFields=@('SchemaVersion','Kind','State','RecordedUtc','Computer','ContextKey','Id','Sources','Definition','Before','Ace','After','DescendantsBefore','DescendantsAfter','DescendantVerification','Ownership')
    foreach ($receipt in @($pending,$confirmed)) {
        Assert-WelaEvtxObject $receipt $receiptFields
        if ($receipt.Kind -cne 'WelaSelectedSaclReceipt' -or $receipt.Computer -cne $operator.Computer -or $receipt.ContextKey -cne $context.Key -or $receipt.Id -cne $row.Id -or $receipt.DescendantsBefore -or $receipt.DescendantsAfter -or $receipt.DescendantVerification -or $receipt.Ownership -cne 'Only the verified explicit selected-root addition; never descendant ACE ownership or bulk rollback authority.') {throw 'Original receipt scope or ownership is unsupported.'}
        Assert-WelaSelectedSaclSources $receipt.Sources
        foreach ($name in @('Definition','Ace')) {if ((Get-WelaFileSaclRecoveryKey $receipt.$name) -cne (Get-WelaFileSaclRecoveryKey $row.$name)) {throw 'Original receipt differs from the selected plan.'}}
        Assert-WelaFileSaclRecoverySnapshot $receipt.Before $row.Definition
        if ((Get-WelaSelectedSaclSnapshotKey $receipt.Before) -cne (Get-WelaSelectedSaclSnapshotKey $row.Before)) {throw 'Original before-state differs across records.'}
    }
    if ($pending.State -cne 'Pending' -or $pending.After -or $confirmed.State -cne 'Confirmed' -or -not $confirmed.After -or $pending.RecordedUtc -cne $confirmed.RecordedUtc) {throw 'A matching pending and confirmed receipt pair is required.'}
    Assert-WelaFileSaclRecoverySnapshot $confirmed.After $row.Definition
    if ($confirmed.After.Identity -cne $row.Before.Identity) {throw 'The original operation changed file identity.'}
    $added=Get-WelaFileSaclRecoveryAddition $row.Before $confirmed.After $ace
    Assert-WelaEvtxObject $result @('SchemaVersion','Kind','ExitCode','DryRun','BackupPath','Plan','Results','GenerationReadiness','UsableRuleCredit')
    if ($result.Kind -cne 'WelaSelectedSaclResult' -or ($result.ExitCode -isnot [int] -and $result.ExitCode -isnot [long]) -or $result.ExitCode -ne 0 -or $result.DryRun -isnot [bool] -or $result.DryRun -or $result.Results -isnot [array] -or $result.Results.Count -ne 1 -or $result.Results[0].Status -cne 'Applied') {throw 'Require a completed successful, non-dry-run selected operation.'}
    $applied=$result.Results[0]
    if ($result.Plan.Kind -cne 'WelaSelectedSaclPlan' -or $result.Plan.Rows -isnot [array] -or $result.Plan.Rows.Count -ne 1 -or (Get-WelaFileSaclRecoveryKey $applied) -cne (Get-WelaFileSaclRecoveryKey $result.Plan.Rows[0]) -or $applied.Id -cne $row.Id -or $applied.DefinitionKey -cne $row.DefinitionKey -or $applied.DescendantsBefore -or $applied.DescendantsAfter -or $applied.DescendantVerification) {throw 'Completed result rows or scope disagree.'}
    foreach ($name in @('Definition','Ace')) {if ((Get-WelaFileSaclRecoveryKey $applied.$name) -cne (Get-WelaFileSaclRecoveryKey $row.$name)) {throw 'Completed selection differs from original plan.'}}
    if ((Get-WelaSelectedSaclSnapshotKey $applied.Before) -cne (Get-WelaSelectedSaclSnapshotKey $row.Before) -or (Get-WelaSelectedSaclSnapshotKey $applied.After) -cne (Get-WelaSelectedSaclSnapshotKey $confirmed.After)) {throw 'Completed descriptor evidence disagrees.'}
    foreach ($name in @('Profile','IncludeOptional','IncludeChildren','Context','Sources')) {if ((Get-WelaFileSaclRecoveryKey $result.Plan.$name) -cne (Get-WelaFileSaclRecoveryKey $plan.$name)) {throw 'Completed plan context differs from the original selection.'}}
    $backup=Resolve-WelaArrivalPath $result.BackupPath
    if ($files.Pending.Path -ine (Join-Path $backup ($row.Id+'.pending.json')) -or $files.Confirmed.Path -ine (Join-Path $backup ($row.Id+'.confirmed.json'))) {throw 'Receipt paths do not match the original recorded backup directory.'}
    $originalTime=ConvertTo-WelaEvtxUtc $plan.CapturedUtc;$configuredTime=ConvertTo-WelaEvtxUtc $result.Plan.CapturedUtc;$receiptTime=ConvertTo-WelaEvtxUtc $pending.RecordedUtc
    if ($originalTime -gt $configuredTime -or $configuredTime -gt $receiptTime -or $receiptTime -gt [DateTimeOffset]::UtcNow) {throw 'Original evidence timestamps are out of order or in the future.'}
    $current=Get-WelaFileSaclRecoverySnapshot $row.Definition
    if ((Get-WelaSelectedSaclSnapshotKey $current) -cne (Get-WelaSelectedSaclSnapshotKey $confirmed.After)) {throw 'Current file identity or descriptor differs from the completed operation; manual review required.'}
    if ((Get-WelaSelectedSaclSnapshotKey (Get-WelaFileSaclRecoverySnapshot $row.Definition)) -cne (Get-WelaSelectedSaclSnapshotKey $current)) {throw 'File changed during recovery planning.'}
    $inputFiles=[ordered]@{};foreach ($name in $files.Keys) {$file=$files[$name];$inputFiles[$name]=[pscustomobject]@{Path=$file.Path;Sha256=$file.Sha256;Bytes=$file.Bytes}}
    $recovery=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaFileSaclRecoveryPlan';Id=$row.Id;Profile=$plan.Profile;Operator=$operator;ContextKey=$context.Key;Sources=$sources;OriginalFiles=[pscustomobject]$inputFiles;Definition=$row.Definition;BeforeAddition=$row.Before;Expected=$current;AddedAce=$added;Outcome='Remove one proven explicit ordinary audit ACE; an empty or null present SACL can remain.';ReadyRuleCredit=0}
    Assert-WelaFileSaclRecoveryFresh $recovery
    $recovery
}
function Assert-WelaFileSaclRecoveryFresh {
    param($Plan)
    if ((Get-WelaFileSaclRecoveryKey (Get-WelaFileSaclRecoverySources)) -cne (Get-WelaFileSaclRecoveryKey $Plan.Sources) -or (Get-WelaFileSaclRecoveryKey (Get-WelaFileSaclRecoveryOperator)) -cne (Get-WelaFileSaclRecoveryKey $Plan.Operator) -or (Get-WelaSelectedSaclContext).Key -cne $Plan.ContextKey) {throw 'Recovery implementation, operator or host context changed.'}
    foreach ($entry in $Plan.OriginalFiles.PSObject.Properties) {$file=Read-WelaFileSaclRecoveryInput $entry.Value.Path;if ($file.Sha256 -cne $entry.Value.Sha256 -or $file.Bytes -ne $entry.Value.Bytes) {throw 'Original recovery evidence changed.'}}
    if ((Get-WelaSelectedSaclSnapshotKey (Get-WelaFileSaclRecoverySnapshot $Plan.Definition)) -cne (Get-WelaSelectedSaclSnapshotKey $Plan.Expected)) {throw 'Reviewed file changed before removal.'}
}
function Invoke-WelaFileSaclRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$OriginalPlanPath,[string]$PendingPath,[string]$ConfirmedPath,[string]$ResultsPath,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$Auto,[switch]$DryRun)
    if ($Action -eq 'Plan') {
        if ($PlanPath -or $PlanHash -or $Auto -or $DryRun -or -not $OriginalPlanPath -or -not $PendingPath -or -not $ConfirmedPath -or -not $ResultsPath -or -not $OutputPath) {throw 'Plan requires four original evidence paths and a new output directory only.'}
        $plan=New-WelaFileSaclRecoveryPlan $OriginalPlanPath $PendingPath $ConfirmedPath $ResultsPath
        $output=New-WelaArrivalOutput -Path $OutputPath -SourcePath (Split-Path $PSScriptRoot -Parent)
        $artifact=Write-WelaFileSaclRecoveryArtifact $output 'plan.json' (Get-WelaFileSaclRecoveryKey $plan)
        return [pscustomobject]@{Status='Planned';ExitCode=0;PlanPath=(Join-Path $output 'plan.json');PlanHash=$artifact.Sha256;ReadyRuleCredit=0}
    }
    if ($OriginalPlanPath -or $PendingPath -or $ConfirmedPath -or $ResultsPath -or -not $PlanPath -or $PlanHash -cnotmatch '^[a-f0-9]{64}$' -or ($DryRun -and ($OutputPath -or $Auto)) -or (-not $DryRun -and (-not $Auto -or -not $OutputPath))) {throw 'Restore requires PlanPath/PlanHash and either DryRun or Auto with a new output directory.'}
    $reviewed=Read-WelaFileSaclRecoveryInput $PlanPath
    if ($reviewed.Sha256 -cne $PlanHash -or $reviewed.Data.Kind -cne 'WelaFileSaclRecoveryPlan') {throw 'Reviewed recovery plan hash or kind differs.'}
    $plan=$reviewed.Data;$inputs=$plan.OriginalFiles
    $rebuilt=New-WelaFileSaclRecoveryPlan $inputs.OriginalPlan.Path $inputs.Pending.Path $inputs.Confirmed.Path $inputs.Results.Path
    if ((Get-WelaFileSaclRecoveryKey $plan) -cne (Get-WelaFileSaclRecoveryKey $rebuilt)) {throw 'Reviewed recovery plan is stale or modified.'}
    if ($DryRun) {return [pscustomobject]@{Status='WouldRemoveAddedAce';ExitCode=0;Target=$plan.Definition.Path;ReadyRuleCredit=0}}
    $output=New-WelaArrivalOutput -Path $OutputPath -SourcePath (Split-Path $reviewed.Path -Parent)
    $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaFileSaclRecoveryResult';Status='Refused';ExitCode=1;StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;PlanHash=$PlanHash;Before=$plan.Expected;After=$null;SaclBefore=[Wela.FileSaclRecovery.Descriptor]::SaclRepresentation($plan.Expected.DescriptorBase64);SaclAfter=$null;WriteAttempted=$false;Artifacts=@();OriginalDescriptorBytesMatch=$false;Diagnostic='';OutputPath=$output;ReadyRuleCredit=0;PolicyChanges=0;Scope='Remove only one proven explicit leaf-file audit ACE; preserve other ACE bytes/counts and observed descriptor components. No descendant, exact historical descriptor, event or Sigma claim.'}
    $target=$null
    try {
        $report.Artifacts+=Write-WelaFileSaclRecoveryArtifact $output 'reviewed-plan.json' (Get-WelaFileSaclRecoveryKey $plan)
        $report.Artifacts+=Write-WelaFileSaclRecoveryArtifact $output 'pending.json' (Get-WelaFileSaclRecoveryKey ([pscustomobject]@{Kind='WelaFileSaclRecoveryIntent';PlanHash=$PlanHash;Before=$plan.Expected;RemoveAce=$plan.AddedAce;RecordedUtc=[DateTime]::UtcNow.ToString('o')}))
        Assert-WelaFileSaclRecoveryFresh $plan
        if ((Read-WelaFileSaclRecoveryInput $reviewed.Path).Sha256 -cne $PlanHash) {throw 'Reviewed recovery plan changed before write.'}
        Initialize-WelaFileSaclRecoveryNative
        $target=[Wela.FileSaclRecovery.Target]::new((Resolve-WelaSelectedSaclNativePath $plan.Definition))
        try {$report.After=$target.Remove($plan.Expected.Identity,$plan.Expected.DescriptorBase64,$plan.AddedAce)} finally {$report.WriteAttempted=$target.WriteAttempted;if ($target.AfterObservation) {$report.After=$target.AfterObservation;$report.SaclAfter=[Wela.FileSaclRecovery.Descriptor]::SaclRepresentation($report.After.DescriptorBase64)}}
        $target.Dispose();$target=$null
        $fresh=Get-WelaFileSaclRecoverySnapshot $plan.Definition
        if ((Get-WelaSelectedSaclSnapshotKey $fresh) -cne (Get-WelaSelectedSaclSnapshotKey $report.After)) {throw 'File identity or descriptor changed after removal.'}
        if ((Get-WelaFileSaclRecoveryKey (Get-WelaFileSaclRecoverySources)) -cne (Get-WelaFileSaclRecoveryKey $plan.Sources) -or (Get-WelaFileSaclRecoveryKey (Get-WelaFileSaclRecoveryOperator)) -cne (Get-WelaFileSaclRecoveryKey $plan.Operator) -or (Get-WelaSelectedSaclContext).Key -cne $plan.ContextKey) {throw 'Recovery context changed after removal.'}
        foreach ($entry in $plan.OriginalFiles.PSObject.Properties) {if ((Read-WelaFileSaclRecoveryInput $entry.Value.Path).Sha256 -cne $entry.Value.Sha256) {throw 'Original recovery evidence changed after removal.'}}
        if ((Read-WelaFileSaclRecoveryInput $reviewed.Path).Sha256 -cne $PlanHash) {throw 'Reviewed plan changed after removal.'}
        foreach ($artifact in $report.Artifacts) {if ((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $artifact.Sha256) {throw 'Recovery artifact changed after writing.'}}
        if ((Get-WelaSelectedSaclSnapshotKey (Get-WelaFileSaclRecoverySnapshot $plan.Definition)) -cne (Get-WelaSelectedSaclSnapshotKey $report.After)) {throw 'Final reopened file differs after recovery.'}
        $report.OriginalDescriptorBytesMatch=$report.After.DescriptorBase64 -ceq $plan.BeforeAddition.DescriptorBase64
        $report.Status='AddedAceRemoved';$report.ExitCode=0
    } catch {$report.Diagnostic=$_.Exception.Message;if ($report.WriteAttempted) {$report.Status='WriteAttemptedUnverified'}}
    finally {if ($target) {try {$target.Dispose()} catch {$report.Status='WriteAttemptedUnverified';$report.ExitCode=1;$report.Diagnostic+=' Native cleanup failed: '+$_.Exception.Message}}}
    $report.CompletedUtc=[DateTime]::UtcNow.ToString('o')
    $null=Write-WelaFileSaclRecoveryArtifact $output 'result.json' (Get-WelaFileSaclRecoveryKey $report)
    $report
}

function Write-WelaFileSaclRecoveryArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaArrivalPath $Root
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);$path=Join-Path $Root $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    $hash=Get-WelaArrivalHash $bytes
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $hash) {throw 'Recovery artifact readback differs.'}
    [pscustomobject]@{Name=$Name;Sha256=$hash;Bytes=$bytes.Length}
}
