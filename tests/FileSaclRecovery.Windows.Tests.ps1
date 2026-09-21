param([switch]$AllowDisposableSaclWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableSaclWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/Configuration.ps1')
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Fingerprint($Map){(@($Map.Keys|Sort-Object|ForEach-Object{"$_=$($Map[$_])"}) -join ';')}
function Json($Path){Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
function Save($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))}
$policyBefore=Get-WelaEffectiveAuditPolicy
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceBefore=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
$nonce=[guid]::NewGuid().ToString('N');$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-file-recovery-'+$nonce);$copy=Join-Path $temp 'checkout'
$engine=(Get-Process -Id $PID).Path
$script:call=0
function Run-Wela {
    param([string[]]$Arguments,[int]$Expected=0,[string]$Pattern='')
    $script:call++;$log=Join-Path $temp ('call-'+$script:call+'.log')
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$engine;$start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $all=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $copy 'WELA.ps1'))+$Arguments
    $start.Arguments=(@($all|ForEach-Object {'"'+$_.Replace('"','\"')+'"'}) -join ' ')
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {$null=$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync();if(-not $process.WaitForExit(180000)){$process.Kill();throw 'Public recovery fixture command timed out.'};if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($out,$err),10000)){throw 'Public fixture output capture timed out.'};$text=$out.Result+$err.Result;[IO.File]::WriteAllText($log,$text);Assert ($process.ExitCode -eq $Expected) "Public command failed with $($process.ExitCode), expected $Expected. $text";if($Pattern){Assert ($text -match $Pattern) "Expected diagnostic $Pattern. $text"}}finally{if($process.Id -and -not $process.HasExited){$process.Kill();$null=$process.WaitForExit(10000)};$process.Dispose()}
}
$completed=$false
try {
    $null=New-Item -ItemType Directory $copy -Force
    foreach($name in @('WELA.ps1','config','scripts','modules')){Copy-Item -LiteralPath (Join-Path $root $name) -Destination $copy -Recurse}
    # Only the owned disposable checkout gets this installed one-file catalog.
    # Production command and receipt validation expose no arbitrary-target override.
    $file=Join-Path $temp 'owned.txt';[IO.File]::WriteAllText($file,'owned recovery fixture')
    $catalog=[pscustomobject]@{description='Owned disposable installed catalog';registry=@();files=@([pscustomobject]@{path=$file;inherit=$false;rights=@('ReadData');note='Owned leaf'});user_registry=@();user_files=@()}
    Save (Join-Path $copy 'config/audit_sacl_targets.json') $catalog
    Import-Module (Join-Path $copy 'modules/AuditProfiles.psm1') -Force
    . (Join-Path $copy 'scripts/ControlApplicability.ps1')
    . (Join-Path $copy 'scripts/TargetedSaclPlanning.ps1')
    . (Join-Path $copy 'scripts/SelectedSaclConfiguration.ps1')
    . (Join-Path $copy 'scripts/WefArrival.ps1')
    . (Join-Path $copy 'scripts/EvtxRecovery.ps1')
    . (Join-Path $copy 'scripts/FileSaclRecovery.ps1')
    Initialize-WelaFileSaclRecoveryNative
    Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
    Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask 3 -Mode minimum
    $context=Get-WelaSelectedSaclContext
    $target=@((Get-WelaSelectedSaclCatalog -Profile wela-2.2.0 -IncludeOptional -Context $context).Rows)
    Assert ($target.Count -eq 1 -and $target[0].Definition.Path -ceq $file) 'Installed fixture catalog selects only the owned leaf.'
    $id=$target[0].Id;$definition=$target[0].Definition
    foreach($case in @('empty','unrelated')){
        $caseDir=Join-Path $temp $case;$null=New-Item -ItemType Directory $caseDir
        if($case -eq 'unrelated'){
            $beforeUnrelated=Get-WelaSelectedSaclSnapshot $definition
            $other=[pscustomobject]@{Sid='S-1-5-11';Mask=2;Flags=64;RequiredPolicyMask=1}
            $null=Write-WelaSelectedSaclNative $definition $beforeUnrelated $other
        }
        $before=Get-WelaSelectedSaclSnapshot $definition
        $original=Join-Path $caseDir 'original.json';$backup=Join-Path $caseDir 'receipts';$configured=Join-Path $caseDir 'configured.json'
        Run-Wela @('targeted-sacl','-TargetSaclAction','Plan','-TargetSaclProfile','wela-2.2.0','-TargetSaclId',$id,'-IncludeOptional','-ResultsPath',$original)
        Run-Wela @('targeted-sacl','-TargetSaclAction','Configure','-TargetSaclPlanPath',$original,'-TargetSaclId',$id,'-IncludeOptional','-Auto','-BackupPath',$backup,'-ResultsPath',$configured)
        $completedAddition=Json $configured
        Assert ($completedAddition.Results[0].Status -ceq 'Applied' -and $completedAddition.ExitCode -eq 0) 'Original public Configure supplied genuine Applied result and receipt pair.'
        $pending=Join-Path $backup ($id+'.pending.json');$confirmed=Join-Path $backup ($id+'.confirmed.json')
        $afterAddition=Get-WelaSelectedSaclSnapshot $definition
        $planDir=Join-Path $caseDir 'recovery-plan'
        $planArgs=@('file-sacl-recovery','-FileSaclRecoveryOriginalPlanPath',$original,'-FileSaclRecoveryPendingPath',$pending,'-FileSaclRecoveryConfirmedPath',$confirmed,'-FileSaclRecoveryResultsPath',$configured)
        Run-Wela ($planArgs+@('-FileSaclRecoveryOutputPath',$planDir))
        $planPath=Join-Path $planDir 'plan.json';$hash=(Get-FileHash $planPath).Hash.ToLowerInvariant();$plan=Json $planPath
        Assert ($plan.Kind -ceq 'WelaFileSaclRecoveryPlan' -and $plan.Expected.Identity -ceq $before.Identity -and $plan.ReadyRuleCredit -eq 0) 'Recovery plan binds the original actual file identity without telemetry credit.'
        $restore=@('file-sacl-recovery','-FileSaclRecoveryAction','Restore','-FileSaclRecoveryPlanPath',$planPath,'-FileSaclRecoveryPlanHash',$hash)
        Run-Wela ($restore+@('-DryRun'))
        Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $afterAddition)) 'Public dry run preserves the exact current full descriptor.'
        if($case -eq 'empty'){
            $saved=[IO.File]::ReadAllBytes($confirmed);$broken=Json $confirmed;$broken.State='Pending';Save $confirmed $broken
            Run-Wela ($restore+@('-DryRun')) 1 'pending and confirmed'
            [IO.File]::WriteAllBytes($confirmed,$saved)
            $nativePath=Join-Path $copy 'scripts/FileSaclRecoveryNative.cs';$nativeBytes=[IO.File]::ReadAllBytes($nativePath);[IO.File]::AppendAllText($nativePath,"`n// owned source mismatch fixture`n")
            Run-Wela ($restore+@('-DryRun')) 1 'stale or modified'
            [IO.File]::WriteAllBytes($nativePath,$nativeBytes)
            # A different file at the identical path must not inherit recovery authority.
            $held=Join-Path $caseDir 'original-held.txt';Move-Item -LiteralPath $file -Destination $held;[IO.File]::WriteAllText($file,'replacement')
            Run-Wela ($restore+@('-DryRun')) 1 'identity or descriptor differs'
            Remove-Item -LiteralPath $file;Move-Item -LiteralPath $held -Destination $file
            Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $afterAddition)) 'Refused receipt/source/replacement cases did not alter the original descriptor.'
        }
        $out=Join-Path $caseDir 'restored'
        Run-Wela ($restore+@('-Auto','-FileSaclRecoveryOutputPath',$out))
        $result=Json (Join-Path $out 'result.json');$after=Get-WelaSelectedSaclSnapshot $definition
        Assert ($result.Status -ceq 'AddedAceRemoved' -and $result.WriteAttempted -and $result.ExitCode -eq 0 -and $result.PolicyChanges -eq 0) 'Public recovery performs and verifies only the proven added ACE removal.'
        [Wela.FileSaclRecovery.Descriptor]::Removed($afterAddition.DescriptorBase64,$after.DescriptorBase64,$plan.AddedAce)
        Assert ($before.Identity -ceq $after.Identity -and $before.Owner -ceq $after.Owner -and $before.Group -ceq $after.Group -and $before.DaclBase64 -ceq $after.DaclBase64 -and $before.Aces.Count -eq $after.Aces.Count) 'Actual reopened leaf preserves identity, owner/group/DACL and unrelated ACE counts.'
        foreach($artifact in $result.Artifacts){Assert ($artifact.Sha256 -ceq (Get-FileHash (Join-Path $out $artifact.Name)).Hash.ToLowerInvariant()) 'Durable review and pre-write intent artifacts retain their recorded hashes.'}
        Assert ((Json (Join-Path $out 'pending.json')).Before.DescriptorBase64 -ceq $afterAddition.DescriptorBase64) 'Pending receipt records the exact descriptor reviewed before removal.'
        Run-Wela ($restore+@('-DryRun')) 1 'identity or descriptor differs'
        Write-Host "PASS: actual public leaf recovery $case, original identity $($before.Identity), $($before.Aces.Count) unrelated ACEs preserved."
    }
    $completed=$true
} finally {
    Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask $policyBefore['0CCE921D-69AE-11D9-BED3-505054503030'] -Mode exact
    if($precedenceBefore.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type $precedenceBefore.Type -Value $precedenceBefore.Value}else{Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue}
    Assert ((Fingerprint (Get-WelaEffectiveAuditPolicy)) -ceq (Fingerprint $policyBefore) -and ((Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy)|ConvertTo-Json -Compress) -ceq ($precedenceBefore|ConvertTo-Json -Compress)) 'All 59 original policy masks and typed precedence restored.'
    if($completed){Remove-Item -LiteralPath $temp -Recurse -Force;Write-Host "PASS: $script:count actual public file recovery assertions; only owned files and checkout removed."}else{Write-Host "Failed fixture evidence retained at $temp"}
}
$global:LASTEXITCODE=0
