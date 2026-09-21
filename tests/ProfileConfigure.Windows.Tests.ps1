param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-profile-configure-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$count=0;$failure=$null;$cleanupErrors=@()
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 30 | Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 25 -Compress}
function Masks($Value){@($Value.Keys|Sort-Object|ForEach-Object{"$_=$($Value[$_])"}) -join ';'}
function Public([string]$Label,[string[]]$Arguments,[int]$Expected=0){
    $prior=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') @Arguments 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
    $output|Set-Content -LiteralPath (Join-Path $root ($Label+'.txt')) -Encoding UTF8
    Assert ($code -eq $Expected) "Public $Label exited $code, expected $Expected : $output"
}
function Channels { @(foreach($name in @('Security','System','Application','ForwardedEvents','Microsoft-Windows-CAPI2/Operational')){Get-WelaNativeChannel $name}) }
function TypedPrecedence {Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy}
$before=Get-WelaEffectiveAuditPolicy;$precedence=TypedPrecedence;$channels=Channels
$hostState=Get-WelaHostContext
Assert ($hostState.Role -eq 'MemberServer' -and $hostState.Build -in @(20348,26100)) 'Only the actual hosted server context is supported by this fixture.'
$catalog=Join-Path $repo 'config/audit_profiles.json';$example=Join-Path $repo 'config/custom-audit-profile.example.json'
$catalogHash=(Get-FileHash $catalog).Hash;$exampleHash=(Get-FileHash $example).Hash
$profilePath=Join-Path $root 'profile.json'
$custom=Get-Content $example -Raw|ConvertFrom-Json
$custom.profiles[0].id='custom-native-acceptance'
$custom.profiles[0].appliesTo=@([pscustomobject]@{roles=@($hostState.Role);minBuild=$hostState.Build;maxBuild=$hostState.Build})
$custom.profiles[0].note='Disposable native acceptance fixture; no baseline or detection claim.'
Save 'profile.json' $custom
$sourceHash=(Get-FileHash $profilePath).Hash.ToLowerInvariant()
$ids=@{Creation='0CCE922B-69AE-11D9-BED3-505054503030';Termination='0CCE922C-69AE-11D9-BED3-505054503030';Share='0CCE9244-69AE-11D9-BED3-505054503030';File='0CCE921D-69AE-11D9-BED3-505054503030'}
$base=@('-Profile','custom-native-acceptance','-ProfileFile',$profilePath,'-SaclMode','Skip')
Save 'original.json' @{Host=$hostState;Engine=$PSVersionTable.PSVersion.ToString();Masks=$before;Precedence=$precedence;Channels=$channels;Sources=@{Custom=$sourceHash;Catalog=$catalogHash;Example=$exampleHash}}
try{
    # Fixture-only initial values distinguish exact, minimum, optional and NC semantics.
    $null=New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -PropertyType DWord -Value 0 -Force
    Set-WelaEffectiveAuditPolicy -Guid $ids.Creation -Mask 2 -Mode exact
    Set-WelaEffectiveAuditPolicy -Guid $ids.Termination -Mask 3 -Mode exact
    Set-WelaEffectiveAuditPolicy -Guid $ids.Share -Mask 1 -Mode exact
    Set-WelaEffectiveAuditPolicy -Guid $ids.File -Mask 0 -Mode exact
    $seed=Get-WelaEffectiveAuditPolicy;$seedPrecedence=TypedPrecedence
    Save 'seeded.json' @{Masks=$seed;Precedence=$seedPrecedence}
    $planPath=Join-Path $root 'plan.json'
    Public 'plan' (@('plan')+$base+@('-PlanPath',$planPath))
    $plan=Get-Content $planPath -Raw|ConvertFrom-Json
    Assert ($plan.role -eq $hostState.Role -and $plan.build -eq $hostState.Build -and $plan.policies.Count -eq 59) 'Public Plan retains actual context and all59 controls.'
    Assert ($plan.CustomProfileSource.Sha256 -ceq $sourceHash) 'Plan binds the selected custom source bytes.'
    $dryPath=Join-Path $root 'dry.json';$dryBackup=Join-Path $root 'dry-backup'
    Public 'dry' (@('configure')+$base+@('-Auto','-DryRun','-BackupPath',$dryBackup,'-ResultsPath',$dryPath))
    $dry=Get-Content $dryPath -Raw|ConvertFrom-Json
    Assert ($dry.DryRun -and $dry.ExitCode -eq 0 -and -not(Test-Path $dryBackup)) 'DryRun returns explicit preview without creating a journal.'
    Assert ((Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $seed) -and (Key (TypedPrecedence)) -ceq (Key $seedPrecedence)) 'Plan/DryRun preserve all59 masks and typed precedence.'
    Public 'wrong-role' (@('configure')+$base+@('-Auto','-Role','Client','-Build',[string]$hostState.Build,'-BackupPath',(Join-Path $root 'wrong-backup'),'-ResultsPath',(Join-Path $root 'wrong.json'))) 1
    Assert (-not(Test-Path (Join-Path $root 'wrong-backup')) -and (Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $seed)) 'Mismatched actual role refuses before native writes or a journal.'
    $backup=Join-Path $root 'configure-backup';$resultPath=Join-Path $root 'configured.json'
    Public 'configure' (@('configure')+$base+@('-Auto','-BackupPath',$backup,'-ResultsPath',$resultPath))
    $result=Get-Content $resultPath -Raw|ConvertFrom-Json
    $expected=$seed.Clone();$expected[$ids.Creation]=3;$expected[$ids.Termination]=1
    Assert ((Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $expected)) 'Actual Configure enables minimum Success without clearing Failure, applies exact Success, and preserves optional/NC/omitted controls.'
    Assert ((TypedPrecedence).Type -eq 'DWord' -and (TypedPrecedence).Value -eq 1) 'Public Configure applies and verifies actual DWORD precedence before audit writes.'
    Assert ($result.ExitCode -eq 0 -and $result.Scope -ceq 'advanced-audit-policy-and-precedence' -and $result.ProfileScope -ceq 'advanced-audit-policy-only') 'Completed public results retain the narrow scope and success.'
    Assert ($result.CustomProfileSource.Sha256 -ceq $sourceHash -and $result.CustomProfileSource.CanonicalSha256 -ieq $catalogHash) 'Completed result retains source and canonical catalog fingerprints.'
    $journal=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json)
    Assert ($journal.Count -eq 3 -and $journal[0].Target.Name -ceq 'SCENoApplyLegacyAuditPolicy') 'Only precedence and the two changed subcategories are journaled, in prerequisite order.'
    foreach($entry in $journal){
        $row=@($result.Results|Where-Object Id -ceq $entry.Id)
        Assert ($row.Count -eq 1 -and $row[0].Status -ceq 'Applied' -and (Key $row[0].Before) -ceq (Key $entry.Before)) 'Every native write has matching original journal and Applied result.'
    }
    $repeatPath=Join-Path $root 'repeat.json';$repeatBackup=Join-Path $root 'repeat-backup'
    Public 'repeat' (@('configure')+$base+@('-Auto','-BackupPath',$repeatBackup,'-ResultsPath',$repeatPath))
    $repeat=Get-Content $repeatPath -Raw|ConvertFrom-Json
    Assert ($repeat.ExitCode -eq 0 -and @($repeat.Results|Where-Object Status -eq 'Applied').Count -eq 0 -and (Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $expected)) 'Repeated public Configure is idempotent with no native write.'
    $optionalPath=Join-Path $root 'optional.json'
    Public 'optional' (@('configure')+$base+@('-Auto','-IncludeOptional','-BackupPath',(Join-Path $root 'optional-backup'),'-ResultsPath',$optionalPath))
    $optional=Get-Content $optionalPath -Raw|ConvertFrom-Json;$expected[$ids.File]=3
    Assert ($optional.ExitCode -eq 0 -and (Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $expected)) 'Explicit IncludeOptional changes only File System; all other masks are preserved.'
    Assert (@($optional.Results|Where-Object Status -eq 'Applied').Count -eq 1) 'Optional second stage records exactly one applied control.'
    $auditPath=Join-Path $root 'audit.json'
    Public 'audit' (@('audit-settings')+$base+@('-IncludeOptional','-PlanPath',$auditPath))
    $audit=Get-Content $auditPath -Raw|ConvertFrom-Json
    Assert ($audit.policies.Count -eq 59 -and $audit.CustomProfileSource.Sha256 -ceq $sourceHash) 'Post-configure public Audit reads the same59 controls and source.'
    Assert ((Key (Channels)) -ceq (Key $channels)) 'Advanced-audit-only configuration preserves native channel configuration.'
    Assert ((Get-FileHash $profilePath).Hash -ieq $sourceHash -and (Get-FileHash $catalog).Hash -ceq $catalogHash -and (Get-FileHash $example).Hash -ceq $exampleHash) 'No input policy or canonical source file was changed.'
    Save 'completed.json' @{Status='Passed';Assertions=$count;ExpectedMasks=$expected;ObservedMasks=Get-WelaEffectiveAuditPolicy;Scope='Actual public custom-profile advanced policy/precedence only; no GPO refresh, event generation or Sigma claim.'}
}catch{$failure=$_.ToString();throw}finally{
    try{
        $now=Get-WelaEffectiveAuditPolicy
        foreach($guid in $before.Keys){if($now[$guid] -ne $before[$guid]){Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $before[$guid] -Mode exact}}
    }catch{$cleanupErrors+=$_.ToString()}
    try{
        if($precedence.ValueExists){$null=New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -PropertyType $precedence.Type -Value $precedence.Value -Force}
        else{Remove-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop}
    }catch{$cleanupErrors+=$_.ToString()}
    $masksOk=$false;$precedenceOk=$false;$channelsOk=$false
    try{$masksOk=(Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $before);$precedenceOk=(Key (TypedPrecedence)) -ceq (Key $precedence);$channelsOk=(Key (Channels)) -ceq (Key $channels)}catch{$cleanupErrors+=$_.ToString()}
    Save 'cleanup.json' @{Failure=$failure;Errors=$cleanupErrors;All59MasksRestored=$masksOk;TypedPrecedenceRestored=$precedenceOk;ChannelsPreserved=$channelsOk;Complete=($masksOk -and $precedenceOk -and $channelsOk -and -not $cleanupErrors.Count)}
    if(-not $masksOk -or -not $precedenceOk -or -not $channelsOk -or $cleanupErrors.Count){throw 'Native profile fixture cleanup failed; inspect retained evidence.'}
}
Write-Host "PASS: $count public native profile configuration assertions and exact cleanup."
exit 0
