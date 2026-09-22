# Mutating test fixture only: public WELA never loads hives or prepares audit policy.
param([switch]$AllowDisposableHiveWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableHiveWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable GitHub-hosted native Windows fixture only.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WmiProbe','ChannelRead','SelectedSaclConfiguration')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
. (Join-Path $PSScriptRoot 'RegistrySaclLifecycleEvidence.ps1')
Initialize-WelaWmiProbeNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistrySaclFixtureNative.cs') -ErrorAction Stop
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-registry-sacl-'+[guid]::NewGuid().ToString('N'))) $script:ScriptRoot
$files=Join-Path $root 'owned-hive-files';$null=New-Item -ItemType Directory $files
function Save([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),($Value|ConvertTo-Json -Depth 28),[Text.UTF8Encoding]::new($false))}
function Read-Receipt([string]$Name){ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $root $Name)))}
function Hives {@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()|Sort-Object)}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
$script:assertions=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:assertions++}
function Invoke-PublicFixture([string]$Name,[string[]]$Arguments,[int]$ExpectedExit=0,[string]$Diagnostic=''){
    $old=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $script:ScriptRoot 'WELA.ps1') targeted-sacl @Arguments -ResultsPath (Join-Path $root ($Name+'.json')) 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old;$global:LASTEXITCODE=0}
    Save ($Name+'-output.json') @($output|ForEach-Object {[string]$_})
    Assert ($code -eq $ExpectedExit) ("Public $Name exited $code : "+($output -join ' '))
    if($Diagnostic){Assert (($output -join ' ') -match $Diagnostic) ("Public $Name did not report the expected refusal: "+($output -join ' '))}
    if($ExpectedExit -eq 0){Read-Receipt ($Name+'.json')}
}
function Assert-SelectedRow($Plan,[string]$Status){
    Assert ($Plan.Kind -is [string] -and $Plan.Kind -ceq 'WelaSelectedSaclPlan' -and @($Plan.Rows).Count -eq 1 -and $Plan.Rows[0].Id -is [string] -and $Plan.Rows[0].Id -ceq $selected.Id -and $Plan.Rows[0].Status -is [string] -and $Plan.Rows[0].Status -ceq $Status) ('Exact public selected row must be '+$Status)
    Assert ($Plan.Rows[0].Definition.UserSid -ceq $hive.Sid -and $Plan.Rows[0].Definition.Path -ieq $providerPath -and $Plan.GenerationReadiness -ceq 'Conditional' -and $Plan.UsableRuleCredit -eq 0) 'Public plan must remain bound to the owned target without generation/Sigma credit.'
}
function Assert-PreparedState {
    Assert ((Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key)) -ceq $preparedMasks) 'Public selected-SACL calls must preserve all 59 prepared audit masks.'
    Assert ((Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq $preparedPrecedence) 'Public selected-SACL calls must preserve typed precedence.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'Current process token groups and privilege attributes must remain exact.'
    $hive.AssertValues($false)
}
$engine=(Get-Process -Id $PID).Path;$guid='0CCE921E-69AE-11D9-BED3-505054503030'
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceName='SCENoApplyLegacyAuditPolicy'
$beforeHives=Hives;$beforeToken=[Wela.WmiProbe.Native]::Snapshot();$beforeMasks=Get-WelaEffectiveAuditPolicy;$beforePrecedence=Get-WelaRegistryState $precedencePath $precedenceName
Save 'before-hives.json' $beforeHives;Save 'before-token.json' $beforeToken;Save 'before-masks.json' $beforeMasks;Save 'before-precedence.json' $beforePrecedence
$hive=[Wela.RegistrySaclFixture.Hive]::new([guid]::NewGuid().ToString('N'),(Join-Path $files 'owned.dat'));$failure=$null;$cleanupErrors=@();$policyTouched=$false
try {
    Assert ($beforeMasks.Count -eq 59) 'All 59 native audit subcategories must be observed before fixture mutation.'
    $hive.Prepare();$hive.CreateRunOnce();$hive.AssertOwned();$hive.AssertValues($false)
    Assert ((Key (Hives)) -ceq (Key (@($beforeHives)+$hive.Sid|Sort-Object))) 'Only the fresh owned SID hive may appear in HKU.'
    $providerPath='Registry::HKEY_USERS\'+$hive.Sid+'\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Save 'mounted.json' ([pscustomobject]@{Sid=$hive.Sid;File=$hive.FilePath;Seed=$hive.SeedPath;Loaded=$hive.Loaded;Target=$providerPath})
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'Fixture save/load must restore existing backup/restore privilege attributes.'
    $catalog=Invoke-PublicFixture 'catalog' @('-TargetSaclProfile','asd-native-2021-10','-IncludeOptional')
    $selectedRows=@($catalog.Catalog|Where-Object {$_.Definition.UserSid -ceq $hive.Sid -and $_.Definition.Path -ieq $providerPath})
    Assert ($selectedRows.Count -eq 1 -and $selectedRows[0].Id -cmatch '^sacl-[a-f0-9]{24}$' -and $selectedRows[0].Definition.Resolution -ceq 'Resolved') 'Actual public catalog must resolve exactly one owned registry target.'
    $selected=$selectedRows[0];Save 'selected.json' $selected
    # Seed a distinct explicit SYSTEM QueryValue audit ACE to prove additive preservation.
    Initialize-WelaSelectedSaclNative;$privilege=[Wela.SelectedSacl.Privilege]::new();$target=$null
    try{$target=[Wela.SelectedSacl.Target]::new('Registry',(Resolve-WelaSelectedSaclNativePath $selected.Definition));$original=$target.Read();$seeded=$target.Add($original.Identity,$original.DescriptorBase64,'S-1-5-18',1,64)}finally{if($target){$target.Dispose()};$privilege.Dispose()}
    Save 'before-public-snapshot.json' $seeded
    $policyTouched=$true
    Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Type DWord -Value 1
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 3 -Mode exact
    $preparedMasks=Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key);$preparedPrecedence=Key (Get-WelaRegistryState $precedencePath $precedenceName)
    $selection=@('-TargetSaclProfile','asd-native-2021-10','-TargetSaclId',$selected.Id,'-IncludeOptional')
    $noConsent=Invoke-PublicFixture 'no-consent-plan' ($selection+@('-TargetSaclAction','Plan'))
    Assert-SelectedRow $noConsent 'Blocked'
    $refusedBackup=Join-Path $root 'refused-no-consent'
    Invoke-PublicFixture 'no-consent-configure' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',(Join-Path $root 'no-consent-plan.json'),'-BackupPath',$refusedBackup,'-Auto')) 1 'inheritance requires explicit'
    Assert (-not(Test-Path -LiteralPath $refusedBackup)) 'Missing inheritance consent must fail before journal creation.'
    $selection+=@('-TargetSaclIncludeChildren')
    $plan=Invoke-PublicFixture 'plan' ($selection+@('-TargetSaclAction','Plan'))
    Assert-SelectedRow $plan 'ChangeRequired'
    Assert ($plan.Rows[0].DescendantsBefore.Status -ceq 'Complete' -and @($plan.Rows[0].DescendantsBefore.Entries).Count -eq 0) 'Owned RunOnce must have a complete empty descendant capture.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $plan.Rows[0].Before) -ceq (Get-WelaSelectedSaclSnapshotKey $seeded)) 'Read-only planning must preserve the entire native target descriptor/identity.'
    $configure=$selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',(Join-Path $root 'plan.json'),'-Auto')
    $dry=Invoke-PublicFixture 'dry-run' ($configure+@('-DryRun'))
    Assert ($dry.Kind -ceq 'WelaSelectedSaclResult' -and $dry.DryRun -is [bool] -and $dry.DryRun -and $dry.Results[0].Status -is [string] -and $dry.Results[0].Status -ceq 'Skipped' -and $null -eq $dry.BackupPath) 'Public DryRun must skip mutation and journal creation.'
    Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $selected.Definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $seeded)) 'DryRun must leave the exact native descriptor unchanged.'
    Assert-PreparedState
    $backup=Join-Path $root 'applied-journal'
    $applied=Invoke-PublicFixture 'applied' ($configure+@('-BackupPath',$backup))
    Assert ($applied.Results.Count -eq 1 -and $applied.Results[0].Status -is [string] -and $applied.Results[0].Status -ceq 'Applied' -and $applied.GenerationReadiness -ceq 'Conditional' -and $applied.UsableRuleCredit -eq 0) 'Exactly the owned target must be Applied without event or rule credit.'
    $after=Get-WelaSelectedSaclSnapshot $selected.Definition;Save 'after-public-snapshot.json' $after
    Assert-WelaSelectedSaclPreserved $seeded $after $plan.Rows[0].Ace
    Assert ($after.Aces.Count -eq $seeded.Aces.Count+1) 'Public Configure must append exactly one ACE and preserve the unrelated explicit audit ACE.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $after) -ceq (Get-WelaSelectedSaclSnapshotKey $applied.Results[0].After)) 'Public result must match independent native final readback.'
    $pending=Read-Receipt ('applied-journal/'+$selected.Id+'.pending.json');$confirmed=Read-Receipt ('applied-journal/'+$selected.Id+'.confirmed.json');$desc=Read-Receipt ('applied-journal/'+$selected.Id+'.descendants-observed.json')
    Assert ($pending.State -is [string] -and $pending.State -ceq 'Pending' -and $null -eq $pending.After -and $confirmed.State -is [string] -and $confirmed.State -ceq 'Confirmed' -and $pending.Id -ceq $selected.Id -and $confirmed.Id -ceq $selected.Id -and $desc.Verification.Status -ceq 'Observed') 'Durable pending/confirmed and descendant receipts must name the exact selected target.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $pending.Before) -ceq (Get-WelaSelectedSaclSnapshotKey $seeded) -and (Get-WelaSelectedSaclSnapshotKey $confirmed.After) -ceq (Get-WelaSelectedSaclSnapshotKey $after)) 'Journal snapshots must agree with both independent native observations.'
    Assert-PreparedState
    $staleBackup=Join-Path $root 'refused-stale'
    Invoke-PublicFixture 'stale-configure' ($configure+@('-BackupPath',$staleBackup)) 1 'changed; review a new plan'
    Assert (-not(Test-Path -LiteralPath $staleBackup)) 'Replaying the old descriptor must fail before another journal.'
    $fresh=Invoke-PublicFixture 'idempotent-plan' ($selection+@('-TargetSaclAction','Plan'))
    Assert-SelectedRow $fresh 'AlreadyCompliant'
    $idemBackup=Join-Path $root 'idempotent-journal'
    $idempotent=Invoke-PublicFixture 'idempotent' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',(Join-Path $root 'idempotent-plan.json'),'-BackupPath',$idemBackup,'-Auto'))
    Assert ($idempotent.Results[0].Status -is [string] -and $idempotent.Results[0].Status -ceq 'AlreadyCompliant' -and @(Get-ChildItem -LiteralPath $idemBackup -Force).Count -eq 0) 'Fresh idempotent public Configure must make no write receipts.'
    Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $selected.Definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $after)) 'Stale refusal and idempotent Configure must preserve exact native state.'
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 0 -Mode exact
    $blocked=Invoke-PublicFixture 'missing-policy-plan' ($selection+@('-TargetSaclAction','Plan'))
    Assert-SelectedRow $blocked 'Blocked'
    $policyBackup=Join-Path $root 'refused-policy'
    Invoke-PublicFixture 'missing-policy-configure' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',(Join-Path $root 'idempotent-plan.json'),'-BackupPath',$policyBackup,'-Auto')) 1 'outcomes are not already effective'
    Assert (-not(Test-Path -LiteralPath $policyBackup) -and (Get-WelaEffectiveAuditPolicy)[$guid] -eq 0) 'Public Configure must refuse ineffective auditing without preparing policy or a journal.'
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 3 -Mode exact
    Assert-PreparedState
    $boundary=Read-WelaChannelLatest 'Security';Save 'security-boundary.json' $boundary
    Assert ($boundary.Status -ceq 'EventObserved' -and $boundary.Event.RecordId -gt 0) 'Actual Security watermark must be observed before the single value write.'
    $operation=[pscustomobject]@{Phase='OneRegSetValueAndSameHandleTypedReadback';Computer=$boundary.Event.Computer;ProcessId=$PID;Engine=$engine;NativePath=('\REGISTRY\USER\'+$hive.Sid+'\Software\Microsoft\Windows\CurrentVersion\RunOnce');RecordIdBefore=$boundary.Event.RecordId;Token=[Wela.WmiProbe.Native]::Snapshot();Write=$hive.WriteProbe();ObservedUtc=[Wela.WmiProbe.Native]::UtcNow().ToString('o')}
    Save 'operation.json' $operation
    Assert ($operation.Write.Calls -eq 1 -and $operation.Write.Success -is [bool] -and $operation.Write.Success -and (ConvertTo-WelaArrivalUtc $operation.Write.StartedUtc) -le (ConvertTo-WelaArrivalUtc $operation.Write.ReturnedUtc) -and (ConvertTo-WelaArrivalUtc $operation.Write.ReturnedUtc) -le (ConvertTo-WelaArrivalUtc $operation.Write.CompletedUtc) -and (ConvertTo-WelaArrivalUtc $operation.Write.CompletedUtc) -le (ConvertTo-WelaArrivalUtc $operation.ObservedUtc)) 'Exactly one native write and its same-handle typed readback must have ordered measured times.'
    $hive.AssertValues($true)
    $found=@{};$candidates=@{};$deadline=[DateTime]::UtcNow.AddSeconds(20)
    $xpath="*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4657 and EventRecordID > $($boundary.Event.RecordId)]] and *[EventData[Data[@Name='ObjectName']='$($operation.NativePath)']]"
    do {
        $events=@();try{$events=@(Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 256 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){throw}}
        try {
            if($events.Count -ge 256){throw 'Owned-target native event query reached its bound.'}
            foreach($event in $events){$xml=$event.ToXml();if($xml.Length -gt 131072){throw 'Owned-target event exceeds its XML bound.'};$candidates[[string]$event.RecordId]=$xml;if(Test-WelaRegistrySaclFixtureEvent $xml $operation){$found[[string]$event.RecordId]=$xml}}
        }finally{foreach($event in $events){if($event -is [IDisposable]){$event.Dispose()}}}
        if($found.Count -eq 0){Start-Sleep -Milliseconds 250}
    }while($found.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)
    Save 'event-candidates.json' $candidates
    Assert ($found.Count -eq 1) ('Expected exactly one attributable native4657; candidates='+$candidates.Count+' matches='+$found.Count)
    [IO.File]::WriteAllText((Join-Path $root 'event.xml'),[string]@($found.Values)[0],[Text.UTF8Encoding]::new($false))
    Assert ((Get-WelaSelectedSaclSnapshot $selected.Definition).DescriptorBase64 -ceq $after.DescriptorBase64) 'The value operation must preserve every native descriptor section.'
    Assert ((Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key)) -ceq $preparedMasks -and (Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq $preparedPrecedence) 'Observed event delivery must not alter prepared auditing.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'The actual native value operation must preserve the full primary token.'
}catch{$failure=$_}finally {
    if($policyTouched){
        try{Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $beforeMasks[$guid] -Mode exact}catch{$cleanupErrors+='Audit restore: '+$_.Exception.Message}
        try{if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Type $beforePrecedence.Type -Value $beforePrecedence.Value}else{Remove-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -ErrorAction Stop}}catch{$cleanupErrors+='Precedence restore: '+$_.Exception.Message}
    }
    try{$hive.Dispose()}catch{$cleanupErrors+='Hive unload/seed removal: '+$_.Exception.Message}
    $hivesOk=$false;$tokenOk=$false;$masksOk=$false;$precedenceOk=$false
    $afterHives=$null;$afterToken=$null;$masks=$null;$afterPrecedence=$null
    try{$afterHives=Hives;$hivesOk=(Key $afterHives) -ceq (Key $beforeHives)}catch{$cleanupErrors+='HKU verification: '+$_.Exception.Message}
    try{$afterToken=[Wela.WmiProbe.Native]::Snapshot();$tokenOk=(Key $afterToken) -ceq (Key $beforeToken)}catch{$cleanupErrors+='Token verification: '+$_.Exception.Message}
    try{$masks=Get-WelaEffectiveAuditPolicy;$masksOk=(Key ($masks.GetEnumerator()|Sort-Object Key)) -ceq (Key ($beforeMasks.GetEnumerator()|Sort-Object Key))}catch{$cleanupErrors+='Audit verification: '+$_.Exception.Message}
    try{$afterPrecedence=Get-WelaRegistryState $precedencePath $precedenceName;$precedenceOk=(Key $afterPrecedence) -ceq (Key $beforePrecedence)}catch{$cleanupErrors+='Precedence verification: '+$_.Exception.Message}
    if(-not $hive.Loaded -and $hivesOk){try{Remove-Item -LiteralPath $files -Recurse -Force -ErrorAction Stop}catch{$cleanupErrors+='Owned file removal: '+$_.Exception.Message}}
    $cleanup=[pscustomobject]@{Complete=($hivesOk -and $tokenOk -and $masksOk -and $precedenceOk -and -not $hive.SeedCreated -and -not(Test-Path -LiteralPath $files) -and $cleanupErrors.Count -eq 0);HivesRestored=$hivesOk;TokenRestored=$tokenOk;AuditMasksCompared=$beforeMasks.Count;AuditMasksRestored=$masksOk;PrecedenceRestored=$precedenceOk;HiveUnloaded=(-not $hive.Loaded);SeedRemoved=(-not $hive.SeedCreated);FilesRemoved=(-not(Test-Path -LiteralPath $files));Errors=$cleanupErrors;Failure=$(if($failure){$failure.Exception.Message}else{$null});Assertions=$script:assertions;AfterHives=$afterHives;AfterToken=$afterToken;AfterMasks=$masks;AfterPrecedence=$afterPrecedence}
    Save 'cleanup.json' $cleanup
    $artifacts=@(Get-ChildItem -LiteralPath $root -Recurse -File |Where-Object Name -ne 'artifact-hashes.json'|Sort-Object FullName|ForEach-Object {[pscustomobject]@{Name=$_.FullName.Substring($root.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    Save 'artifact-hashes.json' $artifacts
}
if($failure){throw $failure};if(-not $cleanup.Complete){throw ('Owned registry fixture cleanup incomplete: '+(Key $cleanup))}
Write-Host "Passed $script:assertions actual public registry SACL lifecycle assertions and one exact4657; all cleanup confirmed. Evidence: $root"
$global:LASTEXITCODE=0
