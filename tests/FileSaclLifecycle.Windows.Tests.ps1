# Mutating fixture only: public WELA never registers profiles or loads hives.
param([switch]$AllowDisposableProfileWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableProfileWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable hosted native Windows fixture only.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WmiProbe','ChannelRead','SelectedSaclConfiguration','FileAccessProbe')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
Initialize-WelaWmiProbeNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistrySaclFixtureNative.cs') -ErrorAction Stop
Add-Type -Path (Join-Path $PSScriptRoot 'FileSaclProfileFixture.cs') -ErrorAction Stop
$nonce=[guid]::NewGuid().ToString('N')
$evidence=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-filesystem-lifecycle-'+$nonce)) $script:ScriptRoot
$targetRoot=New-WelaArrivalOutput (Join-Path (Join-Path $env:SystemRoot 'Temp') ('wela-filesystem-sacl-'+$nonce)) $script:ScriptRoot
$files=Join-Path $evidence 'owned-hive-files';$null=New-Item -ItemType Directory $files
function Save([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $evidence $Name),(ConvertTo-Json -InputObject $Value -Depth 32),[Text.UTF8Encoding]::new($false))}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 32 -Compress}
function Hives {@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()|Sort-Object)}
function Read-Receipt([string]$Name){ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $evidence $Name)))}
function Read-PublicReport([string]$Name){$text=Read-Receipt ($Name+'-output.json');$start=$text.IndexOf('{');if($start -lt 0){throw 'Public probe JSON is missing.'};ConvertFrom-WelaArrivalJson $text.Substring($start)}
$engine=(Get-Process -Id $PID).Path
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;
public static class WelaFileSaclLifecyclePipe {
 public static async Task<string> Read(TextReader reader){var text=new StringBuilder();var buffer=new char[1024];while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeds one Mi character bound.");text.Append(buffer,0,n);}}
}
'@
function Public([string]$Name,[string[]]$Arguments,[int]$Expected=0){
    $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $script:ScriptRoot 'WELA.ps1'))+$Arguments
    foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Ambiguous fixture argument.'}}
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
    try{
        if(-not $process.Start()){throw 'Public process did not start.'};$started=$true
        $stdout=[WelaFileSaclLifecyclePipe]::Read($process.StandardOutput);$stderr=[WelaFileSaclLifecyclePipe]::Read($process.StandardError)
        if(-not $process.WaitForExit(180000)){throw 'Public command exceeded three minutes.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public output drain timed out.'}
        $text=$stdout.Result+"`n"+$stderr.Result;Save ($Name+'-output.json') $text
        Assert ($process.ExitCode -eq $Expected) ("Public $Name exited $($process.ExitCode), expected $Expected : "+$text)
    }finally{
        if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:cleanupErrors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:cleanupErrors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:cleanupErrors+=$_.Exception.Message}};if(-not $exited){$script:cleanupErrors+='Owned public process termination unconfirmed.'}}
        $process.Dispose()
    }
}

$script:assertions=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:assertions++}
$beforeProfiles=[Wela.FileSaclFixture.Profile]::Snapshot();$beforeHives=Hives;$beforeToken=[Wela.WmiProbe.Native]::Snapshot()
$beforeMasks=Get-WelaEffectiveAuditPolicy;$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceName='SCENoApplyLegacyAuditPolicy';$beforePrecedence=Get-WelaRegistryState $precedencePath $precedenceName
Save 'before-profiles.json' $beforeProfiles;Save 'before-hives.json' $beforeHives;Save 'before-token.json' $beforeToken;Save 'before-masks.json' $beforeMasks;Save 'before-precedence.json' $beforePrecedence
$hive=[Wela.RegistrySaclFixture.Hive]::new($nonce,(Join-Path $files 'owned.dat'));$profile=$null;$failure=$null;$cleanupErrors=@();$policyTouched=$false;$auditGuid='0CCE921D-69AE-11D9-BED3-505054503030'
try {
    $hive.Prepare();$profile=[Wela.FileSaclFixture.Profile]::new($nonce,$hive.Sid,$targetRoot);$profile.Prepare()
    $signal=Join-Path $profile.AppDataPath 'Signal';$null=New-Item -ItemType Directory $signal
    Public 'catalog' @('targeted-sacl','-TargetSaclProfile','asd-native-2021-10','-IncludeOptional','-ResultsPath',(Join-Path $evidence 'catalog.json'))
    $catalog=Read-Receipt 'catalog.json'
    Save 'owned-profile.json' ([pscustomobject]@{Sid=$hive.Sid;Nonce=$nonce;Root=$targetRoot;ProfilePath=$profile.ProfilePath;AppDataPath=$profile.AppDataPath;SelectedPath=$signal})
    $selectedRows=@($catalog.Catalog|Where-Object {$_.Definition.UserSid -ceq $hive.Sid -and $_.Definition.Kind -ceq 'FileSystem' -and $_.Definition.Path -ieq $signal})
    Assert ($selectedRows.Count -eq 1 -and $selectedRows[0].Definition.Resolution -ceq 'Redirected') 'Real built-in catalog resolves exactly the owned redirected Signal folder.'
    Assert ($selectedRows[0].Definition.PrincipalSid -ceq 'S-1-1-0' -and @($selectedRows[0].Definition.Rights).Count -eq 1 -and $selectedRows[0].Definition.Rights[0] -ceq 'ReadData') 'Owned fixture uses the unchanged built-in read target.'
    Assert ((Key (Hives)) -ceq (Key (@($beforeHives)+$hive.Sid|Sort-Object))) 'Only the owned hive was mounted.'
    $profile.AssertOwned();$hive.AssertOwned()
    Assert (([Wela.FileSaclFixture.Profile]::Snapshot()).Children.Count -eq $beforeProfiles.Children.Count+1) 'Exactly one marker-owned profile entry was registered.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'Fixture profile/hive preparation restores full token state.'
    $selected=$selectedRows[0];Save 'selected.json' $selected
    $policyTouched=$true;Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Type DWord -Value 1;Set-WelaEffectiveAuditPolicy -Guid $auditGuid -Mask 3 -Mode exact
    $preparedMasks=Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key);$preparedPrecedence=Key (Get-WelaRegistryState $precedencePath $precedenceName)
    $open=Join-Path $signal 'open';$protected=Join-Path $signal 'protected';$null=New-Item -ItemType Directory $open,$protected
    Add-Type -Path (Join-Path $PSScriptRoot 'SelectedSaclFixtureProtection.cs') -ErrorAction Stop
    Initialize-WelaSelectedSaclNative;$privilege=[Wela.SelectedSacl.Privilege]::new();$target=$null
    try{
        $protectedBefore=Get-WelaSelectedSaclSnapshot ([pscustomobject]@{Kind='FileSystem';Path=$protected;Resolution='Resolved'})
        [Wela.SelectedSaclFixture.Protection]::Protect('FileSystem',$protected,$protectedBefore.DescriptorBase64,$nonce)
        $target=[Wela.SelectedSacl.Target]::new('FileSystem',$signal);$before=$target.Read();$null=$target.Add($before.Identity,$before.DescriptorBase64,'S-1-5-18',2,64)
    }finally{if($target){$target.Dispose()};$privilege.Dispose()}
    $leaf=Join-Path $open 'ReadLeaf.bin';$protectedLeaf=Join-Path $protected 'ReadLeaf.bin'
    foreach($path in @($leaf,$protectedLeaf)){[IO.File]::WriteAllBytes($path,[byte[]]@(87,69,76,65))}
    $contentBefore=@(foreach($path in @($leaf,$protectedLeaf)){[pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})
    Save 'owned-content-before.json' $contentBefore
    $before=Get-WelaSelectedSaclSnapshot $selected.Definition;$children=Get-WelaSelectedSaclStableDescendants $selected.Definition $before
    Save 'before-public.json' $before;Save 'before-descendants.json' $children
    Assert ($before.Aces.Count -eq 1 -and $before.Aces[0].Sid -ceq 'S-1-5-18' -and $before.Aces[0].Mask -eq 2) 'Fixture seeds only its unrelated root audit ACE.'
    Assert ($children.Status -ceq 'Complete' -and $children.Entries.Count -eq 4 -and @($children.Entries|Where-Object ProtectedBarrier).Count -eq 2) 'Before-state captures exactly four owned descendants and the protected branch.'
    $selection=@('targeted-sacl','-TargetSaclProfile','asd-native-2021-10','-TargetSaclId',$selected.Id,'-IncludeOptional')
    Public 'no-child-consent' ($selection+@('-TargetSaclAction','Plan','-ResultsPath',(Join-Path $evidence 'no-child-plan.json')))
    Assert ((Read-Receipt 'no-child-plan.json').Rows[0].Status -ceq 'Blocked' -and (Read-Receipt 'no-child-plan.json').Rows[0].Diagnostic -match 'IncludeChildren') 'Actual public Plan refuses inherited scope without explicit child consent.'
    $selection+='-TargetSaclIncludeChildren'
    $planPath=Join-Path $evidence 'reviewed-plan.json';Public 'plan' ($selection+@('-TargetSaclAction','Plan','-ResultsPath',$planPath))
    $plan=Read-Receipt 'reviewed-plan.json';$row=$plan.Rows[0]
    Assert ($plan.Rows.Count -eq 1 -and $row.Status -is [string] -and $row.Status -ceq 'ChangeRequired' -and $row.Definition.Resolution -ceq 'Redirected' -and $row.Ace.Mask -eq 1 -and $row.Ace.Flags -eq 195) 'Public reviewed plan selects exactly the redirected catalog root and explicit ReadData inheritance.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $row.Before) -ceq (Get-WelaSelectedSaclSnapshotKey $before) -and (Get-WelaSelectedSaclDescendantKey $row.DescendantsBefore) -ceq (Get-WelaSelectedSaclDescendantKey $children)) 'Public review binds independently observed full native root and descendants.'
    $dryBackup=Join-Path $evidence 'dry-journal'
    Public 'dry-run' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',$planPath,'-DryRun','-BackupPath',$dryBackup,'-ResultsPath',(Join-Path $evidence 'dry-results.json')))
    $dry=Read-Receipt 'dry-results.json'
    Assert ($dry.DryRun -is [bool] -and $dry.DryRun -and $dry.Results[0].Status -ceq 'Skipped' -and -not(Test-Path $dryBackup)) 'Actual public DryRun writes no recovery directory or ACE.'
    Assert ((Get-WelaSelectedSaclDescendantKey (Get-WelaSelectedSaclStableDescendants $selected.Definition (Get-WelaSelectedSaclSnapshot $selected.Definition))) -ceq (Get-WelaSelectedSaclDescendantKey $children)) 'Plan and DryRun preserve all native parent/child state.'
    $appeared=Join-Path $signal 'Appeared.bin';[IO.File]::WriteAllBytes($appeared,[byte[]]@(1))
    $staleBefore=Get-WelaSelectedSaclStableDescendants $selected.Definition (Get-WelaSelectedSaclSnapshot $selected.Definition);Save 'stale-before.json' $staleBefore
    $staleBackup=Join-Path $evidence 'stale-journal'
    Public 'stale' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',$planPath,'-BackupPath',$staleBackup,'-ResultsPath',(Join-Path $evidence 'stale-results.json'),'-Auto')) 1
    $staleAfter=Get-WelaSelectedSaclStableDescendants $selected.Definition (Get-WelaSelectedSaclSnapshot $selected.Definition);Save 'stale-after.json' $staleAfter
    Assert (-not(Test-Path $staleBackup) -and (Read-Receipt 'stale-output.json') -match 'descendants changed' -and (Get-WelaSelectedSaclDescendantKey $staleBefore) -ceq (Get-WelaSelectedSaclDescendantKey $staleAfter)) 'A real unreviewed child refuses public Configure before journal/write and preserves all observed state.'
    Remove-Item -LiteralPath $appeared -Force -ErrorAction Stop
    $freshPlan=Join-Path $evidence 'fresh-plan.json';Public 'fresh-plan' ($selection+@('-TargetSaclAction','Plan','-ResultsPath',$freshPlan))
    $journal=Join-Path $evidence 'journal';$resultsPath=Join-Path $evidence 'results.json'
    Public 'configure' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',$freshPlan,'-BackupPath',$journal,'-ResultsPath',$resultsPath,'-Auto'))
    $result=Read-Receipt 'results.json';$applied=$result.Results[0]
    Assert ($result.ExitCode -eq 0 -and $result.DryRun -is [bool] -and -not $result.DryRun -and $result.Results.Count -eq 1 -and $applied.Status -is [string] -and $applied.Status -ceq 'Applied') 'Actual public Configure reports exactly one completed selected root addition.'
    $after=Get-WelaSelectedSaclSnapshot $selected.Definition;$afterChildren=Get-WelaSelectedSaclStableDescendants $selected.Definition $after
    Save 'after-public.json' $after;Save 'after-descendants.json' $afterChildren
    Assert-WelaSelectedSaclPreserved $before $after $row.Ace
    Assert ($after.Aces.Count -eq $before.Aces.Count+1 -and $after.Aces[0].Binary -ceq $before.Aces[0].Binary) 'Independent native readback proves one appended root audit ACE and unchanged unrelated ACE.'
    $outcome=Test-WelaSelectedSaclDescendantOutcomes $children $afterChildren $row.Ace
    Save 'independent-descendant-outcomes.json' $outcome
    Assert ($outcome.Status -ceq 'Observed' -and @($outcome.Outcomes|Where-Object Status -CEQ 'InheritedAceObserved').Count -eq 2 -and @($outcome.Outcomes|Where-Object Status -CEQ 'ProtectedUnchanged').Count -eq 2) 'Actual propagation is observed on the open branch while both protected descendants retain exact security.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $applied.After) -ceq (Get-WelaSelectedSaclSnapshotKey $after) -and (Get-WelaSelectedSaclDescendantKey $applied.DescendantsAfter) -ceq (Get-WelaSelectedSaclDescendantKey $afterChildren)) 'Public Applied evidence agrees with independent native parent and descendant readback.'
    $pending=Read-Receipt ('journal/'+$selected.Id+'.pending.json');$confirmed=Read-Receipt ('journal/'+$selected.Id+'.confirmed.json');$observed=Read-Receipt ('journal/'+$selected.Id+'.descendants-observed.json')
    Assert ($pending.State -is [string] -and $pending.State -ceq 'Pending' -and $null -eq $pending.After -and $confirmed.State -is [string] -and $confirmed.State -ceq 'Confirmed') 'Distinct original Pending and Confirmed receipts establish actual intent and completion.'
    Assert ((Get-WelaSelectedSaclSnapshotKey $pending.Before) -ceq (Get-WelaSelectedSaclSnapshotKey $before) -and (Get-WelaSelectedSaclSnapshotKey $confirmed.After) -ceq (Get-WelaSelectedSaclSnapshotKey $after) -and (Get-WelaSelectedSaclDescendantKey $observed.After) -ceq (Get-WelaSelectedSaclDescendantKey $afterChildren)) 'Retained original receipt bytes bind the exact actual root/child transition.'
    Assert ($result.GenerationReadiness -ceq 'Conditional' -and $result.UsableRuleCredit -eq 0) 'Root configuration remains conditional without a coverage or Sigma claim.'
    $againPlan=Join-Path $evidence 'idempotent-plan.json';Public 'idempotent-plan' ($selection+@('-TargetSaclAction','Plan','-ResultsPath',$againPlan))
    $againJournal=Join-Path $evidence 'idempotent-journal';Public 'idempotent-configure' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',$againPlan,'-BackupPath',$againJournal,'-ResultsPath',(Join-Path $evidence 'idempotent-results.json'),'-Auto'))
    $again=Read-Receipt 'idempotent-results.json'
    Assert ($again.Results[0].Status -ceq 'AlreadyCompliant' -and @(Get-ChildItem -LiteralPath $againJournal -Force).Count -eq 0 -and (Get-WelaSelectedSaclDescendantKey (Get-WelaSelectedSaclStableDescendants $selected.Definition (Get-WelaSelectedSaclSnapshot $selected.Definition))) -ceq (Get-WelaSelectedSaclDescendantKey $afterChildren)) 'Public second Configure adds no duplicate ACE or receipt and preserves full native descendant state.'
    Public 'probe-plan' @('file-access-probe','-FileProbePath',$leaf.ToLowerInvariant())
    $probePlan=Read-PublicReport 'probe-plan';Save 'probe-plan.json' $probePlan
    Assert ($probePlan.Status -ceq 'PrerequisitesObserved' -and @($probePlan.Before.File.Aces|Where-Object {($_.Flags -band 16) -and $_.Sid -ceq 'S-1-1-0' -and ($_.Mask -band 1)}).Count -eq 1) 'Public read-probe Plan observes the actual inherited ReadData SACL on the owned leaf.'
    $probeOutput=Join-Path $evidence 'probe';Public 'probe' @('file-access-probe','-FileProbeAction','Run','-FileProbePath',$leaf.ToLowerInvariant(),'-FileProbeOutputPath',$probeOutput)
    $probe=Read-PublicReport 'probe';Save 'probe-result.json' $probe
    Assert ($probe.Status -ceq 'FileReadObserved' -and $probe.Matches -eq 1 -and $probe.Operation.Read.ReadCalls -eq 1 -and $probe.Operation.Read.BytesRead -eq 1 -and $probe.RetainedContentBytes -eq 0) 'Actual one-byte public leaf read produces exactly one attributable4663 without retaining content.'
    Assert (Test-WelaFileProbeEvent ([IO.File]::ReadAllText((Join-Path $probeOutput 'event.xml'))) $probe.Operation $probe.Before) 'Retained native4663 matches exact worker PID/handle/token/path/right and measured operation phase.'
    foreach($artifact in $probe.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $probeOutput $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Public probe artifact hash matches retained bytes.'}
    Assert ($probe.ConfigurationChanges -eq 0 -and $probe.FileDataWrites -eq 0 -and $probe.SigmaEvtxCredit -eq 0) 'Observed read grants no configuration, file-write or Sigma credit.'
    Public 'protected-probe' @('file-access-probe','-FileProbePath',$protectedLeaf) 1
    $protectedProbe=Read-PublicReport 'protected-probe';Save 'protected-probe.json' $protectedProbe
    Assert ($protectedProbe.Status -ceq 'Unverified' -and $null -eq $protectedProbe.Operation -and $protectedProbe.Diagnostic -match 'No existing ordinary success ReadData') 'Protected leaf receives no inherited coverage and its public read probe is refused.'
    $contentAfter=@(foreach($path in @($leaf,$protectedLeaf)){[pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}});Save 'owned-content-after.json' $contentAfter
    Assert ((Key $contentAfter) -ceq (Key $contentBefore)) 'Fixture-owned content remains byte-identical.'
    $finalChildren=Get-WelaSelectedSaclStableDescendants $selected.Definition (Get-WelaSelectedSaclSnapshot $selected.Definition);Save 'final-descendants.json' $finalChildren
    Assert ((Get-WelaSelectedSaclDescendantKey $finalChildren) -ceq (Get-WelaSelectedSaclDescendantKey $afterChildren)) 'Final public probe outcomes preserve full root/descendant security and membership.'
    $profile.AssertOwned();$hive.AssertOwned()
    Assert ((Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key)) -ceq $preparedMasks -and (Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq $preparedPrecedence) 'Every public operation preserves prepared auditing and typed precedence.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'All fixture and public operations restore full token groups/privileges.'

}catch{$failure=$_}finally{
    if($policyTouched){
        try{Set-WelaEffectiveAuditPolicy -Guid $auditGuid -Mask $beforeMasks[$auditGuid] -Mode exact}catch{$cleanupErrors+='Audit restore: '+$_.Exception.Message}
        try{if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Type $beforePrecedence.Type -Value $beforePrecedence.Value}else{Remove-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -ErrorAction Stop}}catch{$cleanupErrors+='Precedence restore: '+$_.Exception.Message}
    }
    try{if($profile){$profile.Dispose()}}catch{$cleanupErrors+='Profile removal: '+$_.Exception.Message}
    try{$hive.Dispose()}catch{$cleanupErrors+='Hive unload/seed removal: '+$_.Exception.Message}
    $afterProfiles=$null;$afterHives=$null;$afterToken=$null;$afterMasks=$null;$afterPrecedence=$null
    $profilesOk=$false;$hivesOk=$false;$tokenOk=$false;$masksOk=$false;$precedenceOk=$false
    try{$afterProfiles=[Wela.FileSaclFixture.Profile]::Snapshot();$profilesOk=(Key $afterProfiles) -ceq (Key $beforeProfiles)}catch{$cleanupErrors+='Profile verification: '+$_.Exception.Message}
    try{$afterHives=Hives;$hivesOk=(Key $afterHives) -ceq (Key $beforeHives)}catch{$cleanupErrors+='Hive verification: '+$_.Exception.Message}
    try{$afterToken=[Wela.WmiProbe.Native]::Snapshot();$tokenOk=(Key $afterToken) -ceq (Key $beforeToken)}catch{$cleanupErrors+='Token verification: '+$_.Exception.Message}
    try{$afterMasks=Get-WelaEffectiveAuditPolicy;$masksOk=(Key ($afterMasks.GetEnumerator()|Sort-Object Key)) -ceq (Key ($beforeMasks.GetEnumerator()|Sort-Object Key))}catch{$cleanupErrors+='Audit verification: '+$_.Exception.Message}
    try{$afterPrecedence=Get-WelaRegistryState $precedencePath $precedenceName;$precedenceOk=(Key $afterPrecedence) -ceq (Key $beforePrecedence)}catch{$cleanupErrors+='Precedence verification: '+$_.Exception.Message}
    if($profilesOk -and $hivesOk -and -not $hive.Loaded){try{Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction Stop;Remove-Item -LiteralPath $files -Recurse -Force -ErrorAction Stop}catch{$cleanupErrors+='Owned file removal: '+$_.Exception.Message}}
    $cleanup=[pscustomobject]@{Complete=($profilesOk -and $hivesOk -and $tokenOk -and $masksOk -and $precedenceOk -and -not $hive.Loaded -and -not $hive.SeedCreated -and -not(Test-Path $targetRoot) -and -not(Test-Path $files) -and $cleanupErrors.Count -eq 0);ProfilesRestored=$profilesOk;HivesRestored=$hivesOk;TokenRestored=$tokenOk;AuditMasksCompared=$beforeMasks.Count;AuditMasksRestored=$masksOk;PrecedenceRestored=$precedenceOk;HiveUnloaded=(-not $hive.Loaded);SeedRemoved=(-not $hive.SeedCreated);FilesRemoved=(-not(Test-Path $targetRoot) -and -not(Test-Path $files));Errors=$cleanupErrors;Failure=$(if($failure){$failure.Exception.Message}else{$null});Assertions=$script:assertions;AfterProfiles=$afterProfiles;AfterHives=$afterHives;AfterToken=$afterToken;AfterMasks=$afterMasks;AfterPrecedence=$afterPrecedence}
    Save 'cleanup.json' $cleanup
    Save 'artifact-hashes.json' @(Get-ChildItem -LiteralPath $evidence -Recurse -File|Where-Object Name -ne 'artifact-hashes.json'|Sort-Object FullName|ForEach-Object {[pscustomobject]@{Name=$_.FullName.Substring($evidence.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
}
if($failure){throw $failure};if(-not $cleanup.Complete){throw ('Owned profile fixture cleanup incomplete: '+(Key $cleanup))}
Write-Host "Passed $script:assertions actual public filesystem SACL lifecycle assertions; cleanup confirmed. Evidence: $evidence"
$global:LASTEXITCODE=0
