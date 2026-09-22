# Mutating test fixture only: public WELA never loads hives or prepares audit policy.
param([switch]$AllowDisposableHiveWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableHiveWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Explicit disposable GitHub-hosted native Windows fixture only.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','WmiProbe','ChannelRead','SelectedSaclConfiguration','RegistrySaclRecovery')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
. (Join-Path $PSScriptRoot 'RegistrySaclLifecycleEvidence.ps1')
Initialize-WelaWmiProbeNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistrySaclFixtureNative.cs') -ErrorAction Stop
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-registry-recovery-'+[guid]::NewGuid().ToString('N'))) $script:ScriptRoot
$files=Join-Path $root 'owned-hive-files';$null=New-Item -ItemType Directory $files
function Save([string]$Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),($Value|ConvertTo-Json -Depth 28),[Text.UTF8Encoding]::new($false))}
function Read-Receipt([string]$Name){ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $root $Name)))}
function Hives {@([Microsoft.Win32.Registry]::Users.GetSubKeyNames()|Sort-Object)}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
$script:assertions=0
function Assert($Condition,[string]$Message){if(-not $Condition){throw $Message};$script:assertions++}

Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;
public static class WelaRegistryRecoveryFixturePipe {
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
        $stdout=[WelaRegistryRecoveryFixturePipe]::Read($process.StandardOutput);$stderr=[WelaRegistryRecoveryFixturePipe]::Read($process.StandardError)
        if(-not $process.WaitForExit(180000)){throw 'Public command exceeded three minutes.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public output drain timed out.'}
        $text=$stdout.Result+"`n"+$stderr.Result;Save ($Name+'-output.json') $text
        Assert ($process.ExitCode -eq $Expected) ("Public $Name exited $($process.ExitCode), expected $Expected : "+$text)
    }finally{
        if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:cleanupErrors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:cleanupErrors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:cleanupErrors+=$_.Exception.Message}};if(-not $exited){$script:cleanupErrors+='Owned public process termination unconfirmed.'}}
        $process.Dispose()
    }
}
$engine=(Get-Process -Id $PID).Path;$guid='0CCE921E-69AE-11D9-BED3-505054503030'
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceName='SCENoApplyLegacyAuditPolicy'
$beforeHives=Hives;$beforeToken=[Wela.WmiProbe.Native]::Snapshot();$beforeMasks=Get-WelaEffectiveAuditPolicy;$beforePrecedence=Get-WelaRegistryState $precedencePath $precedenceName
Save 'before-hives.json' $beforeHives;Save 'before-token.json' $beforeToken;Save 'before-masks.json' $beforeMasks;Save 'before-precedence.json' $beforePrecedence
$hive=[Wela.RegistrySaclFixture.Hive]::new([guid]::NewGuid().ToString('N'),(Join-Path $files 'owned.dat'));$failure=$null;$cleanupErrors=@();$policyTouched=$false
try {
    Assert ($beforeMasks.Count -eq 59) 'All 59 original audit masks observed.'
    $hive.Prepare();$hive.CreateRunOnce();$hive.AssertOwned();$hive.AssertValues($false)
    $providerPath='Registry::HKEY_USERS\'+$hive.Sid+'\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Save 'mounted.json' ([pscustomobject]@{Sid=$hive.Sid;File=$hive.FilePath;Seed=$hive.SeedPath;Target=$providerPath})
    Assert ((Key (Hives)) -ceq (Key (@($beforeHives)+$hive.Sid|Sort-Object))) 'Only fixture-owned hive was mounted.'
    $policyTouched=$true;Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Type DWord -Value 1;Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 3 -Mode exact
    $preparedMasks=Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key);$preparedPrecedence=Key (Get-WelaRegistryState $precedencePath $precedenceName)
    Public 'catalog' @('targeted-sacl','-TargetSaclProfile','asd-native-2021-10','-IncludeOptional','-ResultsPath',(Join-Path $root 'catalog.json'))
    $catalog=Read-Receipt 'catalog.json';$selectedRows=@($catalog.Catalog|Where-Object {$_.Definition.UserSid -ceq $hive.Sid -and $_.Definition.Path -ieq $providerPath})
    Assert ($selectedRows.Count -eq 1 -and $selectedRows[0].Definition.Kind -ceq 'Registry') 'Exactly one real catalog target in owned HKU hive.'
    $selected=$selectedRows[0];Save 'selected.json' $selected
    Initialize-WelaSelectedSaclNative;$privilege=[Wela.SelectedSacl.Privilege]::new();$target=$null
    try{$target=[Wela.SelectedSacl.Target]::new('Registry',(Resolve-WelaSelectedSaclNativePath $selected.Definition));$before=$target.Read();$seeded=$target.Add($before.Identity,$before.DescriptorBase64,'S-1-5-18',1,64)}finally{if($target){$target.Dispose()};$privilege.Dispose()}
    Save 'before-public.json' $seeded
    $originalPlan=Join-Path $root 'original-plan.json';$backup=Join-Path $root 'original-journal';$originalResults=Join-Path $root 'original-results.json'
    $selection=@('targeted-sacl','-TargetSaclProfile','asd-native-2021-10','-TargetSaclId',$selected.Id,'-IncludeOptional','-TargetSaclIncludeChildren')
    Public 'original-plan' ($selection+@('-TargetSaclAction','Plan','-ResultsPath',$originalPlan))
    Public 'original-configure' ($selection+@('-TargetSaclAction','Configure','-TargetSaclPlanPath',$originalPlan,'-BackupPath',$backup,'-ResultsPath',$originalResults,'-Auto'))
    $result=Read-Receipt 'original-results.json';Assert ($result.Results[0].Status -is [string] -and $result.Results[0].Status -ceq 'Applied') 'Recovery starts from actual completed public Configure.'
    $applied=Get-WelaSelectedSaclSnapshot $selected.Definition;Save 'applied-native.json' $applied;$hive.AssertValues($false)
    $review=Join-Path $root 'review';$pending=Join-Path $backup ($selected.Id+'.pending.json');$confirmed=Join-Path $backup ($selected.Id+'.confirmed.json')
    $reviewArgs=@('registry-sacl-recovery','-RegistryRecoveryOriginalPlanPath',$originalPlan,'-RegistryRecoveryPendingPath',$pending,'-RegistryRecoveryConfirmedPath',$confirmed,'-RegistryRecoveryOriginalResultsPath',$originalResults)
    Public 'recovery-plan' ($reviewArgs+@('-RegistryRecoveryOutputPath',$review))
    $manifest=Read-Receipt 'review/manifest.json';Assert ($manifest.Status -ceq 'ReviewRequired' -and -not $manifest.WriteAttempted -and $manifest.PlanHash -ceq (Get-FileHash -LiteralPath (Join-Path $review 'plan.json')).Hash.ToLowerInvariant()) 'Actual recovery Plan binds independently checked exact bytes without writes.'
    Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $selected.Definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $applied)) 'Recovery planning preserves exact native state.'
    $restoreArgs=@('registry-sacl-recovery','-RegistryRecoveryAction','Restore','-RegistryRecoveryPlanPath',(Join-Path $review 'plan.json'),'-RegistryRecoveryPlanHash',$manifest.PlanHash)
    foreach($missing in @('AuditReduction','Inheritance')){
        $out=Join-Path $root ('missing-'+$missing);$consent=if($missing -ceq 'AuditReduction'){'-RegistryRecoveryAllowInheritance'}else{'-RegistryRecoveryAllowAuditReduction'}
        Public ('missing-'+$missing) ($restoreArgs+@('-RegistryRecoveryOutputPath',$out,$consent)) 1
        $refusal=Read-Receipt ('missing-'+$missing+'/manifest.json');Assert ($refusal.Status -ceq 'Refused' -and -not $refusal.WriteAttempted -and -not(Test-Path -LiteralPath (Join-Path $out 'pending.json'))) 'Each explicit reduction/inheritance consent is required before durable intent or removal.'
    }
    $restoredDir=Join-Path $root 'restored'
    Public 'restore' ($restoreArgs+@('-RegistryRecoveryOutputPath',$restoredDir,'-RegistryRecoveryAllowAuditReduction','-RegistryRecoveryAllowInheritance'))
    $restored=Read-Receipt 'restored/manifest.json';Save 'restored-native.json' (Get-WelaSelectedSaclSnapshot $selected.Definition)
    Assert ($restored.Status -ceq 'AddedAceRemoved' -and $restored.WriteAttempted -and $restored.PolicyChanges -eq 0 -and $restored.ReadyRuleCredit -eq 0) 'Actual public recovery removes one proven ACE with no audit-policy or rule credit.'
    $native=Get-WelaSelectedSaclSnapshot $selected.Definition;Initialize-WelaRegistryRecoveryNative
    [Wela.RegistrySaclRecovery.Descriptor]::Removed($applied.DescriptorBase64,$native.DescriptorBase64,(Read-Receipt 'review/plan.json').AddedAce)
    Assert ($native.Aces.Count -eq $seeded.Aces.Count -and $native.Aces[0].Binary -ceq $seeded.Aces[0].Binary -and $native.Owner -ceq $seeded.Owner -and $native.Group -ceq $seeded.Group -and $native.DaclBase64 -ceq $seeded.DaclBase64) 'Independent native observation retains unrelated audit ACE, owner/group/DACL.'
    $hive.AssertValues($false)
    foreach($artifact in $restored.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $restoredDir $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Durable actual recovery artifact hash verified.'}
    Assert ((Read-Receipt 'restored/pending.json').State -ceq 'Pending' -and (Read-Receipt 'restored/confirmed.json').State -ceq 'Confirmed') 'Distinct durable intent and verified completion receipts exist.'
    $replay=Join-Path $root 'replay';Public 'replay' ($restoreArgs+@('-RegistryRecoveryOutputPath',$replay,'-RegistryRecoveryAllowAuditReduction','-RegistryRecoveryAllowInheritance')) 1
    Assert ((Read-Receipt 'replay/manifest.json').Status -ceq 'Refused' -and -not (Read-Receipt 'replay/manifest.json').WriteAttempted) 'Old reviewed restore refuses replay.'
    Assert ((Key ((Get-WelaEffectiveAuditPolicy).GetEnumerator()|Sort-Object Key)) -ceq $preparedMasks -and (Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq $preparedPrecedence) 'All public operations preserve prepared auditing.'
    Assert ((Key ([Wela.WmiProbe.Native]::Snapshot())) -ceq (Key $beforeToken)) 'All native fixture security/backup/restore privilege attributes restored.'
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
Write-Host "Passed $script:assertions actual public registry SACL recovery assertions; all cleanup confirmed. Evidence: $root"
$global:LASTEXITCODE=0
