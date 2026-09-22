param([switch]$AllowDisposableAuditWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAuditWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ProcessCommandline.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
$engine=(Get-Process -Id $PID).Path;$count=0;$failure=$null;$errors=@()
$root=Join-Path $env:RUNNER_TEMP ('wela-process-commandline-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';$name='ProcessCreationIncludeCmdLine_Enabled'
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Masks {$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
function Other {
    [pscustomobject][ordered]@{Unselected=(Get-WelaProcessCommandlineSnapshot).Unselected;SecurityChannel=Get-WelaNativeChannel Security;Services=@(Get-Service Winmgmt,EventLog,WinRM,Wecsvc|Sort-Object Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;State=[string]$_.Status}})}
}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;
public static class WelaCommandlineFixturePipe {
 public static async Task<string> Read(TextReader reader){var text=new StringBuilder();var buffer=new char[1024];while(true){int n=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(n==0)return text.ToString();if(n>1048576-text.Length)throw new InvalidDataException("Fixture output exceeds one Mi character bound.");text.Append(buffer,0,n);}}
}
'@
function Public([string]$Label,[string[]]$Arguments){
    $all=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $repo 'WELA.ps1'),'process-commandline')+$Arguments
    foreach($a in $all){if($a.Contains('"') -or $a.EndsWith('\') -or $a -match '[\x00-\x1f]'){throw 'Ambiguous fixture argument.'}}
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$engine;$info.Arguments=(@($all|ForEach-Object {'"'+$_+'"'}) -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
    try{
        if(-not $process.Start()){throw 'Public process did not start.'};$started=$true
        $stdout=[WelaCommandlineFixturePipe]::Read($process.StandardOutput);$stderr=[WelaCommandlineFixturePipe]::Read($process.StandardError)
        if(-not $process.WaitForExit(180000)){throw 'Public command exceeded three minutes.'}
        if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Public output drain timed out.'}
        $output=$stdout.Result+"`n"+$stderr.Result
        $output|Set-Content -LiteralPath (Join-Path $root ($Label+'.txt')) -Encoding UTF8
        Assert ($process.ExitCode -eq 0) "Public $Label exited $($process.ExitCode) : $output"
        Get-Content -Raw -LiteralPath (Join-Path $root ($Label+'.json'))|ConvertFrom-Json
    }finally{
        if($started){$exited=$false;try{$exited=$process.HasExited}catch{$script:errors+=$_.Exception.Message};if(-not $exited){try{$process.Kill()}catch{$script:errors+=$_.Exception.Message};try{$exited=$process.WaitForExit(5000)}catch{$script:errors+=$_.Exception.Message}};if(-not $exited){$script:errors+='Owned public process termination unconfirmed.'}}
        $process.Dispose()
    }
}
$original=Get-WelaProcessCommandlineSnapshot
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedenceName='SCENoApplyLegacyAuditPolicy'
$precedence=Get-WelaRegistryState $precedencePath $precedenceName
$allMasks=Get-WelaEffectiveAuditPolicy;$masks=Masks;$guid='0cce922b-69ae-11d9-bed3-505054503030'
$other=Other;$touched=$false;$nativeEvents=0
Assert ($original.Host.ProductType -eq 3 -and $original.Host.DomainRole -eq 2 -and -not $original.Host.PartOfDomain) 'Actual unjoined disposable Server required.'
Assert (-not $original.Policy.ValueExists -or ($original.Policy.Type -ceq 'DWord' -and $original.Policy.Value -in 0,1)) 'Unknown original values are preserved.'
Assert (-not $precedence.ValueExists -or ($precedence.Type -ceq 'DWord' -and $precedence.Value -in 0,1)) 'Unknown original precedence is preserved.'
Save 'original.json' @{Snapshot=$original;Unselected=$other;Masks=$masks;Precedence=$precedence;UBR=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR;Engine=$PSVersionTable.PSVersion.ToString();Commit=$env:GITHUB_SHA;Sources=@(foreach($file in @('WELA.ps1','scripts/ProcessCommandline.ps1','scripts/Configuration.ps1','scripts/NativeValidation.ps1','scripts/ControlApplicability.ps1','modules/AuditProfiles.psm1')){[pscustomobject]@{Name=$file;Sha256=(Get-FileHash (Join-Path $repo $file)).Hash.ToLowerInvariant()}})}
try {
    # This owned fixture prepares only the independent prerequisites. The public command must preserve them.
    $touched=$true
    Set-ItemProperty -LiteralPath $precedencePath -Name $precedenceName -Value 1 -Type DWord -ErrorAction Stop
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum
    $preparedMasks=Masks;$preparedPrecedence=Get-WelaRegistryState $precedencePath $precedenceName
    foreach ($case in @('absent','disabled')) {
        if ((Get-WelaRegistryState $path $name).ValueExists) {Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}
        if ($case -eq 'disabled') {$null=New-WelaRegistryKey $path;Set-ItemProperty -LiteralPath $path -Name $name -Value 0 -Type DWord -ErrorAction Stop}
        $prepared=Get-WelaProcessCommandlineSnapshot
        $plan=Public ($case+'-plan') @('-ProcessCommandlineAction','Plan','-ResultsPath',(Join-Path $root ($case+'-plan.json')))
        Assert ($plan.Plan.Status -ceq 'ChangeRequired' -and (Key $plan.Plan.Before) -ceq (Key $prepared) -and $plan.Plan.Prerequisite.State -ceq 'SuccessEnabled') 'Public plan records exact typed state and separate success prerequisite.'
        $dryBackup=Join-Path $root ($case+'-dry-backup')
        $dry=Public ($case+'-dry') @('-ProcessCommandlineAction','Configure','-Auto','-DryRun','-BackupPath',$dryBackup,'-ResultsPath',(Join-Path $root ($case+'-dry.json')))
        Assert ($dry.DryRun -and $dry.Results[0].Status -ceq 'Skipped' -and -not(Test-Path $dryBackup) -and (Key (Get-WelaProcessCommandlineSnapshot)) -ceq (Key $prepared)) 'Dry run changes no registry state and creates no backup directory.'
        $backup=Join-Path $root ($case+'-backup')
        $report=Public $case @('-ProcessCommandlineAction','Configure','-Auto','-BackupPath',$backup,'-ResultsPath',(Join-Path $root ($case+'.json')))
        $after=Get-WelaProcessCommandlineSnapshot
        Assert ($report.Scope -ceq 'process-commandline-policy-only' -and $report.Results.Count -eq 1 -and $report.Results[0].Status -ceq 'Applied' -and $report.ReadyRuleCredit -eq 0) 'Public Configure applies exactly one policy with zero rule credit.'
        Assert ($after.Policy.Type -ceq 'DWord' -and $after.Policy.Value -eq 1 -and (Key $report.Results[0].After) -ceq (Key $after)) 'Actual DWORD readback matches the public result.'
        $journal=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json)
        Assert ($journal.Count -eq 1 -and (Key $journal[0].Before) -ceq (Key $prepared)) 'Original journal retains exact typed prior state.'
        $repeat=Public ($case+'-repeat') @('-ProcessCommandlineAction','Configure','-Auto','-BackupPath',(Join-Path $root ($case+'-repeat-backup')),'-ResultsPath',(Join-Path $root ($case+'-repeat.json')))
        Assert ($repeat.Results[0].Status -ceq 'AlreadyCompliant') 'Repeat is idempotent.'
        Assert ((Masks) -ceq $preparedMasks -and (Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq (Key $preparedPrecedence) -and (Key (Other)) -ceq (Key $other)) 'Public command preserves all59 masks, typed precedence, other values, Security channel and services.'
        $destination=Join-Path $root ($case+'-4688')
        $event=Invoke-WelaNativeValidation -Action Run -OutputPath $destination -TimeoutSeconds 30
        Save ($case+'-4688-report.json') $event
        Assert ($event.ExitCode -eq 0 -and $event.Status -ceq 'NativeEventObserved' -and $event.ReadyRuleCredit -eq 0) 'The separate fixed native probe observes an actual attributed4688.'
        $xml=[IO.File]::ReadAllText((Join-Path $destination 'event.xml'))
        Assert (Test-WelaProbeEvent $xml $event.Process $event.BeforeState ([DateTime]::UtcNow)) 'Exact native process IDs, executable, command line, provider, host and interval match.'
        foreach ($artifact in $event.Artifacts) {Assert ((Get-FileHash -LiteralPath (Join-Path $destination $artifact.path)).Hash.ToLowerInvariant() -ceq $artifact.sha256) 'Probe artifact hash matches.'}
        $nativeEvents++
    }
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 0 -Mode exact
    $missing=Public 'missing-prerequisite' @('-ProcessCommandlineAction','Audit','-ResultsPath',(Join-Path $root 'missing-prerequisite.json'))
    Assert ($missing.Plan.Status -ceq 'AlreadyCompliant' -and $missing.Plan.Prerequisite.State -ceq 'SuccessMissing' -and $missing.ReadyRuleCredit -eq 0) 'An enabled DWORD never hides the separate missing Process Creation prerequisite.'
    Save 'completed.json' @{Status='Passed';Assertions=$count;NativeWrites=2;Exact4688=$nativeEvents;Scope='Actual standalone Server only; no Windows11/DC/CA, forwarding, backend or complete-rule credit.'}
} catch {$failure=$_.ToString();throw} finally {
    if ($touched) {
        foreach ($c in @(@($path,$name,$original.Policy),@($precedencePath,$precedenceName,$precedence))) {
            try {
                if ((Get-WelaRegistryState $c[0] $c[1]).ValueExists) {Remove-ItemProperty -LiteralPath $c[0] -Name $c[1] -ErrorAction Stop}
                if ($c[2].ValueExists) {$null=New-ItemProperty -LiteralPath $c[0] -Name $c[1] -Value $c[2].Value -PropertyType $c[2].Type -ErrorAction Stop}
                if (-not $c[2].KeyExists -and (Test-Path -LiteralPath $c[0])) {
                    $k=Get-Item -LiteralPath $c[0];if($k.ValueCount -or $k.SubKeyCount){throw 'New policy key contains unrelated data; refusing deletion.'}
                    Remove-Item -LiteralPath $c[0] -ErrorAction Stop
                }
            } catch {$errors+=$_.ToString()}
        }
        try {Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $allMasks[$guid] -Mode exact}catch{$errors+=$_.ToString()}
    }
    $checks=[ordered]@{}
    foreach($pair in @(@('Policy',{(Key (Get-WelaProcessCommandlineSnapshot)) -ceq (Key $original)}),@('Unselected',{(Key (Other)) -ceq (Key $other)}),@('All59Masks',{(Masks) -ceq $masks}),@('Precedence',{(Key (Get-WelaRegistryState $precedencePath $precedenceName)) -ceq (Key $precedence)}))) {try{$checks[$pair[0]]=& $pair[1]}catch{$checks[$pair[0]]=$false;$errors+=$_.ToString()}}
    $complete=$errors.Count -eq 0 -and @($checks.Values|Where-Object {-not $_}).Count -eq 0
    Save 'cleanup.json' @{Complete=$complete;Checks=$checks;Errors=$errors;Failure=$failure;Assertions=$count}
    Save 'artifact-hashes.json' @(Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object Name -ne 'artifact-hashes.json'|Sort-Object FullName|ForEach-Object{[pscustomobject]@{Name=$_.FullName.Substring($root.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}})
    if(-not $complete){throw 'Process command-line native fixture cleanup failed.'}
}
Write-Host "PASS: $count native command-line assertions, $nativeEvents exact4688 records and exact cleanup."
exit 0
