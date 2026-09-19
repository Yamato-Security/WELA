param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {Write-Host 'Skipped: native Windows required.';exit 0}
if (-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'Native fixture requires explicit policy-write opt-in on an ephemeral GitHub-hosted runner.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
. (Join-Path $repo 'scripts/EventMeasurement.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
$guid='0cce922b-69ae-11d9-bed3-505054503030'
$controls=@([pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='SCENoApplyLegacyAuditPolicy'},[pscustomobject]@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';Name='ProcessCreationIncludeCmdLine_Enabled'})
$beforeMasks=Get-WelaEffectiveAuditPolicy
if($beforeMasks.Count -ne 59){throw 'Complete initial policy snapshot unavailable.'}
foreach($control in $controls){$control|Add-Member NoteProperty Before (Get-WelaRegistryState -Path $control.Path -Name $control.Name)}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-delivery-native-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$receipt=Join-Path $root 'fixture-before.json'
[pscustomobject]@{AuditMasks=$beforeMasks;Controls=$controls}|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $receipt -Encoding UTF8
$touched=$false;$restored=$false;$child=$null;$checks=0
function Check($Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
try {
    $touched=$true
    foreach($control in $controls){if(-not(Test-Path -LiteralPath $control.Path)){$null=New-WelaRegistryKey $control.Path};$null=New-ItemProperty -LiteralPath $control.Path -Name $control.Name -Value 1 -PropertyType DWord -Force}
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum
    $nativeState=Get-WelaProbeState;Assert-WelaProbePrerequisites $nativeState
    $channelBefore=Get-WelaMeasurementState Security
    $engine=(Get-Process -Id $PID).Path;$bundle=Join-Path $root 'measurement'
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$engine;$start.Arguments='-NoProfile -File "'+(Join-Path $repo 'WELA.ps1')+'" event-measurement -MeasurementAction Run -MeasurementChannel Security -MeasurementSeconds 10 -MeasurementMaximumEvents 1024 -MeasurementOutputPath "'+$bundle+'" -MeasurementExportEvtx'
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $child=[Diagnostics.Process]::Start($start)
    $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
    $opening=[Diagnostics.Stopwatch]::StartNew();$opened=Join-Path $bundle 'window-open.json'
    while(-not(Test-Path -LiteralPath $opened)){
        if($child.HasExited -or $opening.Elapsed.TotalSeconds -gt 60){throw ('Measurement did not open: '+$stdout.GetAwaiter().GetResult()+' '+$stderr.GetAwaiter().GetResult())}
        Start-Sleep -Milliseconds 100
    }
    $processes=@(1..3|ForEach-Object {Start-WelaProbeProcess})
    if(-not $child.WaitForExit(90000)){throw 'Native measurement child exceeded its bounded fixture timeout.'}
    $out=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult();Write-Host $out
    Check ($child.ExitCode -eq 0) ('Public measurement failed: '+$err)
    $manifest=ConvertFrom-WelaEvtxJson (Get-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Raw)
    Check ($manifest.Status -eq 'DeliveryWindowObserved' -and $manifest.Window.ElapsedSeconds -eq 10 -and $manifest.Window.NativeStatus -eq 'WindowComplete') 'Native callback observation did not complete its monotonic window.'
    Check ($manifest.PolicyChanges -eq 0 -and $manifest.ReadyRuleCredit -eq 0 -and $manifest.LossAssessment -match '^Unknown') 'Native report overclaimed configuration, readiness or upstream completeness.'
    Check ($manifest.ObservedDeliveries -ge 3 -and $manifest.ObservedDeliveriesPerSecond -eq $manifest.ObservedDeliveries/10.0) 'Native observed count/rate is inconsistent.'
    Check ($manifest.Evtx.Status -eq 'ExactSampleReopened' -and $manifest.Evtx.Records -eq $manifest.ObservedDeliveries) 'Exact native export/reopen failed.'
    Check ($manifest.Evtx.Bytes -eq (Get-Item -LiteralPath (Join-Path $bundle 'sample.evtx')).Length -and $manifest.Evtx.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $bundle 'sample.evtx')).Hash.ToLowerInvariant()) 'Measured native EVTX artifact bytes/hash differ.'
    foreach($artifact in $manifest.Artifacts){Check ((Get-FileHash -LiteralPath (Join-Path $bundle $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Native artifact hash mismatch.'}
    $delivered=@($manifest.Events|ForEach-Object {[IO.File]::ReadAllText((Join-Path $bundle $_.XmlArtifact))})
    foreach($process in $processes){$matches=@($delivered|Where-Object {Test-WelaProbeEvent -Xml $_ -Process $process -State $nativeState -EndUtc ([datetime]::UtcNow)});Check ($matches.Count -eq 1) ('No exact sampled native 4688 for owned process '+$process.Marker)}
    $parsed=@($delivered|ForEach-Object {Read-WelaMeasurementEvent -Xml $_ -Channel Security -Computer ([Environment]::MachineName)})
    $independent=Confirm-WelaMeasurementEvtx -Path (Join-Path $bundle 'sample.evtx') -Events $parsed -Channel Security -Computer ([Environment]::MachineName)
    Check ($independent.Sha256 -ceq $manifest.Evtx.Sha256) 'Independent native reopen differs.'
    $channelAfter=Get-WelaMeasurementState Security;Assert-WelaMeasurementState $channelBefore $channelAfter;$checks++
    $acl=Get-Acl -LiteralPath $bundle;Check $acl.AreAccessRulesProtected 'Evidence ACL is not protected.'
    # No policy/channel clear, service start, arbitrary provider or source registration occurs in product or fixture.
    Write-Host "Native delivery/export proved exact owned 4688 samples in a ten-second callback window on $($nativeState.context.patch), PowerShell $($PSVersionTable.PSVersion). Other channels/roles and backend storage remain unproven."
} finally {
    if($child){if(-not $child.HasExited){$child.Kill();$child.WaitForExit(10000)|Out-Null};$child.Dispose()}
    if($touched){
        $errors=@()
        try{Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $beforeMasks[$guid] -Mode exact}catch{$errors+=$_.Exception.Message}
        foreach($control in $controls){try{
            if($control.Before.ValueExists){$null=New-ItemProperty -LiteralPath $control.Path -Name $control.Name -Value $control.Before.Value -PropertyType $control.Before.Type -Force}
            else{Remove-ItemProperty -LiteralPath $control.Path -Name $control.Name -ErrorAction SilentlyContinue}
            if(-not $control.Before.KeyExists -and(Test-Path -LiteralPath $control.Path)){$key=Get-Item -LiteralPath $control.Path;if($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0){Remove-Item -LiteralPath $control.Path -ErrorAction Stop}}
            if((Get-WelaRegistryState -Path $control.Path -Name $control.Name|ConvertTo-Json -Compress) -cne ($control.Before|ConvertTo-Json -Compress)){throw ('Registry restoration differs: '+$control.Name)}
        }catch{$errors+=$_.Exception.Message}}
        try{$afterMasks=Get-WelaEffectiveAuditPolicy;foreach($id in $beforeMasks.Keys){if($afterMasks[$id] -ne $beforeMasks[$id]){throw ('Restoration differs for audit GUID '+$id)}}}catch{$errors+=$_.Exception.Message}
        $restored=$errors.Count -eq 0
        if(-not $restored){throw ('Fixture restoration failed; evidence retained at '+$root+': '+($errors -join '; '))}
    }
    if($restored){Remove-Item -LiteralPath $root -Recurse -Force}
}
Write-Host "$checks native delivery/export checks and complete policy/typed-registry restoration passed."
$global:LASTEXITCODE=0
