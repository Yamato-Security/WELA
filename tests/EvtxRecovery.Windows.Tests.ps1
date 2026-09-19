param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'Skipped: native Windows is required.'; exit 0 }
if (-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'This native event test requires explicit policy-write opt-in on a disposable GitHub-hosted runner.' }
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
. (Join-Path $repo 'scripts/EvtxRecovery.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
$guid='0cce922b-69ae-11d9-bed3-505054503030'
$controls=@(
    [pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='SCENoApplyLegacyAuditPolicy'},
    [pscustomobject]@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';Name='ProcessCreationIncludeCmdLine_Enabled'}
)
$beforeMask=(Get-WelaEffectiveAuditPolicy)[$guid]
foreach ($control in $controls) { $control | Add-Member NoteProperty Before (Get-WelaRegistryState -Path $control.Path -Name $control.Name) }
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-native-4688-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$receipt=Join-Path $root 'policy-before.json'
[pscustomobject]@{AuditMask=$beforeMask;Controls=$controls} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $receipt -Encoding UTF8
$touched=$false; $restored=$false
try {
    $touched=$true
    foreach ($control in $controls) {
        if (-not (Test-Path -LiteralPath $control.Path)) { $null=New-WelaRegistryKey -Path $control.Path }
        $null=New-ItemProperty -LiteralPath $control.Path -Name $control.Name -Value 1 -PropertyType DWord -Force
    }
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum
    $destination=Join-Path $root 'collection'
    $result=Invoke-WelaNativeValidation -Action Run -OutputPath $destination -TimeoutSeconds 30
    if ($result.ExitCode -ne 0 -or $result.Status -ne 'NativeEventObserved') { throw ($result | ConvertTo-Json -Depth 20) }
    if ($result.ReadyRuleCredit -ne 0 -or $result.Artifacts.Count -ne 4) { throw 'Collector mislabeled incomplete evidence.' }
    foreach ($artifact in $result.Artifacts) {
        if ((Get-FileHash -LiteralPath (Join-Path $destination $artifact.path)).Hash.ToLowerInvariant() -cne $artifact.sha256) { throw 'Native artifact hash mismatch.' }
    }
    $event=[IO.File]::ReadAllText((Join-Path $destination 'event.xml'))
    if (-not (Test-WelaProbeEvent $event $result.Process $result.BeforeState ([DateTime]::UtcNow))) { throw 'Native event cannot be independently matched.' }
    $export=Invoke-WelaEvtxRecovery -Action Export -ProbePath $destination -OutputPath (Join-Path $root 'export')
    if ($export.ExitCode -ne 0 -or $export.Status -ne 'NativeEventRecovered') {throw ($export | ConvertTo-Json -Depth 24)}
    $verify=Invoke-WelaEvtxRecovery -Action Verify -ProbePath $destination -ArchivePath $export.ArchivePath -OutputPath (Join-Path $root 'verify')
    if ($verify.ExitCode -ne 0 -or $verify.Status -ne 'NativeEventRecovered' -or $verify.ReaderBefore.Reader.Sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {throw ($verify | ConvertTo-Json -Depth 24)}
    if ($verify.ArchiveSha256 -cne $export.ArchiveSha256 -or $verify.ReadyRuleCredit -ne 0) {throw 'Native readback lost artifact identity or claimed readiness.'}
    # A natively generated empty EVTX must not be mistaken for recovered data.
    $empty=Join-Path $root 'empty.evtx'
    Export-WelaEvtxNative -Query '*[System[EventID=0 and Provider[@Name="Microsoft-Windows-Security-Auditing"]]]' -Path $empty
    $emptyResult=Invoke-WelaEvtxRecovery -ProbePath $destination -ArchivePath $empty -OutputPath (Join-Path $root 'empty-check')
    if ($emptyResult.ExitCode -ne 1 -or $emptyResult.Status -ne 'Unverified') {throw 'Empty native archive incorrectly accepted.'}
    Write-Host 'Native Security probe exported and recovered by actual reader from EVTX; empty native archive rejected.'
    Write-Host "Native 4688 event observed on $($result.BeforeState.context.role) $($result.BeforeState.context.patch) under PowerShell $($PSVersionTable.PSVersion). Complete-rule, backend and other-role validation remain pending."
} finally {
    if ($touched) {
        $errors=@()
        try { Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $beforeMask -Mode exact } catch { $errors+=$_.Exception.Message }
        foreach ($control in $controls) {
            try {
                if ($control.Before.ValueExists) { $null=New-ItemProperty -LiteralPath $control.Path -Name $control.Name -Value $control.Before.Value -PropertyType $control.Before.Type -Force }
                else { Remove-ItemProperty -LiteralPath $control.Path -Name $control.Name -ErrorAction SilentlyContinue }
                if (-not $control.Before.KeyExists -and (Test-Path -LiteralPath $control.Path)) {
                    $key=Get-Item -LiteralPath $control.Path
                    if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { Remove-Item -LiteralPath $control.Path -ErrorAction Stop }
                }
                $after=Get-WelaRegistryState -Path $control.Path -Name $control.Name
                if (($after | ConvertTo-Json -Compress) -cne ($control.Before | ConvertTo-Json -Compress)) { throw "Registry restoration differs: $($control.Name)" }
            } catch { $errors+=$_.Exception.Message }
        }
        try { if ((Get-WelaEffectiveAuditPolicy)[$guid] -ne $beforeMask) { throw 'Audit mask restoration differs.' } } catch { $errors+=$_.Exception.Message }
        $restored=$errors.Count -eq 0
        if (-not $restored) { throw "Policy restoration failed; receipt retained at $receipt : $($errors -join '; ')" }
    }
    if ($restored) { Remove-Item -LiteralPath $root -Recurse -Force }
}
$global:LASTEXITCODE=0
Write-Host 'Native EVTX export/reopen and exact policy restoration passed.'
