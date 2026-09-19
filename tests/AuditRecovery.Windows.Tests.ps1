param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {Write-Host 'Skipped: native Windows required.';exit 0}
if (-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'Explicit opt-in on a disposable GitHub-hosted runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/AuditRecovery.ps1')
$guid='0cce922b-69ae-11d9-bed3-505054503030';$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$name='SCENoApplyLegacyAuditPolicy'
$mask=Get-WelaAuditPolicyMask $guid;$precedence=Get-WelaRegistryState $path $name
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-native-recovery-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$restored=$false
Write-WelaRecoveryArtifact (Join-Path $temp 'safety-before.json') ([pscustomobject]@{Mask=$mask;Precedence=$precedence})
try {
    # The test deliberately changes only this subcategory and local precedence.
    $null=New-ItemProperty -LiteralPath $path -Name $name -Value 1 -PropertyType DWord -Force
    $context=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $temp 'original-backup')
    Set-WelaAuditPolicyControl -Context $context -Policy @{GUID=$guid;Name='Process Creation'} -Mask (3 -bxor $mask) -Mode exact -RequirePrecedence
    $original=Join-Path $temp 'original-results.json'
    $report=Complete-WelaConfiguration -Context $context -ResultsPath $original
    if ($report.ExitCode -ne 0 -or $report.Results[0].Status -ne 'Applied') {throw 'Test configuration did not create a completed native journal.'}
    $plan=Invoke-WelaAuditRecovery -JournalPath (Join-Path $context.BackupPath 'before.jsonl') -OriginalResultsPath $original -ControlId 'AuditPolicy/Process Creation' -OutputPath (Join-Path $temp 'plan')
    $result=Invoke-WelaAuditRecovery -Action Restore -PlanPath (Join-Path $plan.OutputPath 'plan.json') -OutputPath (Join-Path $temp 'recovery') -Auto
    if ($result.ExitCode -ne 0 -or $result.Results[0].Status -ne 'Restored' -or (Get-WelaAuditPolicyMask $guid) -ne $mask) {throw ($result | ConvertTo-Json -Depth 20)}
    $again=Invoke-WelaAuditRecovery -Action Restore -PlanPath (Join-Path $plan.OutputPath 'plan.json') -OutputPath (Join-Path $temp 'again') -Auto
    if ($again.ExitCode -ne 0 -or $again.Results[0].Status -ne 'AlreadyRecovered') {throw 'Native recovery is not idempotent.'}
    Write-Host 'Native completed-journal planning, exact audit restoration and idempotence passed.'
} finally {
    $errors=@()
    try {Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $mask -Mode exact;if ((Get-WelaAuditPolicyMask $guid) -ne $mask) {throw 'Audit safety restoration differs.'}} catch {$errors+=$_.Exception.Message}
    try {
        if ($precedence.ValueExists) {$null=New-ItemProperty -LiteralPath $path -Name $name -Value $precedence.Value -PropertyType $precedence.Type -Force}
        else {Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue}
        if ((Get-WelaRecoveryKey (Get-WelaRegistryState $path $name)) -cne (Get-WelaRecoveryKey $precedence)) {throw 'Precedence safety restoration differs.'}
    } catch {$errors+=$_.Exception.Message}
    if ($errors.Count) {throw "Native safety restoration failed; evidence retained at $temp : $($errors -join '; ')"}
    Remove-Item -LiteralPath $temp -Recurse -Force
}
$global:LASTEXITCODE=0
