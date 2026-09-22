param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {Write-Host 'Skipped: native Windows required.';exit 0}
if (-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {throw 'Explicit opt-in on a disposable GitHub-hosted runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/AuditRecovery.ps1')
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-native-named-recovery-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$catalog=@(Get-WelaNamedRecoveryCatalog)
$safety=@(foreach ($item in $catalog) {[pscustomobject]@{Definition=$item;Before=(Get-WelaRegistryState $item.Path $item.Name)}})
$created=New-Object 'System.Collections.Generic.List[string]'
foreach ($item in $catalog) {
    $path=$item.Path
    while (-not (Test-Path -LiteralPath $path)) {if (-not $created.Contains($path)) {$created.Add($path)};$path=$path.Substring(0,$path.LastIndexOf('\'))}
}
Write-WelaRecoveryArtifact (Join-Path $temp 'safety-before.json') $safety
$sentinel='WelaRecoveryFixture_'+[guid]::NewGuid().ToString('N');$sentinelPath=$null
try {
    $sequence=0
    foreach ($definition in $catalog) {
        foreach ($absent in @($false,$true)) {
            $sequence++;$case=Join-Path $temp ('case-'+$sequence);$null=New-Item -ItemType Directory $case
            New-WelaRegistryKey $definition.Path
            if ($absent) {Remove-ItemProperty -LiteralPath $definition.Path -Name $definition.Name -ErrorAction SilentlyContinue}
            else {$null=New-ItemProperty -LiteralPath $definition.Path -Name $definition.Name -Value 0 -PropertyType DWord -Force}
            $before=Get-WelaNamedRecoveryObservation $definition
            $context=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $case 'backup')
            Set-WelaRegistryControl -Context $context -Path $definition.Path -Name $definition.Name -Value 1 -Type DWord
            $original=Join-Path $case 'original.json'
            $report=Complete-WelaConfiguration -Context $context -ResultsPath $original
            if ($report.ExitCode -ne 0 -or $report.Results[0].Status -ne 'Applied') {throw 'Native configuration did not create Applied evidence.'}
            $plan=Invoke-WelaAuditRecovery -JournalPath (Join-Path $context.BackupPath 'before.jsonl') -OriginalResultsPath $original -ControlId $definition.Id -OutputPath (Join-Path $case 'plan')
            $planPath=Join-Path $plan.OutputPath 'plan.json'
            $dry=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -DryRun
            if ($dry.Results[0].Status -ne 'WouldRestore' -or (Get-WelaRegistryState $definition.Path $definition.Name).Value -ne 1) {throw 'Native dry-run changed the selected value.'}
            # A neighboring value change must block before any recovery mutation.
            $sentinelPath=$definition.Path;$null=New-ItemProperty -LiteralPath $sentinelPath -Name $sentinel -Value 'owned-fixture' -PropertyType String
            $refused=$false
            try {$null=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -DryRun} catch {if ($_.Exception.Message -notmatch 'independently rebuilt') {throw};$refused=$true}
            if (-not $refused -or (Get-WelaRegistryState $definition.Path $definition.Name).Value -ne 1) {throw 'Neighbor drift did not refuse safely.'}
            Remove-ItemProperty -LiteralPath $sentinelPath -Name $sentinel;$sentinelPath=$null
            $result=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -OutputPath (Join-Path $case 'recovered') -Auto
            $after=Get-WelaNamedRecoveryObservation $definition
            if ($result.ExitCode -ne 0 -or $result.Results[0].Status -ne 'Restored' -or (Get-WelaRecoveryKey (Get-WelaNamedRecoveryState $after)) -cne (Get-WelaRecoveryKey (Get-WelaNamedRecoveryState $before)) -or -not [Wela.NamedRegistryRecovery.Key]::Preserved($before,$after)) {throw ($result | ConvertTo-Json -Depth 20)}
            $again=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -OutputPath (Join-Path $case 'again') -Auto
            if ($again.ExitCode -ne 0 -or $again.Results[0].Status -ne 'AlreadyRecovered') {throw 'Native named-value recovery is not idempotent.'}
            Write-Host "Native named recovery passed: $($definition.Name), prior absence=$absent; typed value, neighboring values, children, owner/group/DACL preserved."
        }
    }
} finally {
    $errors=@()
    if ($sentinelPath) {try {Remove-ItemProperty -LiteralPath $sentinelPath -Name $sentinel -ErrorAction Stop} catch {$errors+=$_.Exception.Message}}
    foreach ($saved in $safety) {
        try {
            $definition=$saved.Definition;$before=$saved.Before
            if ($before.ValueExists) {$null=New-ItemProperty -LiteralPath $definition.Path -Name $definition.Name -Value $before.Value -PropertyType $before.Type -Force}
            elseif (Test-Path -LiteralPath $definition.Path) {Remove-ItemProperty -LiteralPath $definition.Path -Name $definition.Name -ErrorAction SilentlyContinue}
        } catch {$errors+=$_.Exception.Message}
    }
    foreach ($path in ($created | Sort-Object Length -Descending)) {
        try {if (Test-Path -LiteralPath $path) {$key=Get-Item -LiteralPath $path;if ($key.GetValueNames().Count -or $key.GetSubKeyNames().Count) {throw "Owned fixture-created key is no longer empty: $path"};Remove-Item -LiteralPath $path -ErrorAction Stop}} catch {$errors+=$_.Exception.Message}
    }
    foreach ($saved in $safety) {
        try {if ((Get-WelaRecoveryKey (Get-WelaRegistryState $saved.Definition.Path $saved.Definition.Name)) -cne (Get-WelaRecoveryKey $saved.Before)) {throw "Safety restoration differs: $($saved.Definition.Name)"}} catch {$errors+=$_.Exception.Message}
    }
    if ($errors.Count) {throw "Native registry safety restoration failed; evidence retained at $temp : $($errors -join '; ')"}
    Remove-Item -LiteralPath $temp -Recurse -Force
}
$global:LASTEXITCODE=0
