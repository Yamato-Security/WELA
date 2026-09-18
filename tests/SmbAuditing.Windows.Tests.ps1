# Native Windows read-only evidence: policy registry, local ADMX and SMB getters only.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'SKIP: Windows only'; return }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/SmbAuditing.ps1')
function Read-PolicySnapshot {
    foreach ($definition in Get-WelaSmbAuditDefinitions) {
        [pscustomobject]@{ Component = $definition.Component; Name = $definition.Name; State = Get-WelaRegistryState -Path $definition.Path -Name $definition.Name }
    }
}
$before = @(Read-PolicySnapshot) | ConvertTo-Json -Depth 8
$serverBefore = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EncryptData, RejectUnencryptedAccess | ConvertTo-Json
$clientBefore = Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, RequireEncryption, EnableInsecureGuestLogons | ConvertTo-Json
$plan = @(Get-WelaSmbAuditPlan)
if ($plan.Count -ne 6) { throw 'Expected all six SMB audit controls.' }
foreach ($entry in $plan) {
    if ($entry.Status -notin @('NotApplicable', 'Unknown', 'ChangeRequired', 'Compliant')) { throw 'Unexpected assessment status.' }
    Write-Host "$($entry.Definition.Component)/$($entry.Definition.Name): $($entry.Status); $($entry.Diagnostic)"
    if ($entry.Before.Runtime) { Write-Host "Runtime: $($entry.Before.Runtime.Status) / $($entry.Before.Runtime.Value)" }
}
$path = Join-Path ([IO.Path]::GetTempPath()) ('wela-smb-readonly-' + [guid]::NewGuid().ToString('N'))
$context = New-WelaConfigurationContext -DryRun -Auto -BackupPath $path
Set-WelaSmbAuditControls -Context $context -Plan $plan
if (Test-Path -LiteralPath $path) { throw 'Dry run created an unexpected recovery directory.' }
if (@($context.Results | Where-Object Status -eq Applied).Count) { throw 'Dry run applied a control.' }
$after = @(Read-PolicySnapshot) | ConvertTo-Json -Depth 8
$serverAfter = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EncryptData, RejectUnencryptedAccess | ConvertTo-Json
$clientAfter = Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, RequireEncryption, EnableInsecureGuestLogons | ConvertTo-Json
if ($before -ne $after -or $serverBefore -ne $serverAfter -or $clientBefore -ne $clientAfter) { throw 'Policy or security requirements changed during read-only test.' }
Write-Host 'PASS: native policy/ADMX/runtime observation and dry-run evidence; audit policies and security requirements unchanged. No event generation or ingestion test performed.'
