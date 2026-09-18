# Real Windows reader smoke only. No native setter, SaveChanges or policy mutation.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/EventLogSettings.psm1') -Force
foreach ($log in @('Application', 'System', 'Setup', 'Security')) {
    $before = Get-WelaEventLogState -Log $log
    if ($before.ReadStatus -ne 'Available') { throw "Cannot inspect $log : $($before.Diagnostic)" }
    $row = @(Get-WelaEventLogAudit -Profile 'cis-v4-source' | Where-Object Log -eq $log)
    $after = Get-WelaEventLogState -Log $log
    if ($row.Count -ne 1 -or $row[0].CurrentMaximumBytes -ne $before.MaximumSizeInBytes -or $row[0].RetentionDays -ne 'Unknown') { throw "Audit did not represent the live $log configuration." }
    if ($before.MaximumSizeInBytes -ne $after.MaximumSizeInBytes -or $before.LogMode -ne $after.LogMode) { throw "Observed concurrent change to $log during read-only smoke." }
}
$missing = Get-WelaEventLogState -Log ('WELA-Unregistered-' + [guid]::NewGuid().ToString('N'))
if ($missing.ReadStatus -ne 'Missing') { throw "Missing Windows channel was misclassified: $($missing.ReadStatus) $($missing.Diagnostic)" }
Write-Host 'PASS: live read-only event-log audit; exact bytes, modes and missing-channel reporting verified.'
