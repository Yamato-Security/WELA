# Read-only Windows smoke: no traffic generation, profile changes, ACL writes, or service operations.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { Write-Host 'SKIP: Windows only'; return }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/FirewallLogging.ps1')
$before = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogMaxSizeKilobytes, LogFileName) | ConvertTo-Json -Depth 4
$plan = @(Get-WelaFirewallLoggingPlan)
if ($plan.Count -ne 3) { throw 'Expected all three firewall profiles.' }
foreach ($entry in $plan) {
    if (-not $entry.Before -or $entry.Before.Effective.Name -ne $entry.Name -or $entry.Before.Local.Name -ne $entry.Name) {
        throw "Could not read actual effective/local profile $($entry.Name): $($entry.Diagnostic)"
    }
    if ($entry.TargetAccess.State -notin @('VerifiedExplicitGrant', 'Unknown', 'Blocked')) { throw 'Unexpected ACL observation.' }
    Write-Host "$($entry.Name): $($entry.Status); effective size $($entry.Before.Effective.LogMaxSizeKilobytes) KiB; service access $($entry.TargetAccess.State): $($entry.TargetAccess.Diagnostic)"
}
$path = Join-Path ([IO.Path]::GetTempPath()) ('wela-firewall-readonly-' + [guid]::NewGuid().ToString('N'))
$context = New-WelaConfigurationContext -DryRun -Auto -BackupPath $path
Set-WelaFirewallLoggingControls -Context $context -Plan $plan
if (Test-Path -LiteralPath $path) { throw 'Dry run unexpectedly created a recovery directory.' }
if (@($context.Results | Where-Object Status -eq Applied).Count) { throw 'Dry run unexpectedly applied a control.' }
$after = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogMaxSizeKilobytes, LogFileName) | ConvertTo-Json -Depth 4
if ($before -ne $after) { throw 'Firewall state changed during the read-only smoke.' }
Write-Host 'PASS: real ActiveStore/PersistentStore reads, conservative service ACL inspection and dry run; effective policy unchanged. Traffic/log generation and forwarding remain untested.'
