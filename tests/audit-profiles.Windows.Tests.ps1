# Read-only Windows smoke test: requires administrator or audit-policy query permission.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$current = Get-WelaEffectiveAuditPolicy
$catalog = (Import-WelaAuditProfiles).catalog
if ($current.Count -ne $catalog.Count) { throw "Native API returned $($current.Count) policies; expected $($catalog.Count)." }
foreach ($policy in $catalog) {
    if (-not $current.ContainsKey($policy.guid) -or $current[$policy.guid] -notin @(0, 1, 2, 3)) {
        throw "Missing/invalid effective state: $($policy.id)"
    }
}
$context = Get-WelaHostContext
$plan = Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role $context.Role -Build $context.Build -Current $current
Assert-WelaAuditProfileTarget -Plan $plan -Context $context -Current $current
Write-Host "PASS: queried all $($current.Count) effective audit policies on $($context.Role) build $($context.Build); no settings changed."
