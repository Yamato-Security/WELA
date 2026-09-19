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
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('wela-cli-audit-' + [guid]::NewGuid().ToString() + '.json')
try {
    # Exercise real script dispatch and export without printing the 59-row table or changing policy.
    & (Join-Path $PSScriptRoot '../WELA.ps1') audit -Profile wela-2.2.0 -PlanPath $temp 6>$null | Out-Null
    $export = Get-Content -LiteralPath $temp -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($export.policies.Count -ne 59 -or $export.role -ne $context.Role -or $export.build -ne $context.Build -or $export.profile -ne 'wela-2.2.0') {
        throw 'CLI audit export did not preserve all policies and the detected role/build.'
    }
    if (@($export.policies | Where-Object { $null -eq $_.currentMask }).Count -ne 0) {
        throw 'CLI audit unexpectedly exported unknown effective policy values.'
    }
} finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
Write-Host "PASS: queried all $($current.Count) effective audit policies on $($context.Role) build $($context.Build); CLI audit JSON verified; no settings changed."
