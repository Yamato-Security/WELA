# Pure policy regressions. No Windows settings are read or changed.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$config = Import-WelaAuditProfiles
$assertions = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message : expected '$Expected', got '$Actual'." }
    $script:assertions++
}
$expected = @{
    'Group Membership' = @{ Guid = '0CCE9249-69AE-11D9-BED3-505054503030'; Mask = 1; Source = 'ms-sct' }
    'Application Group Management' = @{ Guid = '0CCE9239-69AE-11D9-BED3-505054503030'; Mask = 3; Source = 'cis-client' }
    'Authorization Policy Change' = @{ Guid = '0CCE9231-69AE-11D9-BED3-505054503030'; Mask = 1; Source = 'cis-client' }
    'MPSSVC Rule-Level Policy Change' = @{ Guid = '0CCE9232-69AE-11D9-BED3-505054503030'; Mask = 3; Source = 'ms-wef' }
    'IPsec Driver' = @{ Guid = '0CCE9213-69AE-11D9-BED3-505054503030'; Mask = 3; Source = 'ms-audit' }
    'Kernel Object' = @{ Guid = '0CCE921F-69AE-11D9-BED3-505054503030'; Mask = 3; Source = 'asd' }
}
$current = @{}
foreach ($policy in $config.catalog) { $current[$policy.guid] = 0 }
foreach ($role in @('Client', 'MemberServer', 'DomainController', 'ADCS')) {
    $plan = Get-WelaAuditProfilePlan -Profile 'wela-2.2.0' -Role $role -Build 26100 -Current $current
    foreach ($name in $expected.Keys) {
        $row = @($plan.policies | Where-Object { $_.id -eq $name })
        Assert-Equal $row.Count 1 "$role/$name has exactly one plan row"
        Assert-Equal $row[0].guid $expected[$name].Guid "$role/$name canonical GUID"
        Assert-Equal $row[0].targetMask $expected[$name].Mask "$role/$name applies the intended mask"
        Assert-Equal ($row[0].sourceIds -contains $expected[$name].Source) $true "$role/$name retains provenance"
    }
    $kernel = $plan.policies | Where-Object { $_.id -eq 'Kernel Object' }
    Assert-Equal ($kernel.prerequisites -match 'SACL') $true "$role kernel auditing reports object-SACL dependency"
}
# The WELA extension must not overwrite another guide's semantics.
$inherited = $current.Clone()
$inherited[$expected['Group Membership'].Guid] = 2
$inherited[$expected['Authorization Policy Change'].Guid] = 2
$cis = Get-WelaAuditProfilePlan -Profile 'cis-win11-v4-l1' -Role Client -Build 26100 -Current $inherited
foreach ($name in @('Group Membership', 'Authorization Policy Change')) {
    $row = $cis.policies | Where-Object { $_.id -eq $name }
    Assert-Equal $row.mode 'minimum' "CIS $name is a minimum"
    Assert-Equal $row.targetMask 3 "CIS $name preserves inherited failure auditing"
}
$wef = Get-WelaAuditProfilePlan -Profile 'microsoft-wef-reviewed-2026-09' -Role Client -Build 26100 -Current $current
Assert-Equal (($wef.policies | Where-Object { $_.id -eq 'Authorization Policy Change' }).targetMask) 3 'WEF authorization auditing retains both outcomes'
$server = Get-WelaAuditProfilePlan -Profile 'microsoft-sct-server2025-2602' -Role MemberServer -Build 26100 -Current $current
Assert-Equal (($server.policies | Where-Object { $_.id -eq 'Authorization Policy Change' }).targetMask) 1 'Server 2025 SCT authorization target remains success'
$asd = Get-WelaAuditProfilePlan -Profile 'asd-native-2021-10' -Role Client -Build 26100 -Current $current
Assert-Equal (($asd.policies | Where-Object { $_.id -eq 'Kernel Object' }).targetMask) 3 'ASD kernel target remains both outcomes'
Assert-Equal (($asd.policies | Where-Object { $_.id -eq 'Detailed File Share' }).mode) 'not-configured' 'ASD detailed-share setting is not silently enabled'
# Exercise the actual shared apply path using an in-memory provider.
$script:policyState = $current.Clone()
$script:writes = @{}
$plan = Get-WelaAuditProfilePlan -Profile 'wela-2.2.0' -Role Client -Build 26100 -Current $script:policyState
$result = Invoke-WelaAuditProfilePlan -Plan $plan -ReadPolicy { $script:policyState } -WritePolicy {
    param($Guid, $Mask)
    $script:policyState[$Guid] = $Mask
    $script:writes[$Guid] = $Mask
} -ReadContext { [pscustomobject]@{ Role = 'Client'; Build = 26100 } } -Confirm:$false
Assert-Equal $result.success $true 'Shared apply reports verified success with matching readback'
$kernelResult = $result.results | Where-Object { $_.id -eq 'Kernel Object' }
Assert-Equal ($kernelResult.prerequisites -match 'SACL') $true 'Apply result retains kernel SACL prerequisite'
Assert-Equal ($kernelResult.sourceIds -contains 'asd') $true 'Apply result identifies ASD kernel requirement'
Assert-Equal ($kernelResult.evidence -match 'ASD') $true 'Apply result retains source evidence'
Assert-Equal $result.role 'Client' 'Apply result retains selected role'
Assert-Equal $result.build 26100 'Apply result retains selected build'
foreach ($name in $expected.Keys) {
    Assert-Equal $script:writes[$expected[$name].Guid] $expected[$name].Mask "Apply requests correct $name mask"
}
$script:writes = @{}
$result = Invoke-WelaAuditProfilePlan -Plan $plan -ReadPolicy { $script:policyState } -WritePolicy {
    param($Guid, $Mask)
    $script:writes[$Guid] = $Mask
} -ReadContext { [pscustomobject]@{ Role = 'Client'; Build = 26100 } } -Confirm:$false
Assert-Equal $script:writes.Count 0 'Reapply is idempotent after all controls match'
Write-Host "PASS: $assertions native-audit-control assertions (mocked; no host changes)."
