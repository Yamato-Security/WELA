# Deterministic tests: no elevation, Windows policy writes, or Pester dependency.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$script:Checks = 0
function Assert([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action | Out-Null } catch { Assert ($_.Exception.Message -match $Pattern) "Expected '$Pattern', got '$($_.Exception.Message)'"; return }
    throw "Expected exception matching '$Pattern'."
}
function Policy($Plan, $Id) { $Plan.policies | Where-Object { $_.id -eq $Id } }
$data = Import-WelaAuditProfiles
Assert ($data.catalog.Count -eq 59) 'all canonical audit subcategories are represented'
$zero = @{}
foreach ($policy in $data.catalog) { $zero[$policy.guid] = 0 }
foreach ($profile in $data.profiles) {
    foreach ($range in $profile.appliesTo) {
        foreach ($role in $range.roles) {
            $plan = Get-WelaAuditProfilePlan -Profile $profile.id -Role $role -Build $range.minBuild -Current $zero
            Assert ($plan.policies.Count -eq 59) "$($profile.id)/$role preserves omitted policies explicitly"
            Assert ($plan.provenance.Count -gt 0 -and $plan.schemaSha256.Length -eq 64) 'versioned source and schema fingerprints'
        }
    }
}
$wela = Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role Client -Build 26100 -Current $zero
foreach ($id in @('Process Termination', 'RPC Events', 'Detailed File Share', 'Other Policy Change Events')) {
    $row = Policy $wela $id
    Assert ($row.mode -eq 'exact' -and $row.targetMask -eq 3) "$id recommendation matches existing configure SF policy"
}
Assert ((Policy $wela 'File System').action -eq 'Optional (not selected)') 'optional controls preserve current state by default'
$opt = Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role Client -Build 26100 -Current $zero -IncludeOptional
Assert ((Policy $opt 'File System').targetMask -eq 3) 'optional control is explicit opt-in'
Assert ((Policy $opt 'File System').prerequisites -match 'SACL') 'SACL dependency is visible'
Assert ((Policy $wela 'Directory Service Access').mode -eq 'not-applicable') 'DC auditing is role scoped'
$adcs = Get-WelaAuditProfilePlan -Profile wela-2.2.0 -Role ADCS -Build 20348 -Current $zero
Assert ((Policy $adcs 'Certification Services').targetMask -eq 3) 'CA role is supported'
Assert ((Policy $adcs 'Certification Services').prerequisites -match 'AuditFilter') 'CA prerequisite not silently claimed applied'
$shareGuid = (Policy $wela 'Detailed File Share').guid
$current = $zero.Clone(); $current[$shareGuid] = 1
$cis = Get-WelaAuditProfilePlan -Profile cis-win11-v4-l1 -Role Client -Build 26100 -Current $current
Assert ((Policy $cis 'Detailed File Share').mode -eq 'minimum') 'CIS includes Failure is represented as minimum'
Assert ((Policy $cis 'Detailed File Share').targetMask -eq 3) 'minimum Failure preserves preexisting Success'
$asd = Get-WelaAuditProfilePlan -Profile asd-native-2021-10 -Role Client -Build 26100 -Current $current
Assert ((Policy $asd 'Detailed File Share').mode -eq 'not-configured') 'ASD explicit NC is retained'
Assert ($null -eq (Policy $asd 'Detailed File Share').targetMask) 'NC does not become disabled'
Assert ((Policy $asd 'RPC Events').mode -eq 'unchanged') 'omission is unchanged, not no-auditing'
$unknown = Get-WelaAuditProfilePlan -Profile cis-win11-v4-l1 -Role Client -Build 26100
Assert ($null -eq (Policy $unknown 'Detailed File Share').targetMask -and (Policy $unknown 'Detailed File Share').action -eq 'Unknown') 'unknown current does not become disabled before minimum merge'
Assert-Throws { Get-WelaAuditProfilePlan -Profile microsoft-sct-win11-24h2 -Role Client -Build 26200 } 'does not support'
Assert-Throws { Get-WelaAuditProfilePlan -Profile microsoft-sct-win11-24h2 -Role DomainController -Build 26100 } 'does not support'
Assert-Throws { Get-WelaAuditProfilePlan -Profile typo -Role Client -Build 26100 } 'Unknown audit profile'
# Inject a stateful native boundary, exercising actual selection, merge, verify and failure behavior.
$script:State = $zero.Clone(); $script:Writes = @()
$reader = { return $script:State.Clone() }
$writer = { param($Guid, $Mask) $script:Writes += $Guid; $script:State[$Guid] = $Mask }
$context = { [pscustomobject]@{ Role = 'Client'; Build = 26100 } }
$applied = Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy $writer -ReadContext $context -Confirm:$false
Assert $applied.success 'apply succeeds after verified effective reads'
Assert ($script:Writes.Count -gt 0) 'selected exact policies were applied'
Assert (@($applied.results | Where-Object { $_.status -eq 'Applied' -and $_.effectiveMask -ne $_.targetMask }).Count -eq 0) 'applied always means verified'
$count = $script:Writes.Count
$again = Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy $writer -ReadContext $context -Confirm:$false
Assert ($again.success -and $script:Writes.Count -eq $count) 'applying twice is idempotent using fresh current state'
# Apply a stale minimum plan after a preexisting Success flag is introduced: merge fresh state.
$script:State = $zero.Clone(); $script:State[$shareGuid] = 1
$minimum = Invoke-WelaAuditProfilePlan -Plan $cis -ReadPolicy $reader -WritePolicy $writer -ReadContext $context -Confirm:$false
Assert ($minimum.success -and $script:State[$shareGuid] -eq 3) 'fresh effective flags are preserved in minimum apply'
$script:State = $zero.Clone()
$failed = Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy { throw 'command failed' } -ReadContext $context -Confirm:$false
Assert (-not $failed.success -and @($failed.results | Where-Object { $_.status -eq 'Failed' }).Count -gt 0) 'native failure is machine-readable'
$mismatch = Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy { param($Guid, $Mask) } -ReadContext $context -Confirm:$false
Assert (-not $mismatch.success) 'zero exit without effective change does not count as success'
$script:Writes = @()
$whatIf = Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy $writer -ReadContext $context -WhatIf
Assert ($script:Writes.Count -eq 0) 'WhatIf never invokes native writer'
Assert-Throws { Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy { @{} } -WritePolicy $writer -ReadContext $context -Confirm:$false } 'unknown current'
Assert ($script:Writes.Count -eq 0) 'unknown preflight refuses all writes'
Assert-Throws { Invoke-WelaAuditProfilePlan -Plan $wela -ReadPolicy $reader -WritePolicy $writer -ReadContext { [pscustomobject]@{ Role = 'DomainController'; Build = 26100 } } } 'actual Windows host'
$defaults = Get-WelaAuditProfilePlan -Profile windows-defaults-reviewed-2026-09 -Role Client -Build 26100 -Current $zero
Assert-Throws { Invoke-WelaAuditProfilePlan -Plan $defaults -ReadPolicy $reader -WritePolicy $writer -ReadContext $context } 'reference'
# Schema rejects bad policy names, duplicate GUIDs, invalid masks/modes, and unknown provenance.
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('wela-profile-test-' + [guid]::NewGuid().ToString() + '.json')
try {
    foreach ($case in @('guid', 'mask', 'mode', 'source', 'unknown')) {
        $copy = Get-Content (Join-Path $PSScriptRoot '../config/audit_profiles.json') -Raw | ConvertFrom-Json
        switch ($case) {
            'guid' { $copy.catalog[1].guid = $copy.catalog[0].guid }
            'mask' { $copy.profiles[0].controls.'Process Creation'.mask = 7 }
            'mode' { $copy.profiles[0].controls.'Process Creation'.mode = 'invented' }
            'source' { $copy.profiles[0].sourceIds = @('unreviewed') }
            'unknown' { $copy.profiles[0].controls | Add-Member NoteProperty 'Typo Policy' ([pscustomobject]@{ mode = 'exact'; mask = 3 }) }
        }
        $copy | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temp -Encoding UTF8
        Assert-Throws { Import-WelaAuditProfiles -Path $temp } 'Invalid|Unknown|duplicate'
    }
} finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
# Legacy Yamato audit display now takes recommendations from the shared profile, including omitted policies.
. (Join-Path $PSScriptRoot '../WELA.ps1') help -Role Client -Build 26100
function GetAuditpol { return @{} }
$legacy = BuildAuditResult -all_rules @() -Baseline YamatoSecurity -enabledguid @()
foreach ($id in @('Process Termination', 'RPC Events', 'Detailed File Share', 'Other Policy Change Events')) {
    $entry = $legacy | Where-Object { $_.SubCategory -eq $id }
    Assert ($entry.RecommendedSetting -eq 'Success and Failure [exact]') "legacy audit/settings shares $id recommendation"
}
Assert (@($legacy | Where-Object { $_.Category -like 'Security Advanced*' }).Count -eq 59) 'legacy display includes all canonical GUIDs'
# An unsupported legacy configure target must fail before reaching the old setup body.
function TestWindows { return $true }
function TestAdministrator { return $true }
function Get-WelaHostContext { [pscustomobject]@{ Role = 'Client'; Build = 19045 } }
function Get-WelaEffectiveAuditPolicy { return $zero.Clone() }
function CollectAuditpol { throw 'Reached the old configuration body before profile validation' }
Assert-Throws { ConfigureAuditSettings -Auto } 'does not support'
Write-Host "PASS: $script:Checks audit profile checks; no Windows settings changed."
