$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
. (Join-Path $PSScriptRoot '../scripts/TargetedSaclPlanning.ps1')
$count = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message }; $script:count++ }
$wef = Get-WelaAuditProfilePlan -Profile microsoft-wef-reviewed-2026-09 -Role Client -Build 26100
$plan = Get-WelaTargetedSaclPlan -AuditPlan $wef
$reference = @($plan.Targets | Where-Object Origin -like 'Microsoft WEF*')
Assert ($reference.Count -eq 2) 'Both exact WEF Appendix B targets must be present.'
Assert (($reference.PrincipalSid | Select-Object -Unique) -eq 'S-1-5-11') 'WEF principal differs from WELA Everyone.'
Assert ($reference[0].Rights.Count -eq 2 -and $reference[1].Rights.Count -eq 3) 'WEF Run/RunOnce rights must stay distinct.'
Assert ($reference[0].AuditFlags.Count -eq 1 -and $reference[0].AuditFlags[0] -eq 'Success') 'WEF audits success only.'
Assert ($reference[0].PolicyMode -eq 'not-configured') 'WEF documentary Not Configured must not become registry auditing.'
Assert (@($plan.Targets | Where-Object { $_.Observation.PathState -ne 'Unknown' }).Count -eq 0) 'Offline planning must never credit live paths.'
Assert (-not $plan.UserInventory.Complete) 'Offline user inventory must remain incomplete.'
Assert ($plan.UsableRuleCredit -eq 0 -and $plan.GenerationReadiness -eq 'Conditional') 'No event evidence means no rule uplift.'
foreach ($role in @('Client', 'MemberServer', 'DomainController', 'ADCS')) {
    $asd = Get-WelaAuditProfilePlan -Profile asd-native-2021-10 -Role $role -Build 26100
    $without = Get-WelaTargetedSaclPlan -AuditPlan $asd
    Assert (@($without.Targets | Where-Object PolicySelected).Count -eq 0) "$role ASD optional targets should not be selected implicitly."
    $asd = Get-WelaAuditProfilePlan -Profile asd-native-2021-10 -Role $role -Build 26100 -IncludeOptional
    $with = Get-WelaTargetedSaclPlan -AuditPlan $asd
    Assert (@($with.Targets | Where-Object { -not $_.PolicySelected }).Count -eq 0) "$role ASD optional selection must propagate."
    Assert (@($with.Targets | Where-Object RequiredPolicyMask -ne 3).Count -eq 0) "$role ASD requires success and failure."
}
# Native boundary fixtures: loaded, unloaded, Default, unresolved and redirected users.
function Get-WelaSaclUserInventory {
    [pscustomobject]@{ Complete = $false; Diagnostics = @('One profile could not be read.'); Users = @(
        [pscustomobject]@{ Sid='S-1-5-21-1'; ProfilePath='C:\Users\One'; HiveLoaded=$true; Diagnostic='' },
        [pscustomobject]@{ Sid='S-1-5-21-2'; ProfilePath='D:\Two'; HiveLoaded=$false; Diagnostic='' },
        [pscustomobject]@{ Sid='Default'; ProfilePath='C:\Users\Default'; HiveLoaded=$false; Diagnostic='' }
    ) }
}
$script:probeCalls = 0
function Get-WelaSaclTargetObservation {
    param($Path, $Kind)
    $script:probeCalls++
    $state = if ($Path -like '*RunOnce') { 'Inaccessible' } elseif ($Path -like '*RunOnceEx') { 'Missing' } else { 'Exists' }
    [pscustomobject]@{ PathState=$state; SaclReadState='Unknown'; Diagnostic='Fixture' }
}
function Resolve-WelaSaclUserFile {
    param($User, $RelativePath)
    if (-not $User.HiveLoaded) { return [pscustomobject]@{ Path=$null; State='UnloadedHive'; Diagnostic='No offline hive load.' } }
    [pscustomobject]@{ Path='\\fileserver\redirected\Startup'; State='Redirected'; Diagnostic='Explicit redirected folder' }
}
$live = Get-WelaTargetedSaclPlan -AuditPlan $wef -Live
Assert ($script:probeCalls -gt 0) 'Matching live host should inspect paths.'
Assert (@($live.Targets | Where-Object { $_.UserSid -eq 'S-1-5-21-2' -and $_.Observation.PathState -eq 'UnloadedHive' }).Count -eq 13) 'Unloaded hive and unresolved known folders must be reported for every user target.'
Assert (@($live.Targets | Where-Object { $_.Resolution -eq 'Redirected' }).Count -eq 2) 'Redirected files must be explicit.'
Assert (@($live.Targets | Where-Object { $_.Observation.PathState -eq 'Inaccessible' }).Count -gt 0) 'Access denied is not missing or compliant.'
Assert (@($live.Targets | Where-Object { $_.Observation.PathState -eq 'Missing' }).Count -gt 0) 'Missing paths must be explicit.'
Assert (-not $live.UserInventory.Complete -and $live.UserInventory.Diagnostics.Count -gt 0) 'Partial inventory diagnostics must survive.'
$script:probeCalls = 0
$skip = Get-WelaTargetedSaclPlan -AuditPlan $wef -Mode Skip -Live
Assert ($script:probeCalls -eq 0) 'Explicit skip must not inspect targets.'
Assert (@($skip.Targets | Where-Object { $_.Observation.PathState -ne 'Skipped' }).Count -eq 0) 'Every skipped target retains a gap.'
Assert ($skip.TelemetryGap -like '*explicitly skipped*') 'Skip gap must be visible in top-level report.'
# Reload native helpers. Network paths must never trigger Get-Item/authentication.
. (Join-Path $PSScriptRoot '../scripts/TargetedSaclPlanning.ps1')
function Get-Item { throw 'Unexpected path access.' }
$remote = Get-WelaSaclTargetObservation -Path '\\server\share\Startup' -Kind FileSystem
Assert ($remote.PathState -eq 'RemoteNotInspected') 'Read-only planning must not access remote known folders.'
$unloaded = Resolve-WelaSaclUserFile -User ([pscustomobject]@{HiveLoaded=$false}) -RelativePath 'AppData\Roaming\Signal'
Assert ($unloaded.State -eq 'UnloadedHive') 'Unloaded hive must not fall back to operator APPDATA.'
# Real CLI offline JSON export exercises integration without changing Windows.
Remove-Item Function:Get-Item
$temp = Join-Path ([IO.Path]::GetTempPath()) ('wela-sacl-plan-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    # Different role/build deliberately prevents live probing even on Windows CI.
    & (Join-Path $PSScriptRoot '../WELA.ps1') plan -Profile asd-native-2021-10 -Role Client -Build 22001 -IncludeOptional -SaclMode Skip -PlanPath $temp | Out-Null
    $json = Get-Content -LiteralPath $temp -Raw | ConvertFrom-Json
    Assert ($json.SaclPrerequisites.Mode -eq 'Skip') 'Public CLI JSON must include selected mode.'
    Assert ($json.SaclPrerequisites.Targets.Count -gt 40) 'Public CLI must export target details.'
    Assert ($json.SaclPrerequisites.ObjectPolicies.Count -eq 3) 'Plan links File System, Registry and Handle Manipulation.'
} finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
Write-Host "PASS: $count targeted SACL planning assertions. No audit policies or ACLs changed."
