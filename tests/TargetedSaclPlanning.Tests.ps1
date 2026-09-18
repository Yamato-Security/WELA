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
# Verify actual resolver against real catalog escaping, not a pre-normalized fixture.
$script:knownFolder = '%USERPROFILE%\AppData\Roaming'
$script:key = [pscustomobject]@{}
$script:key | Add-Member ScriptMethod GetValue { param($Name,$Default,$Options) if ($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { throw 'Unsafe variable expansion mode' }; return $script:knownFolder }
function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction) return $script:key }
$definitions = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/audit_sacl_targets.json') -Raw | ConvertFrom-Json
$user = [pscustomobject]@{Sid='S-1-5-21-1';ProfilePath='C:\Users\One';HiveLoaded=$true}
$signal = Resolve-WelaSaclUserFile -User $user -RelativePath $definitions.user_files[1].relpath
Assert ($signal.State -eq 'Resolved' -and $signal.Path -eq 'C:\Users\One\AppData\Roaming\Signal') 'Actual doubled-separator catalog path must not mislabel a default known folder as redirected.'
$script:knownFolder = '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
$startup = Resolve-WelaSaclUserFile -User $user -RelativePath $definitions.user_files[0].relpath
Assert ($startup.State -eq 'Resolved') 'Actual Startup catalog path normalizes before comparison.'
$script:knownFolder = '\\server\share\Startup'
Assert ((Resolve-WelaSaclUserFile -User $user -RelativePath $definitions.user_files[0].relpath).State -eq 'Redirected') 'Real redirected Startup remains distinguished.'
Assert (@($live.Targets | Where-Object { $_.Scope -eq 'user_registry' -and $_.Path -match '\\\\' }).Count -eq 0) 'User registry keys normalize catalog separators.'
# Failures inside an individual profile must affect global inventory completeness.
function Get-ChildItem {
    param($LiteralPath,$ErrorAction)
    if ($LiteralPath -eq 'Registry::HKEY_USERS') { return }
    [pscustomobject]@{PSChildName='S-1-5-21-1';PSPath='Registry::profile-one'}
}
$script:profilePath = $null
$script:profileKey = [pscustomobject]@{}
$script:profileKey | Add-Member ScriptMethod GetValue {
    param($Name,$Default,$Options)
    if ($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { throw 'ProfileList read must preserve unexpanded tokens.' }
    if ($Name -eq 'Default') { return 'C:\Users\Default' }
    if ($null -eq $script:profilePath) { throw 'Profile path denied' }
    return $script:profilePath
}
function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction) return $script:profileKey }
$inventory = Get-WelaSaclUserInventory
Assert (-not $inventory.Complete -and $inventory.Diagnostics.Count -gt 0 -and $inventory.Users[0].ProfilePath -eq $null) 'Unreadable per-user profile path must not yield complete inventory.'
$script:profilePath = '%USERPROFILE%\AnotherProfile'
$inventory = Get-WelaSaclUserInventory
Assert (-not $inventory.Complete -and $inventory.Users[0].ProfilePath -eq $null) 'ProfileList must not expand operator USERPROFILE for another user.'
$script:profilePath = 'C:\Users\One'
Assert (Get-WelaSaclUserInventory).Complete 'Known absolute profiles and Default form a complete inventory.'
Remove-Item Function:Get-ChildItem
# Guard mapped drives and every ancestor before any descendants or ACL read.
$script:accessed = @(); $script:aclCalls = 0; $script:remoteDrive = $false
function Get-PSDrive { param($Name,$PSProvider,$ErrorAction) [pscustomobject]@{Root='C:\';DisplayRoot=$(if ($script:remoteDrive) {'\\server\share'} else {$null})} }
function Get-Item {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    $script:accessed += $LiteralPath
    if ($LiteralPath -like 'C:\Users\*') { throw 'Guard must not traverse the Users junction.' }
    [pscustomobject]@{Attributes=$(if ($LiteralPath -eq 'C:\Users') {[IO.FileAttributes]::ReparsePoint} else {[IO.FileAttributes]::Directory})}
}
function Get-Acl { $script:aclCalls++; throw 'ACL reads must not cross redirect boundaries.' }
$guarded = Get-WelaSaclTargetObservation -Path 'C:\Users\One\AppData\Roaming\Signal' -Kind FileSystem
Assert ($guarded.PathState -eq 'ReparsePoint' -and $script:accessed.Count -eq 2 -and $script:aclCalls -eq 0) 'Ancestor junction stops before child resolution or Get-Acl.'
$script:accessed=@(); $script:remoteDrive=$true
$guarded = Get-WelaSaclTargetObservation -Path 'Z:\Startup' -Kind FileSystem
Assert ($guarded.PathState -eq 'RemoteNotInspected' -and $script:accessed.Count -eq 0) 'Mapped network drive never reaches Get-Item.'
Remove-Item Function:Get-Item, Function:Get-PSDrive, Function:Get-Acl
# Extract and execute only the option guard; never execute configure-sacl dispatch.
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'),[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'CLI must parse after adding explicit SaclMode command guard.'
$guard=$ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith("if (`$PSBoundParameters.ContainsKey('SaclMode')") } | Select-Object -First 1
Assert ($null -ne $guard) 'Public CLI must reject ignored SaclMode before dispatch.'
$exercise=[scriptblock]::Create('param($SaclMode,$Cmd,$Profile)' + [Environment]::NewLine + $guard.Extent.Text)
$rejected=$false
try { & $exercise -SaclMode Skip -Cmd configure-sacl } catch { $rejected=$true }
Assert $rejected 'configure-sacl -SaclMode Skip must be rejected before any legacy SACL mutator.'
$rejected=$false
try { & $exercise -SaclMode Skip -Cmd configure } catch { $rejected=$true }
Assert $rejected 'Legacy configure without Profile cannot silently ignore SaclMode.'
& $exercise -SaclMode Skip -Cmd plan -Profile wela-2.2.0
& $exercise -SaclMode Skip -Cmd configure -Profile wela-2.2.0
# Real CLI offline JSON export exercises integration without changing Windows.
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
