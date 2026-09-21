$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
$script:checks=0
function Assert($Condition,[string]$Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:checks++ }
function Rule([string]$Enabled='True',[string]$Inbound='Require',[string]$Outbound='Request',[string]$Health='OK') {
    [pscustomobject]@{Name='owned';Enabled=$Enabled;InboundSecurity=$Inbound;OutboundSecurity=$Outbound;PrimaryStatus=$Health}
}
$script:rule=Rule
$positive=Get-WelaIpsecPrerequisite -ReadRules {$script:rule} -ReadAssociations {}
Assert ($positive.Status -eq 'Applicable' -and $positive.Rules[0].Qualifies) 'healthy effective securing rule qualifies'
$none=Get-WelaIpsecPrerequisite -ReadRules {} -ReadAssociations {}
Assert ($none.Status -eq 'NotObservedWithinScope' -and $none.Limitations -match 'legacy IPsec') 'empty complete inventory is scope-limited absence'
foreach ($candidate in @((Rule False),(Rule False Require Request Inactive),(Rule True None None))) {
    $script:rule=$candidate
    $evidence=Get-WelaIpsecPrerequisite -ReadRules {$script:rule} -ReadAssociations {}
    Assert ($evidence.Status -eq 'NotObservedWithinScope' -and -not $evidence.Rules[0].Qualifies) 'disabled and exemption-only policies do not qualify'
}
foreach ($candidate in @((Rule True Require Request Error),(Rule True Require Request Unknown),(Rule True Require Request Inactive),(Rule Maybe),([pscustomobject]@{Name='missing'}))) {
    $script:rule=$candidate
    Assert ((Get-WelaIpsecPrerequisite -ReadRules {$script:rule} -ReadAssociations {}).Status -eq 'Unknown') 'invalid or unhealthy policy stays unknown'
}
$script:rule=Rule
Assert ((Get-WelaIpsecPrerequisite -ReadRules {$script:rule; throw 'denied midway'} -ReadAssociations {}).Status -eq 'Unknown') 'partial failed enumeration never qualifies'
Assert ((Get-WelaIpsecPrerequisite -ReadRules {$script:rule} -ReadAssociations {throw 'denied'}).Status -eq 'Unknown') 'failed independent SA observation prevents complete positive evidence'
Assert ((Get-WelaIpsecPrerequisite -ReadRules {$script:rule;$script:rule} -ReadAssociations {}).Status -eq 'Unknown') 'duplicate rule identities rejected'
Assert ((Get-WelaIpsecPrerequisite -ReadRules {1..4097} -ReadAssociations {}).Status -eq 'Unknown') 'native inventory cap remains unknown'
$sa=Get-WelaIpsecPrerequisite -ReadRules {} -ReadAssociations {[pscustomobject]@{Name='1';LocalEndpoint='192.0.2.1';RemoteEndpoint='192.0.2.2'}}
Assert ($sa.Status -eq 'Applicable' -and $sa.MainModeAssociations.Count -eq 1) 'valid native SA is independently positive evidence'
Assert ((Get-WelaIpsecPrerequisite -ReadRules {} -ReadAssociations {[pscustomobject]@{Name='1';LocalEndpoint='unknown';RemoteEndpoint='192.0.2.2'}}).Status -eq 'Unknown') 'malformed SA does not qualify'
Assert ((Get-WelaIpsecPrerequisite -Offline -ReadRules {throw 'must not run'} -ReadAssociations {throw 'must not run'}).Status -eq 'Unknown') 'offline never queries this host'
$script:zero=@{}; foreach ($policy in (Import-WelaAuditProfiles).catalog) {$script:zero[$policy.guid]=0}
$profile='microsoft-stronger-reviewed-2026-09';$guid='0CCE9218-69AE-11D9-BED3-505054503030'
function Plan([switch]$Optional,[switch]$Observe) { Get-WelaAuditProfilePlan -Profile $profile -Role MemberServer -Build 26100 -Current $script:zero -IncludeOptional:$Optional -ObserveIpsec:$Observe -ReadIpsec {$script:evidence} }
$script:evidence=$positive
$plan=Plan -Optional
$row=@($plan.policies|Where-Object id -eq 'IPsec Main Mode')[0]
Assert ($row.conditionalPrerequisite.Status -eq 'Unknown' -and $null -eq $row.targetMask) 'offline conditional plan has no applicable target'
$plan=Plan -Observe
Assert (($plan.policies|Where-Object id -eq 'IPsec Main Mode').action -eq 'Optional (not selected)') 'positive evidence never substitutes for explicit selection'
$plan=Plan -Observe -Optional
Assert (($plan.policies|Where-Object id -eq 'IPsec Main Mode').targetMask -eq 3) 'live selected positive plan retains exact SF mask'
$script:evidence=$none;$plan=Plan -Observe -Optional
Assert (($plan.policies|Where-Object id -eq 'IPsec Main Mode').action -like 'Preserve*') 'scope-limited absence explicitly preserves'
function Single-Plan {
    $p=Plan -Optional -Observe
    $p.policies=@($p.policies|Where-Object id -eq 'IPsec Main Mode')
    $p
}
$script:evidence=$positive;$plan=Single-Plan
$script:state=$script:zero.Clone();$script:writes=0;$script:reads=0
$contextReader={ [pscustomobject]@{Role='MemberServer';Build=26100} }
$writer={param($Guid,$Mask) $script:writes++;$script:state[$Guid]=$Mask}
$reader={$script:state.Clone()}
$result=Invoke-WelaAuditProfilePlan $plan -ReadContext $contextReader -ReadPolicy $reader -WritePolicy $writer -ReadIpsec {$positive} -Confirm:$false
Assert ($result.success -and $script:writes -eq 1 -and $result.results[0].prerequisiteObservations.Count -eq 2) 'direct executor observes and rechecks before write'
$script:state[$guid]=0;$script:writes=0
$result=Invoke-WelaAuditProfilePlan $plan -ReadContext $contextReader -ReadPolicy $reader -WritePolicy $writer -ReadIpsec {$none} -Confirm:$false
Assert ($result.success -and $script:writes -eq 0 -and $result.results[0].status -eq 'Skipped') 'unobserved condition never writes'
$result=Invoke-WelaAuditProfilePlan $plan -ReadContext $contextReader -ReadPolicy $reader -WritePolicy $writer -ReadIpsec {$script:reads++;if($script:reads -eq 1){$positive}else{$none}} -Confirm:$false
Assert (-not $result.success -and $script:writes -eq 0 -and $result.results[0].prerequisiteObservations.Count -eq 2) 'last-moment condition drift blocks direct executor'
$plan.profile='microsoft-sct-server2025-2602'
$result=Invoke-WelaAuditProfilePlan $plan -ReadContext $contextReader -ReadPolicy $reader -WritePolicy $writer -ReadIpsec {throw 'unrelated query'} -Confirm:$false
Assert ($result.success -and $script:writes -eq 1) 'other profile intent is unaffected'
$plan=Single-Plan;$plan|Add-Member NoteProperty CustomProfileSource ([pscustomobject]@{})
Assert (-not (Test-WelaIpsecConditionalPolicy $plan $plan.policies[0])) 'custom profile intent is not reclassified by its id'

# Public configure adapter: real runner and durable journal, injected native boundaries.
function Get-WelaRegistryState {param($Path,$Name) [pscustomobject]@{ValueExists=$true;Type='DWord';Value=1} }
function Get-WelaAuditPrecedenceSource { $null }
function Get-WelaNativeAuditPolicy {param($Guid) $script:state[$Guid] }
function Invoke-WelaNative {param($FilePath,$Arguments)
    Assert (Test-Path -LiteralPath (Join-Path $script:backup 'before.jsonl')) 'journal precedes native write'
    $script:writes++;$script:state[$guid]=3
}
function Read-Host {param($Prompt) $script:evidence=$none; 'y' }
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ipsec-'+[guid]::NewGuid().ToString('N'))
try {
    $script:evidence=$positive;$plan=Single-Plan;$script:state[$guid]=0;$script:writes=0
    $script:backup=Join-Path $root 'race';$ctx=New-WelaConfigurationContext -BackupPath $script:backup
    Set-WelaProfileAuditControls $ctx $plan -ReadIpsec {$script:evidence}
    $result=Complete-WelaConfiguration $ctx -Plan $plan
    $row=@($result.Results|Where-Object Id -eq 'AuditPolicy/IPsec Main Mode')[0]
    Assert ($row.Status -eq 'Failed' -and $script:writes -eq 0 -and $row.PrerequisiteObservations[-1].Status -eq 'NotObservedWithinScope') 'public runner rechecks after prompt/journal and retains negative evidence'
    $script:evidence=$positive;$script:backup=Join-Path $root 'positive';$ctx=New-WelaConfigurationContext -Auto -BackupPath $script:backup
    Set-WelaProfileAuditControls $ctx $plan -ReadIpsec {$script:evidence}
    $result=Complete-WelaConfiguration $ctx -Plan $plan
    $row=@($result.Results|Where-Object Id -eq 'AuditPolicy/IPsec Main Mode')[0]
    Assert ($row.Status -eq 'Applied' -and $script:writes -eq 1 -and $row.PrerequisiteObservations.Count -eq 5) 'public runner keeps plan/read/prewrite/readback/final native prerequisite observations'
    $script:evidence=$none;$script:backup=Join-Path $root 'negative';$ctx=New-WelaConfigurationContext -Auto -BackupPath $script:backup
    Set-WelaProfileAuditControls $ctx $plan -ReadIpsec {$script:evidence}
    $result=Complete-WelaConfiguration $ctx -Plan $plan
    Assert ($result.Skipped -eq 1 -and $script:writes -eq 1) 'negative public prerequisite is visible even when audit mask already matches'
} finally {if(Test-Path $root){Remove-Item $root -Recurse -Force}}
Write-Host "Passed $script:checks IPsec prerequisite assertions. No native mutations."
