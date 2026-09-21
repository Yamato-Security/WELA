param([switch]$AllowDisposablePolicyWrite,[switch]$AllowDisposableIpsecRule)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'Native Windows fixture required.'}
if (-not $AllowDisposablePolicyWrite -or -not $AllowDisposableIpsecRule) {throw 'Disposable audit-policy and owned IPsec-rule opt-in are both required.'}
$repo=Split-Path $PSScriptRoot -Parent;$script:ScriptRoot=$repo
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module NetSecurity -ErrorAction Stop
. (Join-Path $repo 'scripts/Configuration.ps1')
$script:checks=0
function Assert($Condition,[string]$Message) {if(-not $Condition){throw "FAIL: $Message"};$script:checks++}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Assert ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'fixture is elevated'
$root=Join-Path $env:RUNNER_TEMP ('wela-ipsec-'+[guid]::NewGuid().ToString('N'))
$null=New-Item $root -ItemType Directory
$name='wela-ipsec-'+[guid]::NewGuid().ToString('N')
$guid='0CCE9218-69AE-11D9-BED3-505054503030'
$before=Get-WelaEffectiveAuditPolicy
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$precedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
$beforeRules=@(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop|Select-Object Name,Enabled,InboundSecurity,OutboundSecurity,PrimaryStatus|Sort-Object Name|ConvertTo-Json -Depth 5 -Compress)
$engine=(Get-Process -Id $PID).Path
$created=$false;$cleanup=$false
try {
    $baseline=Get-WelaIpsecPrerequisite
    $baseline|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'baseline.json') -Encoding UTF8
    Assert ($baseline.Status -ne 'Unknown') "both native sources are readable: $($baseline.Diagnostic)"
    # Both endpoints are documentation-only addresses; no packets or negotiations are generated.
    $null=New-NetIPsecRule -Name $name -DisplayName $name -PolicyStore PersistentStore -Enabled False -LocalAddress 192.0.2.250 -RemoteAddress 192.0.2.251 -InboundSecurity Request -OutboundSecurity Request -ErrorAction Stop
    $created=$true
    $evidence=Get-WelaIpsecPrerequisite
    $evidence|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'disabled.json') -Encoding UTF8
    Get-NetIPsecRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop|Select-Object *|Export-Clixml (Join-Path $root 'disabled-native.xml')
    Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop|Select-Object *|Export-Clixml (Join-Path $root 'disabled-active-native.xml')
    $owned=@($evidence.Rules|Where-Object Name -eq $name)
    Assert ((Get-NetIPsecRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop).Enabled -eq 'False') 'owned persistent rule is actually disabled'
    Assert ($evidence.Status -ne 'Unknown' -and @($owned|Where-Object Qualifies).Count -eq 0) "disabled rule does not qualify (ActiveStore may omit it): $($evidence.Diagnostic)"
    Set-NetIPsecRule -Name $name -PolicyStore PersistentStore -Enabled True -InboundSecurity None -OutboundSecurity None -ErrorAction Stop
    $evidence=Get-WelaIpsecPrerequisite
    $owned=@($evidence.Rules|Where-Object Name -eq $name)
    $evidence|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'exemption.json') -Encoding UTF8
    Get-NetIPsecRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop|Select-Object *|Export-Clixml (Join-Path $root 'exemption-native.xml')
    Assert ($evidence.Status -ne 'Unknown' -and @($owned|Where-Object Qualifies).Count -eq 0) "real exemption-only rule does not qualify: $($evidence.Diagnostic)"
    Set-NetIPsecRule -Name $name -PolicyStore PersistentStore -InboundSecurity Request -OutboundSecurity Request -ErrorAction Stop
    $evidence=Get-WelaIpsecPrerequisite
    $evidence|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'positive.json') -Encoding UTF8
    Get-NetIPsecRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop|Select-Object *|Export-Clixml (Join-Path $root 'positive-native.xml')
    $owned=@($evidence.Rules|Where-Object Name -eq $name)
    Assert ($evidence.Status -eq 'Applicable' -and $owned.Count -eq 1 -and $owned[0].Qualifies) "real enabled securing ActiveStore rule establishes scoped applicability: $($evidence.Diagnostic)"
    $planPath=Join-Path $root 'plan.json'
    & $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') plan -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -SaclMode Skip -PlanPath $planPath
    Assert ($LASTEXITCODE -eq 0) 'public live plan succeeds'
    $plan=Get-Content $planPath -Raw|ConvertFrom-Json
    $row=@($plan.policies|Where-Object id -eq 'IPsec Main Mode')[0]
    Assert ($row.conditionalPrerequisite.Status -eq 'Applicable' -and $row.targetMask -eq 3) 'public plan contains native evidence and selected SF mask'
    $dryPath=Join-Path $root 'dry.json'
    & $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') configure -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -SaclMode Skip -DryRun -Auto -ResultsPath $dryPath
    Assert ($LASTEXITCODE -eq 0) 'public configure dry-run succeeds'
    $current=Get-WelaEffectiveAuditPolicy
    Assert (@($before.Keys|Where-Object {$before[$_] -ne $current[$_]}).Count -eq 0) 'dry-run preserves all59 effective masks'
    $dry=Get-Content $dryPath -Raw|ConvertFrom-Json
    $row=@($dry.Results|Where-Object Id -eq 'AuditPolicy/IPsec Main Mode')[0]
    Assert ($row.PrerequisiteObservations.Count -ge 2 -and $row.Status -in @('Skipped','AlreadyCompliant')) 'public dry-run retains native prerequisite evidence'

    # Actual public configure must produce a write for this control, then read it back.
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 0 -Mode exact
    $resultPath=Join-Path $root 'configure.json'
    & $engine -NoProfile -File (Join-Path $repo 'WELA.ps1') configure -Profile microsoft-stronger-reviewed-2026-09 -IncludeOptional -SaclMode Skip -Auto -BackupPath (Join-Path $root 'backup') -ResultsPath $resultPath
    Assert ($LASTEXITCODE -eq 0) 'actual public configure succeeds'
    $result=Get-Content $resultPath -Raw|ConvertFrom-Json
    $row=@($result.Results|Where-Object Id -eq 'AuditPolicy/IPsec Main Mode')[0]
    Assert ($row.Status -eq 'Applied' -and $row.After -eq 3 -and $row.PrerequisiteObservations.Count -eq 5) 'actual gated policy write retains all five native observations'
    Assert (@($row.PrerequisiteObservations|Where-Object Status -ne Applicable).Count -eq 0) 'every configure boundary has positive native evidence'
    $journal=@(Get-Content (Join-Path $root 'backup/before.jsonl')|ConvertFrom-Json)
    Assert (@($journal|Where-Object {$_.Id -eq 'AuditPolicy/IPsec Main Mode' -and $_.Before -eq 0 -and $_.Desired.Mask -eq 3}).Count -eq 1) 'real public recovery journal retains exact policy transition'

    # Native drift after prompt: exercise the real configuration callback and native reader.
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 0 -Mode exact
    $plan.policies=@($plan.policies|Where-Object id -eq 'IPsec Main Mode')
    function Read-Host {param($Prompt) Remove-NetIPsecRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop; $script:created=$false; 'y'}
    $ctx=New-WelaConfigurationContext -BackupPath (Join-Path $root 'drift-backup')
    Set-WelaProfileAuditControls $ctx $plan
    $drift=Complete-WelaConfiguration $ctx -Plan $plan -ResultsPath (Join-Path $root 'drift.json')
    $row=@($drift.Results|Where-Object Id -eq 'AuditPolicy/IPsec Main Mode')[0]
    if($baseline.Status -eq 'NotObservedWithinScope') {
        Assert ($row.Status -eq 'Failed' -and (Get-WelaEffectiveAuditPolicy)[$guid] -eq 0) 'real rule disappearance after prompt blocks auditpol write'
    } else {
        Assert ($row.Status -eq 'Applied') 'independent baseline prerequisite remains applicable after owned-rule removal'
    }
} finally {
    if($created){Remove-NetIPsecRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop}
    foreach($id in $before.Keys){Set-WelaEffectiveAuditPolicy -Guid $id -Mask $before[$id] -Mode exact}
    if($precedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type $precedence.Type -Value $precedence.Value -ErrorAction Stop}
    else {Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue}
    $after=Get-WelaEffectiveAuditPolicy
    Assert (@($before.Keys|Where-Object {$before[$_] -ne $after[$_]}).Count -eq 0) 'all59 original masks restored'
    $afterPrecedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
    Assert (($precedence|ConvertTo-Json -Compress) -ceq ($afterPrecedence|ConvertTo-Json -Compress)) 'typed precedence/absence restored'
    $afterRules=@(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop|Select-Object Name,Enabled,InboundSecurity,OutboundSecurity,PrimaryStatus|Sort-Object Name|ConvertTo-Json -Depth 5 -Compress)
    Assert (($beforeRules -join '') -ceq ($afterRules -join '')) 'native rule inventory restored exactly'
    $cleanup=$true
    [pscustomobject]@{CleanupVerified=$cleanup;Checks=$script:checks;Engine=$PSVersionTable.PSVersion.ToString();Computer=$env:COMPUTERNAME;NoTrafficGenerated=$true}|ConvertTo-Json|Set-Content (Join-Path $root 'cleanup.json') -Encoding UTF8
}
Write-Host "Passed $script:checks native IPsec checks; artifacts: $root"
