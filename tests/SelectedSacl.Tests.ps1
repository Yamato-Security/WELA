$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/TargetedSaclPlanning.ps1')
. (Join-Path $root 'scripts/SelectedSaclConfiguration.ps1')
$script:count=0
function Assert($Condition,$Message){if(-not $Condition){throw $Message};$script:count++}
function Throws($Action,$Pattern){$message='';try{& $Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function Clone($Value){$Value|ConvertTo-Json -Depth 24|ConvertFrom-Json}
$script:hostKey='fixture-host';$script:contextReads=0
function Get-WelaSelectedSaclContext {$script:contextReads++;[pscustomobject]@{Computer='fixture';Role='Client';Build=26100;Detail=[pscustomobject]@{UBR=1};Key=$script:hostKey}}
$script:policy=@{};foreach($row in (Import-WelaAuditProfiles).catalog){$script:policy[$row.guid]=3}
function Get-WelaEffectiveAuditPolicy {$script:policy}
$script:precedence=[pscustomobject]@{Registry=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1}}
function Get-WelaAuditPrecedenceState {$script:precedence}
function Get-WelaSaclUserInventory {[pscustomobject]@{Users=@();Diagnostics=@('Fixture has no loaded users.');Complete=$true}}
function Get-WelaSaclTargetObservation {throw 'Catalog must not read unselected objects.'}
$catalog=Get-WelaSelectedSaclCatalog -Profile wela-2.2.0 -IncludeOptional -Context (Get-WelaSelectedSaclContext)
Assert ($catalog.Rows.Count -eq 52) 'Shared definitions retain all50 companion targets plus2 separately identified WEF entries without unselected ACL reads.'
$reg=@($catalog.Rows|Where-Object {$_.Definition.Scope -eq 'registry'})[0]
$file=@($catalog.Rows|Where-Object {$_.Definition.Scope -eq 'files'})[0]
Assert ($reg.Definition.PrincipalSid -eq 'S-1-1-0' -and $reg.Definition.AuditFlags.Count -eq 2) 'WELA principal and audit outcomes retained.'
$wef=Get-WelaSelectedSaclCatalog -Profile microsoft-wef-reviewed-2026-09 -Context (Get-WelaSelectedSaclContext)
$wefRows=@($wef.Rows|Where-Object {$_.Definition.Origin -like 'Microsoft WEF*'})
Assert ($wefRows.Count -eq 2 -and $wefRows[0].Definition.PrincipalSid -eq 'S-1-5-11' -and $wefRows[0].Definition.AuditFlags.Count -eq 1 -and $wefRows[0].Id -ne $reg.Id) 'Exact WEF audit entries remain separate from WELA companion targets.'
$script:states=@{};$script:writes=0;$script:scenario='';$script:currentPlan='';$script:backup='';$script:sourceReader=(Get-Command Get-WelaSelectedSaclSources).ScriptBlock
function Reset-State {
    $script:hostKey='fixture-host';$script:writes=0;$script:scenario=''
    foreach($item in @($reg,$file)){
        $script:states[$item.Definition.Path]=[pscustomobject]@{SecurityInformation=511;DescriptorScope='WinSDK-defined sections 0x1ff; future sections unobserved';Path=$item.Definition.Path;Kind=$item.Definition.Kind;Identity=$item.Id;IsDirectory=$false;DescriptorBase64=('before-'+$item.Id);Owner='S-1-5-18';Group='S-1-5-18';DaclBase64='retained-dacl';ControlFlags=32788;Aces=@([pscustomobject]@{Binary='Aa==';Type=17;Flags=0;Mask=0;Sid=$null;Ordinary=$false})}
    }
}
function Get-WelaSelectedSaclSources {
    $sources=@(& $script:sourceReader)
    if($script:scenario -eq 'source-race' -and (Test-Path -LiteralPath $script:backup) -and @(Get-ChildItem -LiteralPath $script:backup -Filter '*.pending.json').Count){$sources[0].Sha256='0'*64}
    $sources
}
function Get-WelaSelectedSaclSnapshot {
    param($Definition)
    if(-not $script:states.ContainsKey($Definition.Path)){throw 'Fixture refuses reads of any unselected/broad target.'}
    if($script:scenario -eq 'read-denied'){throw 'Selected descriptor access denied'}
    Clone $script:states[$Definition.Path]
}
function Write-WelaSelectedSaclNative {
    param($Definition,$Before,$Ace)
    $script:writes++
    Assert (@(Get-ChildItem -LiteralPath $script:backup -Filter '*.pending.json').Count -ge 1) 'Durable pending receipt exists before native writer.'
    if($script:scenario -eq 'write-failure'){throw 'Native SACL write failure'}
    $after=Clone $Before
    $after.Aces+=@([pscustomobject]@{Binary='audit-added';Type=2;Flags=$Ace.Flags;Mask=$Ace.Mask;Sid=$Ace.Sid;Ordinary=$true})
    $after.DescriptorBase64='after-'+$Before.DescriptorBase64
    if($script:scenario -eq 'dacl-drift'){$after.DaclBase64='someone-else'}
    $script:states[$Definition.Path]=$after
    $after
}
function Read-Host {
    param($Prompt)
    if($script:scenario -eq 'decline'){return 'n'}
    if($script:scenario -eq 'prompt-race'){$script:states[$reg.Definition.Path].DescriptorBase64='concurrent'}
    if($script:scenario -eq 'plan-race'){[IO.File]::AppendAllText($script:currentPlan,[Environment]::NewLine)}
    'y'
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-selected-sacl-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
function New-Review {
    Reset-State
    $script:currentPlan=Join-Path $temp ([guid]::NewGuid().ToString('N')+'.json')
    $script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N'))
    Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -IncludeOptional -Ids $reg.Id -IncludeChildren -ResultsPath $script:currentPlan
}
function Apply-Review {
    param([switch]$DryRun,[switch]$Auto)
    Invoke-WelaSelectedSacl -Action Configure -PlanPath $script:currentPlan -Ids $reg.Id -IncludeOptional -IncludeChildren -BackupPath $script:backup -DryRun:$DryRun -Auto:$Auto
}
try {
    $plan=New-Review
    Assert ($plan.Rows.Count -eq 1 -and $plan.Rows[0].Status -eq 'ChangeRequired' -and $plan.UsableRuleCredit -eq 0 -and $script:writes -eq 0) 'Plan selects one real catalog definition and remains read-only/Conditional.'
    $report=Apply-Review -DryRun
    Assert ($script:writes -eq 0 -and -not(Test-Path $script:backup) -and $report.Results[0].Status -eq 'Skipped') 'DryRun does not write SACLs or recovery files.'
    $report=Apply-Review -Auto
    Assert ($report.ExitCode -eq 0 -and $report.Results[0].Status -eq 'Applied' -and $script:writes -eq 1) 'Selected writer applies and verifies exact requested ACE.'
    $receipt=Get-Content (Join-Path $script:backup ($reg.Id+'.confirmed.json')) -Raw|ConvertFrom-Json
    Assert ($receipt.State -eq 'Confirmed' -and $receipt.Before.Aces[0].Binary -ceq 'Aa==' -and $receipt.After.DaclBase64 -ceq 'retained-dacl') 'Confirmed receipt retains before/after unknown ACEs and access descriptor.'
    $secondPlan=Join-Path $temp 'idempotent.json'
    $null=Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -IncludeOptional -Ids $reg.Id -IncludeChildren -ResultsPath $secondPlan
    $report=Invoke-WelaSelectedSacl -Action Configure -PlanPath $secondPlan -Ids $reg.Id -IncludeOptional -IncludeChildren -BackupPath (Join-Path $temp 'idempotent-backup') -Auto
    Assert ($report.Results[0].Status -eq 'AlreadyCompliant' -and $script:writes -eq 1) 'Fresh reviewed re-run avoids duplicate ACE.'
    foreach($case in @('prompt-race','plan-race','source-race','decline')){
        $null=New-Review;$script:scenario=$case;$report=Apply-Review
        Assert ($script:writes -eq 0 -and $report.Results[0].Status -in @('Failed','Skipped')) "No write after $case."
        if($case -ne 'decline'){Assert ($report.ExitCode -eq 1) "$case produces nonzero result."}
    }
    foreach($case in @('write-failure','dacl-drift')){
        $null=New-Review;$script:scenario=$case;$report=Apply-Review -Auto
        Assert ($report.ExitCode -eq 1 -and -not(Test-Path (Join-Path $script:backup ($reg.Id+'.confirmed.json')))) "$case cannot create confirmed ownership receipt."
    }
    $null=New-Review;$script:states[$reg.Definition.Path].Identity='replaced'
    Throws {Apply-Review -Auto} 'preflight failed'
    Assert ($script:writes -eq 0 -and -not(Test-Path $script:backup)) 'Changed target identity fails entire preflight before recovery directory.'
    $null=New-Review;$script:scenario='read-denied'
    Throws {Apply-Review -Auto} 'access denied'
    Assert ($script:writes -eq 0) 'Denied selected descriptor is never treated as absent/empty.'
    $null=New-Review;$script:hostKey='other-host'
    Throws {Apply-Review -Auto} 'different actual host'
    $null=New-Review
    Throws {Invoke-WelaSelectedSacl -Action Configure -PlanPath $script:currentPlan -Ids $reg.Id -Auto -BackupPath $script:backup} 'consent'
    Throws {Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0} 'Explicit nonempty'
    Throws {Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -IncludeOptional -Ids @($reg.Id,$reg.Id)} 'duplicate'
    Throws {Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -IncludeOptional -Ids ('sacl-'+('0'*24))} 'Unknown/stale'
    $null=New-Review;$bad=Get-Content $script:currentPlan -Raw|ConvertFrom-Json;$bad.Rows[0].Definition.Path='HKLM:\malicious-unreviewed';$bad|ConvertTo-Json -Depth 24|Set-Content $script:currentPlan -Encoding UTF8
    $beforeReads=$script:contextReads;Throws {Apply-Review -Auto} 'definition was modified'
    Assert ($beforeReads -eq $script:contextReads) 'Tampered definition rejected before native context/target reads.'
    $null=New-Review;$bad=Get-Content $script:currentPlan -Raw|ConvertFrom-Json;$bad.Sources[0].Sha256='bad';$bad|ConvertTo-Json -Depth 24|Set-Content $script:currentPlan -Encoding UTF8
    $beforeReads=$script:contextReads;Throws {Apply-Review -Auto} 'source changed'
    Assert ($beforeReads -eq $script:contextReads) 'Source mismatch fails before native host inspection.'
    $null=New-Review;[IO.File]::WriteAllText($script:currentPlan,'{"SchemaVersion":1,"schemaVersion":1}')
    Throws {Read-WelaSelectedSaclPlan $script:currentPlan} 'Duplicate|colliding'
    Reset-State;$snapshot=Get-WelaSelectedSaclSnapshot $reg.Definition
    Throws {Get-WelaSelectedSaclAce $reg.Definition $snapshot} 'IncludeChildren'
    $incomplete=Clone $snapshot;$incomplete.SecurityInformation=31
    Throws {Get-WelaSelectedSaclSnapshotKey $incomplete} 'observation scope'
    $noInheritance=Clone $reg.Definition;$noInheritance.Inheritance='None'
    $existing=Clone $snapshot;$existing.Aces[0].Flags=66
    Throws {Get-WelaSelectedSaclAce $noInheritance $existing} 'existing SACL inheritance'
    $existingAce=Get-WelaSelectedSaclAce $noInheritance $existing -IncludeChildren
    Assert ($existingAce.Flags -eq 192 -and $existing.Aces[0].Flags -eq 66) 'Descendant consent covers existing unknown ACEs without changing source or existing inheritance flags.'
    $duplicate=@($catalog.Rows|Where-Object {$_.Definition.Path -eq $reg.Definition.Path -and $_.Id -ne $reg.Id})[0]
    Assert ($null -ne $duplicate) 'Real catalog has distinct source/principal entries for the same physical target.'
    $duplicatePlan=Join-Path $temp 'duplicate-target.json'
    $duplicateBackup=Join-Path $temp 'duplicate-target-backup'
    $blocked=Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -IncludeOptional -IncludeChildren -Ids @($reg.Id,$duplicate.Id) -ResultsPath $duplicatePlan
    Assert (@($blocked.Rows|Where-Object Status -eq 'Blocked').Count -eq 2) 'Duplicate physical target entries are blocked together in the reviewed plan.'
    Throws {Invoke-WelaSelectedSacl -Action Configure -PlanPath $duplicatePlan -IncludeOptional -IncludeChildren -Ids @($reg.Id,$duplicate.Id) -BackupPath $duplicateBackup -Auto} 'same target'
    Assert ($script:writes -eq 0 -and -not(Test-Path $duplicateBackup)) 'Duplicate source entries cannot produce a predictable partial apply.'
    $ace=Get-WelaSelectedSaclAce $reg.Definition $snapshot -IncludeChildren
    Assert ($ace.Mask -eq 65542 -and $ace.Flags -eq 194 -and $ace.RequiredPolicyMask -eq 3) 'Exact registry SetValue/CreateSubKey/Delete and success/failure/inheritance masks.'
    $wefAce=Get-WelaSelectedSaclAce $wefRows[0].Definition $snapshot -IncludeChildren
    Assert ($wefAce.Mask -eq 6 -and $wefAce.Flags -eq 66 -and $wefAce.RequiredPolicyMask -eq 1) 'WEF Run retains SetValue/CreateSubKey success, Authenticated Users and child inheritance.'
    $copy=Clone $snapshot;$copy.Aces+=@([pscustomobject]@{Binary='new';Type=2;Flags=194;Mask=65542;Sid='S-1-1-0';Ordinary=$true})
    Assert (Test-WelaSelectedSaclAce $copy $ace) 'Exact ordinary ACE matches.'
    $copy.Aces[1].Flags=210;Assert (-not(Test-WelaSelectedSaclAce $copy $ace)) 'Inherited ACE is preserved but never mistaken for explicit requested entry.'
    $copy.Aces[1].Flags=194;$copy.Aces[0].Binary='aa=='
    Throws {Assert-WelaSelectedSaclPreserved $snapshot $copy $ace} 'unknown ACE'
    foreach($kind in @('String','DWord')){
        $script:precedence.Registry.Type=$kind;$script:precedence.Registry.Value='1'
        Throws {Assert-WelaSelectedSaclPrerequisites $reg.Definition $ace} 'Typed audit precedence'
    }
    $script:precedence.Registry.Type='DWord';$script:precedence.Registry.Value=1
    $guid='0CCE921E-69AE-11D9-BED3-505054503030';$script:policy[$guid]=1
    Throws {Assert-WelaSelectedSaclPrerequisites $reg.Definition $ace} 'outcomes'
    $script:policy[$guid]=3
    $exe=(Get-Process -Id $PID).Path
    foreach($arguments in @(@('configure','-TargetSaclAction','Audit'),@('targeted-sacl','-Profile','wela-2.2.0'),@('targeted-sacl','-DryRun'))){
        $ErrorActionPreference='Continue';try{$output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
        $plain=($output -join ' ') -replace '\x1b\[[0-9;]*[A-Za-z]','' -replace '[|\r\n]',' '
        Assert ($code -ne 0 -and $plain -match 'No\s+command\s+was\s+run') 'Public guards refuse unrelated commands and ignored DryRun.'
    }
    Write-Host "PASS: $script:count selected-SACL mocked assertions. Native target reads/writes are replaced; no machine ACL or policy mutations."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
