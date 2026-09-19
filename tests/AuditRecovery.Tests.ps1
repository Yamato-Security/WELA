$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AuditRecovery.ps1')
$script:n=0
function Assert($Value,$Message) {if (-not $Value) {throw $Message};$script:n++}
function Throws($Action,$Pattern) {$message='';try {& $Action | Out-Null} catch {$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, received $message"}
function Get-WelaRecoveryHost {[pscustomobject][ordered]@{Computer='TEST';MachineGuid='11111111-1111-1111-1111-111111111111';ContextKey=$script:hostKey}}
$script:hostKey='test-context'
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-recovery-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$journal=Join-Path $root 'before.jsonl';$original=Join-Path $root 'original.json'
$id='AuditPolicy/Process Creation';$prec='Registry/HKLM:\SYSTEM\CurrentControlSet\Control\Lsa/SCENoApplyLegacyAuditPolicy'
$script:state=3;$script:writes=0;$script:failWrite=$false;$script:badReadback=$false
$script:precedence=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=1;Type='DWord'}
function Get-WelaRegistryState {$script:precedence}
function Get-WelaRecoveryCurrent {param($Control) if ($Control.Kind -eq 'AuditPolicy') {$script:state} else {$script:precedence}}
function Set-WelaRecoveryCurrent {param($Control) if ($script:failWrite) {throw 'Injected write failure'};$script:writes++;if ($script:badReadback) {return};if ($Control.Kind -eq 'AuditPolicy') {$script:state=$Control.RecoverTo} else {$script:precedence=$Control.RecoverTo}}
function Save-Fixture {
    param([switch]$WithPrecedence)
    $script:entry=[pscustomobject][ordered]@{Version=1;ComputerName='TEST';RecordedUtc=[datetime]::UtcNow.ToString('o');Id=$id;Kind='AuditPolicy';Target=[pscustomobject]@{Guid='0cce922b-69ae-11d9-bed3-505054503030'};Before=0;Desired=[pscustomobject]@{Mask=1;Mode='minimum'}}
    $script:final=[pscustomobject]@{Id=$entry.Id;Kind=$entry.Kind;Target=$entry.Target;Before=$entry.Before;Desired=$entry.Desired;After=3;Status='Applied';Diagnostic=''}
    $entries=@($entry);$rows=@($final)
    if ($WithPrecedence) {
        $prior=[pscustomobject]@{KeyExists=$true;ValueExists=$false;Value=$null;Type=$null}
        $pe=[pscustomobject]@{Version=1;ComputerName='TEST';RecordedUtc=[datetime]::UtcNow.ToString('o');Id=$prec;Kind='Registry';Target=[pscustomobject]@{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Name='SCENoApplyLegacyAuditPolicy'};Before=$prior;Desired=[pscustomobject]@{Value=1;Type='DWord'}}
        $entries=@($pe)+$entries
        $rows=@([pscustomobject]@{Id=$pe.Id;Kind=$pe.Kind;Target=$pe.Target;Before=$pe.Before;Desired=$pe.Desired;After=$script:precedence;Status='Applied'})+$rows
    }
    ($entries | ForEach-Object {$_ | ConvertTo-Json -Depth 20 -Compress}) | Set-Content -LiteralPath $journal -Encoding UTF8
    [pscustomobject]@{DryRun=$false;ExitCode=0;Results=$rows} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $original -Encoding UTF8
}
function New-PlanFile {
    param([string[]]$Ids=@($id))
    $destination=Join-Path $root ([guid]::NewGuid().ToString('N'))
    $result=Invoke-WelaAuditRecovery -JournalPath $journal -OriginalResultsPath $original -ControlId $Ids -OutputPath $destination
    Assert ($result.Status -eq 'Planned') 'Plan is read only.'
    Join-Path $destination 'plan.json'
}
try {
    for ($before=0;$before -le 3;$before++) {for ($desired=0;$desired -le 3;$desired++) {for ($after=0;$after -le 3;$after++) {
        if (($after -band $before) -eq $before -and ($after -band $desired) -eq $desired) {
            $target=Get-WelaRecoveryMaskTarget $before ([pscustomobject]@{Mask=$desired;Mode='minimum'}) $after
            Assert (($target -band $before) -eq $before) 'Minimum undo preserves every original bit.'
            $unrequested=$after -band (3 -bxor $desired)
            Assert (($target -band $unrequested) -eq $unrequested) 'Minimum undo preserves independent added bits.'
            Assert (($target -band ($desired -band (3 -bxor $before))) -eq 0) 'Minimum undo removes only requested additions.'
        } else {Throws {Get-WelaRecoveryMaskTarget $before ([pscustomobject]@{Mask=$desired;Mode='minimum'}) $after} 'inconsistent'}
        Assert ((Get-WelaRecoveryMaskTarget $before ([pscustomobject]@{Mask=$desired;Mode='exact'}) $desired) -eq $before) 'Exact undo returns original mask.'
    }}}
    Throws {Get-WelaRecoveryMaskTarget '0' ([pscustomobject]@{Mask=1;Mode='exact'}) 1} 'integer'
    Throws {ConvertFrom-WelaRecoveryJson '{"Id":1,"i\u0064":2}'} 'Duplicate'
    Throws {ConvertFrom-WelaRecoveryJson '{"Id":1,}'} 'strict JSON'
    Save-Fixture
    $planFile=New-PlanFile
    $dry=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -DryRun -Auto
    Assert ($dry.Status -eq 'DryRun' -and $writes -eq 0 -and $dry.Results[0].Status -eq 'WouldRestore') 'DryRun writes nothing.'
    $script:state=1
    $drift=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'drift') -Auto
    Assert ($drift.ExitCode -eq 1 -and $writes -eq 0 -and $drift.Results[0].Diagnostic -match 'drift') 'Intervening change refuses restoration.'
    $script:state=3
    $ok=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'restored') -Auto
    Assert ($ok.ExitCode -eq 0 -and $state -eq 2 -and $writes -eq 1) 'Actual restore preserves independent Failure auditing.'
    Assert (Test-Path -LiteralPath (Join-Path $root 'restored/001-before.json')) 'Durable pre-write receipt exists.'
    $again=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'again') -Auto
    Assert ($again.Results[0].Status -eq 'AlreadyRecovered' -and $writes -eq 1) 'Recovery is idempotent.'
    Throws {Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'again') -Auto} 'new local'
    $script:hostKey='drift';Throws {Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -DryRun} 'host changed';$script:hostKey='test-context'
    Add-Content -LiteralPath $journal -Value ' '
    Throws {Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -DryRun} 'evidence changed'
    Save-Fixture
    $entry.ComputerName='OTHER';$entry | ConvertTo-Json -Depth 20 -Compress | Set-Content $journal
    Throws {New-WelaRecoveryPlan $journal $original @($id)} 'wrong-host'
    Save-Fixture
    $final.Status='Failed';[pscustomobject]@{DryRun=$false;Results=@($final)} | ConvertTo-Json -Depth 20 | Set-Content $original
    Throws {New-WelaRecoveryPlan $journal $original @($id)} 'Applied'
    Save-Fixture
    $entry.Target.Guid='0cce922c-69ae-11d9-bed3-505054503030';$entry | ConvertTo-Json -Depth 20 -Compress | Set-Content $journal
    Throws {New-WelaRecoveryPlan $journal $original @($id)} 'mismatch'
    Save-Fixture -WithPrecedence
    Throws {New-WelaRecoveryPlan $journal $original @($prec)} 'every journaled'
    $planFile=New-PlanFile @($id,$prec)
    $script:state=3;$script:failWrite=$true
    $failed=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'failed') -Auto
    Assert ($failed.ExitCode -eq 1 -and $failed.Results[1].Diagnostic -match 'blocked' -and $precedence.Value -eq 1) 'Failed mask recovery blocks precedence restoration.'
    $script:failWrite=$false;$script:badReadback=$true
    $failed=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'readback') -Auto
    Assert ($failed.ExitCode -eq 1 -and $failed.Results[0].Diagnostic -match 'readback') 'Ineffective write is a failure.'
    $script:badReadback=$false
    $ok=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -OutputPath (Join-Path $root 'ordered') -Auto
    Assert ($ok.ExitCode -eq 0 -and $state -eq 2 -and -not $precedence.ValueExists) 'Precedence absence restores only after masks.'
    $payload=Get-WelaRecoveryFile $planFile
    $tampered=ConvertFrom-WelaRecoveryJson $payload.Text;$tampered.Controls[0].RecoverTo=0
    $tampered | ConvertTo-Json -Depth 24 | Set-Content $planFile
    Throws {Invoke-WelaAuditRecovery -Action Restore -PlanPath $planFile -DryRun} 'independently rebuilt'
    $ps=(Get-Process -Id $PID).Path
    $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    $output=& $ps -NoProfile -File (Join-Path $repo 'WELA.ps1') configure -RecoveryAction Restore 2>&1;$code=$LASTEXITCODE
    $ErrorActionPreference=$old
    Assert ($code -ne 0 -and ($output -join ' ') -match 'require audit-recovery') 'Recovery options cannot dispatch unrelated configuration.'
    Push-Location $root
    try {Save-Fixture;$script:precedence=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=1;Type='DWord'};$script:state=3;$null=Invoke-WelaAuditRecovery -JournalPath ./before.jsonl -OriginalResultsPath ./original.json -ControlId $id -OutputPath ./relative;Assert (Test-Path ./relative/plan.json) 'Relative paths follow PowerShell location.'} finally {Pop-Location}
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
$global:LASTEXITCODE=0
Write-Host "Audit recovery: $script:n assertions passed."
