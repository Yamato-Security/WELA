$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/AuditRecovery.ps1')
$script:n=0;$script:writes=0
function Assert($Value,$Message) {if (-not $Value) {throw $Message};$script:n++}
function Throws($Action,$Pattern) {$message='';try {& $Action | Out-Null} catch {$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, received $message"}
function Get-WelaRecoveryHost {[pscustomobject][ordered]@{Computer='TEST';MachineGuid='11111111-1111-1111-1111-111111111111';ContextKey='test'}}
function Get-WelaNamedRecoveryObservation {param($Target) $script:observation}
function Set-WelaNamedRecoveryValue {
    param($Control)
    Assert (Test-Path -LiteralPath (Join-Path $script:destination '001-before.json')) 'A durable receipt precedes mutation.'
    Assert-WelaNamedRecoveryGuard $Control $script:observation
    $script:writes++;$script:observation.Exists=$Control.RecoverTo.ValueExists;$script:observation.Value=$Control.RecoverTo.Value
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-named-recovery-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$journal=Join-Path $root 'before.jsonl';$original=Join-Path $root 'original.json'
function Save-Fixture($Definition,$Before) {
    $script:observation=[pscustomobject]@{Exists=$true;Value=1;ObjectName=('\REGISTRY\MACHINE\'+$Definition.Path.Substring(6));OtherValues='other';Children='children';Security='security';LastWrite='42'}
    $script:entry=[pscustomobject]@{Version=1;ComputerName='TEST';RecordedUtc=[datetime]::UtcNow.ToString('o');Id=$Definition.Id;Kind='Registry';Target=[pscustomobject]@{Path=$Definition.Path;Name=$Definition.Name};Before=$Before;Desired=[pscustomobject]@{Value=1;Type='DWord'}}
    $script:final=[pscustomobject]@{Id=$entry.Id;Kind='Registry';Target=$entry.Target;Before=$Before;Desired=$entry.Desired;After=(Get-WelaNamedRecoveryState $observation);Status='Applied'}
    Save-Evidence
}
function Save-Evidence {
    $entry | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $journal -Encoding UTF8
    [pscustomobject]@{DryRun=$false;Results=@($final)} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $original -Encoding UTF8
}
try {
    $catalog=@(Get-WelaNamedRecoveryCatalog)
    Assert ($catalog.Count -eq 3) 'Only three fixed logging switches are admitted.'
    foreach ($definition in $catalog) {
        foreach ($before in @(
            [pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=0;Type='DWord'},
            [pscustomobject]@{KeyExists=$true;ValueExists=$false;Value=$null;Type=$null},
            [pscustomobject]@{KeyExists=$false;ValueExists=$false;Value=$null;Type=$null}
        )) {
            Save-Fixture $definition $before
            $count=$writes
            $planned=Invoke-WelaAuditRecovery -JournalPath $journal -OriginalResultsPath $original -ControlId $definition.Id -OutputPath (Join-Path $root ([guid]::NewGuid().ToString('N')))
            $planPath=Join-Path $planned.OutputPath 'plan.json'
            Assert ($writes -eq $count -and $planned.Status -eq 'Planned') 'Planning does not mutate registry.'
            $plan=ConvertFrom-WelaRecoveryJson (Get-WelaRecoveryFile $planPath).Text
            Assert ($plan.Controls[0].Kind -eq 'NamedLoggingRegistry' -and $plan.Controls[0].RecoverTo.KeyExists -and $plan.Controls[0].OriginalKeyExisted -eq $before.KeyExists) 'Value-only recovery retains keys and reports original absence.'
            $dry=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -DryRun
            Assert ($dry.Results[0].Status -eq 'WouldRestore' -and $writes -eq $count) 'Dry-run has no mutation.'
            foreach ($field in @('ObjectName','OtherValues','Children','Security')) {
                $old=$observation.$field;$observation.$field='changed'
                Throws {Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -DryRun} 'independently rebuilt'
                $observation.$field=$old
            }
            $script:destination=Join-Path $root ([guid]::NewGuid().ToString('N'))
            $result=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -OutputPath $destination -Auto
            Assert ($result.ExitCode -eq 0 -and $result.Results[0].Status -eq 'Restored' -and $writes -eq $count+1 -and $result.ReadyRuleCredit -eq 0) 'Selected typed value restores without readiness credit.'
            $script:destination=Join-Path $root ([guid]::NewGuid().ToString('N'))
            $again=Invoke-WelaAuditRecovery -Action Restore -PlanPath $planPath -OutputPath $destination -Auto
            Assert ($again.Results[0].Status -eq 'AlreadyRecovered' -and $writes -eq $count+1) 'Observation of restored value is idempotent.'
        }
    }
    $zero=[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=0;Type='DWord'}
    foreach ($invalid in @(
        [pscustomobject]@{KeyExists=$true;ValueExists=$true;Value='0';Type='DWord'},
        [pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=2;Type='DWord'},
        [pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=0;Type='QWord'},
        [pscustomobject]@{KeyExists=$false;ValueExists=$true;Value=0;Type='DWord'},
        [pscustomobject]@{KeyExists=$true;ValueExists=$false;Value=0;Type=$null}
    )) {Save-Fixture $catalog[0] $invalid;Throws {New-WelaRecoveryPlan $journal $original @($entry.Id)} 'Only prior|inconsistent'}
    Save-Fixture $catalog[0] $zero;$final.Status='Failed';Save-Evidence
    Throws {New-WelaRecoveryPlan $journal $original @($entry.Id)} 'Applied'
    Save-Fixture $catalog[0] $zero;$entry.Target.Path+='\Other';Save-Evidence
    Throws {New-WelaRecoveryPlan $journal $original @($entry.Id)} 'Unsupported'
    Save-Fixture $catalog[0] $zero;$entry.Desired.Value=$true;Save-Evidence
    Throws {New-WelaRecoveryPlan $journal $original @($entry.Id)} 'Unsupported'
    Save-Fixture $catalog[0] $zero;$plan=New-WelaRecoveryPlan $journal $original @($entry.Id);$plan.NamedSources[0].Sha256='bad'
    Throws {Assert-WelaRecoverySources $plan} 'implementation changed'
    Throws {Open-WelaNamedRecoveryKey ([pscustomobject]@{Path='HKLM:\SOFTWARE\Other';Name='Unknown'})} 'Unknown'
    Initialize-WelaNamedRecoveryNative
    Assert ([Wela.NamedRegistryRecovery.Key]::SourceSha256 -eq (Get-FileHash (Join-Path $repo 'scripts/NamedRegistryRecoveryNative.cs')).Hash.ToLowerInvariant()) 'Compiled native helper binds exact source bytes.'
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
$global:LASTEXITCODE=0
Write-Host "Named registry recovery: $script:n assertions passed."
