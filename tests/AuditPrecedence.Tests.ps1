# Mocked registry/audit policy; no Windows policy changes.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/Configuration.ps1')
$script:assertions = 0
$script:paths = @()
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
function Reset-Fixture($Value = 0, $Type = 'DWord') {
    $script:value = $Value; $script:type = $Type; $script:writes = 0; $script:auditWrites = 0
    $script:readFails = $false; $script:writeFails = $false; $script:ignoreWrite = $false
    $script:rsop = @(); $script:mask = 0; $script:response = 'Y'; $script:flipOnPrompt = $false
}
function Get-WelaRegistryState {
    param($Path, $Name)
    if ($Name -ne 'SCENoApplyLegacyAuditPolicy') { throw 'Unexpected registry read' }
    if ($script:readFails) { throw 'Injected access denied' }
    [pscustomobject]@{ KeyExists = $true; ValueExists = ($null -ne $script:value); Value = $script:value; Type = $script:type }
}
function New-WelaRegistryKey { param($Path) }
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    if ($Name -ne 'SCENoApplyLegacyAuditPolicy' -or $Type -ne 'DWord') { throw 'Unexpected registry write' }
    if ($script:writeFails) { throw 'Injected write denied' }
    $script:writes++
    if (-not $script:ignoreWrite) { $script:value = $Value; $script:type = $Type }
}
function Get-CimInstance { param($Namespace, $ClassName, $ErrorAction) if ($ClassName -eq 'RSOP_SecuritySettingNumeric') { return $script:rsop } }
function Get-WelaNativeAuditPolicy { param($Guid) return $script:mask }
function Invoke-WelaNative {
    param($FilePath, $Arguments)
    if ($script:value -ne 1 -or $script:type -ne 'DWord') { throw 'Audit write without verified prerequisite' }
    $script:auditWrites++; $script:mask = 1
    [pscustomobject]@{ Diagnostic = 'mock auditpol success' }
}
function Read-Host { param($Prompt) if ($script:flipOnPrompt) { $script:value = 0 }; return $script:response }
function New-TestContext([switch]$DryRun, [switch]$Interactive) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-precedence-' + [guid]::NewGuid().ToString('N'))
    $script:paths += $path
    New-WelaConfigurationContext -Auto:(-not $Interactive) -DryRun:$DryRun -BackupPath $path
}
$plan = [pscustomobject]@{
    profile = 'fixture'; version = '1'; schemaSha256 = 'fixture'; role = 'Client'; build = 26100; includeOptional = $false
    policies = @([pscustomobject]@{ id = 'Process Creation'; guid = '0CCE922B-69AE-11D9-BED3-505054503030'; mode = 'minimum'; requiredMask = 1; prerequisites = ''; evidence = 'fixture'; sourceIds = @('fixture'); note = '' })
}
try {
    foreach ($initial in @($null, 0, 42, '1')) {
        Reset-Fixture $initial $(if ($initial -is [string]) { 'String' } else { 'DWord' })
        $ctx = New-TestContext
        Set-WelaProfileAuditControls -Context $ctx -Plan $plan
        $report = Complete-WelaConfiguration $ctx
        Assert ($report.ExitCode -eq 0 -and $script:writes -eq 1 -and $script:auditWrites -eq 1) 'Precedence repair precedes subcategory writes'
        $journal = @(Get-Content (Join-Path $ctx.BackupPath 'before.jsonl') | ConvertFrom-Json)
        Assert ($journal[0].Target.Name -eq 'SCENoApplyLegacyAuditPolicy' -and $journal[0].Before.Value -eq $initial) 'Journal retains the original value before policy writes'
        Assert ($script:type -eq 'DWord') 'Numeric strings are repaired as DWORD'
        Set-WelaProfileAuditControls -Context $ctx -Plan $plan
        Assert ($script:writes -eq 1 -and $script:auditWrites -eq 1) 'Verified rerun is idempotent'
    }
    Reset-Fixture
    $ctx = New-TestContext -DryRun
    Set-WelaProfileAuditControls -Context $ctx -Plan $plan
    Assert ($script:writes -eq 0 -and $script:auditWrites -eq 0 -and -not (Test-Path $ctx.BackupPath)) 'Dry-run changes nothing and creates no journal'
    Assert ($ctx.Results.Count -eq 2) 'Dry-run previews both prerequisite and policy'
    foreach ($failure in @('readFails','writeFails','ignoreWrite')) {
        Reset-Fixture
        Set-Variable -Name $failure -Value $true -Scope Script
        $ctx = New-TestContext
        Set-WelaProfileAuditControls -Context $ctx -Plan $plan
        $report = Complete-WelaConfiguration $ctx
        Assert ($report.ExitCode -eq 1 -and $script:auditWrites -eq 0) 'Failed prerequisite blocks dependent policy writes'
        Assert ($ctx.Results[1].Status -eq 'Skipped') 'Blocked dependent control remains explicit'
    }
    Reset-Fixture
    $script:response = 'n'; $ctx = New-TestContext -Interactive
    Set-WelaProfileAuditControls -Context $ctx -Plan $plan
    Assert ($script:writes -eq 0 -and $script:auditWrites -eq 0 -and $ctx.Results[1].Status -eq 'Skipped') 'Declined prerequisite does not allow downstream writes'
    Reset-Fixture 1
    $script:flipOnPrompt = $true; $ctx = New-TestContext -Interactive
    Set-WelaProfileAuditControls -Context $ctx -Plan $plan
    $report = Complete-WelaConfiguration $ctx
    Assert ($script:auditWrites -eq 0 -and $report.ExitCode -eq 1) 'Pre-write guard rejects precedence changed during confirmation'
    Assert ($ctx.Results[0].Status -eq 'Overridden') 'Final read-back detects precedence drift'
    Reset-Fixture 1
    $script:rsop = @([pscustomobject]@{ keyName = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'; GPOID = 'Test GPO'; value = 0; precedence = 1 })
    $state = Get-WelaAuditPrecedenceState
    Assert ($state.State -eq 'Enabled' -and $state.PolicySource.ConflictsWithRequiredValue) 'Observed value and conflicting last-applied GPO are distinct'
    Assert ($state.PolicySource.Description -match 'may be stale') 'RSoP does not claim current ownership'
    $script:rsop[0].value = [byte[]]@(1, 0, 0, 0)
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'Unrecognized RSoP encoding is not fabricated as conflict'
    $script:readFails = $true
    Assert ((Get-WelaAuditPrecedenceState).State -eq 'Unknown') 'Read errors remain unknown'
    Assert ((Get-WelaAuditPrecedenceState -Offline).Registry -eq $null) 'Offline plans never read live registry state'
    Reset-Fixture
    $ctx = New-TestContext
    Set-WelaProfileAuditControls -Context $ctx -Plan ([pscustomobject]@{ policies = @(); includeOptional = $false })
    Assert ($ctx.Results.Count -eq 0 -and $script:writes -eq 0) 'Empty profile does not change precedence'
    Write-Host "PASS: $script:assertions audit precedence assertions (mocked; no host changes)."
} finally {
    foreach ($path in $script:paths) { if (Test-Path $path) { Remove-Item $path -Recurse -Force } }
}
