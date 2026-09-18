# Mocked registry/audit policy; no Windows policy changes.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/Configuration.ps1')
$script:assertions = 0
$script:paths = @()
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++ }
function Reset-Fixture($Value = 0, $Type = 'DWord') {
    $script:value = $Value; $script:type = $Type; $script:writes = 0; $script:auditWrites = 0
    $script:readFails = $false; $script:writeFails = $false; $script:ignoreWrite = $false
    $script:rsop = @{}; $script:mask = 0; $script:response = 'Y'; $script:flipOnPrompt = $false
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
function Get-CimInstance { param($Namespace, $ClassName, $ErrorAction) if ($script:rsop.ContainsKey($ClassName)) { return $script:rsop[$ClassName] } }
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
    $script:rsop['RSOP_SecuritySettingNumeric'] = @([pscustomobject]@{ KeyName = 'SCENoApplyLegacyAuditPolicy'; GPOID = 'Numeric GPO'; Setting = [uint32]0; precedence = [uint32]1 })
    $state = Get-WelaAuditPrecedenceState
    Assert ($state.State -eq 'Enabled' -and $state.PolicySource.ConflictsWithRequiredValue -and $state.PolicySource.ReportedValue -eq 0) 'Observed registry and documented Numeric Setting conflict are distinct'
    Assert ($state.PolicySource.Description -match 'may be stale') 'RSoP does not claim current ownership'
    $script:rsop['RSOP_SecuritySettingNumeric'][0].Setting = '1'
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'Malformed numeric Setting strings are not coerced'

    # Microsoft documents registryKey/valueName/value/valueType for ADM registry
    # policies, and Path/Type/Data for security-option registry values. Keep these
    # fixtures schema-faithful so a shared fictional keyName/value cannot pass.
    foreach ($value in @(0, 1)) {
        $script:rsop = @{}
        $script:rsop['RSOP_RegistryPolicySetting'] = @([pscustomobject]@{
            registryKey = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; valueName = 'SCENoApplyLegacyAuditPolicy'
            valueType = [uint32]4; value = [byte[]]@($value, 0, 0, 0); deleted = $false; GPOID = 'Registry GPO'; precedence = [uint32]1
        })
        $source = Get-WelaAuditPrecedenceSource
        Assert ($source.GpoId -eq 'Registry GPO' -and $source.SourceClass -eq 'RSOP_RegistryPolicySetting') 'Documented registryKey resolves the matching ADM policy GPO'
        Assert ($source.ReportedValue -eq $value -and $source.ConflictsWithRequiredValue -eq ($value -eq 0)) 'Four-byte little-endian DWORD RSoP data is decoded cautiously'
        $script:rsop = @{}
        $script:rsop['RSOP_RegistryValue'] = @([pscustomobject]@{
            Path = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'
            Type = [uint32]4; Data = [string]$value; GPOID = 'Security option GPO'; precedence = [uint32]1
        })
        $source = Get-WelaAuditPrecedenceSource
        Assert ($source.GpoId -eq 'Security option GPO' -and $source.SourceClass -eq 'RSOP_RegistryValue') 'Security-option Path resolves the matching RSoP GPO'
        Assert ($source.ReportedValue -eq $value -and $source.ConflictsWithRequiredValue -eq ($value -eq 0)) 'Canonical DWORD Data string is decoded without inventing other encodings'
    }
    foreach ($data in @('01', '0x00000001', ' 1', '4,1')) {
        $script:rsop['RSOP_RegistryValue'][0].Data = $data
        $source = Get-WelaAuditPrecedenceSource
        Assert ($null -eq $source.ConflictsWithRequiredValue -and $source.ReportedValue -ceq $data -and $source.GpoId -eq 'Security option GPO') 'Unknown Data encoding retains source/raw evidence without a fabricated conflict'
    }
    $script:rsop['RSOP_RegistryValue'][0].Data = '0'; $script:rsop['RSOP_RegistryValue'][0].Type = [uint32]1
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'REG_SZ zero is not treated as a DWORD precedence setting'
    $script:rsop['RSOP_RegistryValue'][0].Type = '4'
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'Malformed Type strings remain unknown'
    $script:rsop = @{}
    $registry = [pscustomobject]@{
        registryKey = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; valueName = 'SCENoApplyLegacyAuditPolicy'
        valueType = [uint32]4; value = [byte[]]@(1); deleted = $false; GPOID = 'Registry GPO'; precedence = [uint32]1
    }
    $script:rsop['RSOP_RegistryPolicySetting'] = @($registry)
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'A short DWORD byte array is unknown'
    $registry.value = [byte[]]@(1, 0, 0, 0, 0)
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'An oversized DWORD byte array is unknown'
    $registry.value = [byte[]]@(1, 0, 0, 0); $registry.valueType = [uint32]3
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'Binary data is not decoded as DWORD even if four bytes long'
    $registry.valueType = '4'
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).ConflictsWithRequiredValue) 'Malformed valueType strings remain unknown'
    $registry.valueType = [uint32]4; $registry.deleted = $true
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).GpoId) 'Deleted registry policy entries do not masquerade as active settings'
    $registry.deleted = $false; $registry.registryKey = 'HKCU\SYSTEM\CurrentControlSet\Control\Lsa'
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).GpoId) 'A same-name user-hive key is not mistaken for the machine security option'
    $registry.registryKey = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'; $registry.valueName = 'OtherValue'
    Assert ($null -eq (Get-WelaAuditPrecedenceSource).GpoId) 'A registry key sharing the policy name does not substitute for the exact value path'
    $registry.valueName = 'SCENoApplyLegacyAuditPolicy'
    $registry.registryKey = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; $registry.precedence = [uint32]2
    $winner = $registry.PSObject.Copy(); $winner.precedence = [uint32]1; $winner.GPOID = 'Higher precedence GPO'; $winner.value = [byte[]]@(0, 0, 0, 0)
    $script:rsop['RSOP_RegistryPolicySetting'] = @($registry, $winner)
    $source = Get-WelaAuditPrecedenceSource
    Assert ($source.GpoId -eq 'Higher precedence GPO' -and $source.ConflictsWithRequiredValue -and $source.Matches.Count -eq 2) 'Lower precedence number is selected while all matching evidence remains available'
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
