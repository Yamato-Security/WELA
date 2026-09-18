# Composed #362/#363/#365 behavior, using mock registry/CIM and temporary journals only.
$ErrorActionPreference = 'Stop'
# Keep mocks in the same script scope as dot-sourced helpers/imported commands;
# Windows PowerShell 5.1 resolves script-local originals ahead of global mocks.
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'WELA.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Get-WelaOutgoingNtlmPolicySource', 'Get-WelaOutgoingNtlmState', 'Set-WelaOutgoingNtlmPolicy', 'Get-WelaDomainNtlmState', 'Set-WelaDomainNtlmAudit')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($function.Extent.Text))
}
$script:assertions = 0
$script:contexts = New-Object 'System.Collections.Generic.List[object]'
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
function New-TestContext([switch]$DryRun) {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-integration-' + [guid]::NewGuid().ToString('N'))
    $context = New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath $path
    $script:contexts.Add($context)
    $script:currentContext = $context
    return $context
}
function Reset-Mocks($Outgoing = 0, $Domain = 2, $ProductType = 2) {
    $script:registry = @{ RestrictSendingNTLMTraffic = $Outgoing; AuditNTLMInDomain = $Domain }
    $script:productType = $ProductType
    $script:writes = 0; $script:readFails = $false; $script:writeFails = ''
    $script:roleFails = $false
}
function Get-CimInstance {
    param($ClassName, $Property, $Namespace, $ErrorAction)
    if ($ClassName -eq 'Win32_OperatingSystem') {
        if ($script:roleFails) { throw 'Mock role query failure' }
        return [pscustomobject]@{ ProductType = $script:productType }
    }
}
function Test-Path {
    param($LiteralPath, $Path, $ErrorAction)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -like 'HKLM:*') { return $true }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $target
}
function Get-ItemProperty {
    param($LiteralPath, $ErrorAction)
    if ($script:readFails) { throw 'Mock registry read failure' }
    return [pscustomobject]$script:registry
}
function Get-WelaRegistryState {
    param($Path, $Name)
    if ($script:readFails) { throw 'Mock registry read failure' }
    [pscustomobject]@{ KeyExists = $true; ValueExists = ($null -ne $script:registry[$Name]); Value = $script:registry[$Name]; Type = 'DWord' }
}
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    # Assert the actual mutation cannot run before its matching journal entry.
    $journal = Join-Path $script:currentContext.BackupPath 'before.jsonl'
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $journal)) { throw 'Mutation occurred before journal existed' }
    $entries = @(Get-Content -LiteralPath $journal | ConvertFrom-Json)
    if ($entries[-1].Target.Name -ne $Name) { throw 'Mutation occurred before its own journal entry' }
    if ($script:writeFails -eq $Name) { throw 'Mock NTLM write failure' }
    $script:writes++
    $script:registry[$Name] = $Value
}
try {
    Reset-Mocks
    $context = New-TestContext -DryRun
    Set-WelaOutgoingNtlmPolicy -Context $context
    Set-WelaDomainNtlmAudit -Context $context
    Assert ($script:writes -eq 0) 'Both NTLM controls honor shared DryRun'
    Assert ($context.Results.Count -eq 2 -and @($context.Results | Where-Object Status -ne Skipped).Count -eq 0) 'Both dry-run changes are reported as skipped'
    Assert (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $context.BackupPath)) 'NTLM dry run creates no journal or backup directory'

    Reset-Mocks 2
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context
    Assert ($script:writes -eq 0 -and $script:registry.RestrictSendingNTLMTraffic -eq 2) 'Context Auto preserves existing deny'
    Assert ($context.Results[0].Status -eq 'Skipped' -and $context.Results[0].Diagnostic -match 'Deny all enforcement') 'Preserved enforcement is explicit in results'

    Reset-Mocks 42
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Skipped') 'Unknown outgoing value is preserved and reported'

    Reset-Mocks
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context
    Set-WelaDomainNtlmAudit -Context $context
    $result = Complete-WelaConfiguration -Context $context
    Assert ($script:registry.RestrictSendingNTLMTraffic -eq 1 -and $script:registry.AuditNTLMInDomain -eq 7) 'Context applies audit-only outgoing and DC Enable all'
    Assert ($script:writes -eq 2 -and $result.ExitCode -eq 0) 'Both actual writes are verified successfully'
    $journal = @(Get-Content -LiteralPath (Join-Path $context.BackupPath 'before.jsonl') | ConvertFrom-Json)
    Assert ($journal.Count -eq 2 -and $journal[0].Before.Value -eq 0 -and $journal[1].Before.Value -eq 2) 'Journal records exact values before both NTLM changes'
    Assert ($journal[0].Before.Type -eq 'DWord' -and $journal[1].Desired.Value -eq 7) 'Journal retains registry type and requested domain value'
    Set-WelaOutgoingNtlmPolicy -Context $context
    Set-WelaDomainNtlmAudit -Context $context
    Assert ($script:writes -eq 2) 'Verified NTLM controls are idempotent'
    $script:registry.AuditNTLMInDomain = 0
    Assert ((Complete-WelaConfiguration $context).ExitCode -eq 1) 'Final verification aggregates later NTLM drift'

    Reset-Mocks 2
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context -Mode Audit
    Assert ($script:registry.RestrictSendingNTLMTraffic -eq 1) 'Explicit Audit override goes through shared journal and verification'
    Set-WelaOutgoingNtlmPolicy -Context $context -Mode Deny
    Assert ($script:registry.RestrictSendingNTLMTraffic -eq 2) 'Explicit Deny remains a separate operator choice'

    Reset-Mocks 0 2 3
    $context = New-TestContext
    Set-WelaDomainNtlmAudit -Context $context
    Assert ($script:writes -eq 0 -and $context.Results[0].Status -eq 'Skipped') 'Non-DC domain policy is skipped'
    Assert ($context.Results[0].Diagnostic -match 'Not applicable') 'Non-DC reason is explicit'

    Reset-Mocks
    $script:roleFails = $true
    $context = New-TestContext
    Set-WelaDomainNtlmAudit -Context $context
    Set-WelaOutgoingNtlmPolicy -Context $context
    $result = Complete-WelaConfiguration $context
    Assert ($result.ExitCode -eq 1 -and $result.Failed -eq 1) 'Unknown role produces an aggregated failure'
    Assert ($script:registry.RestrictSendingNTLMTraffic -eq 1) 'Other controls continue after unknown domain role'

    Reset-Mocks
    $script:readFails = $true
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context
    Set-WelaDomainNtlmAudit -Context $context
    $result = Complete-WelaConfiguration $context
    Assert ($result.ExitCode -eq 1 -and $result.Failed -eq 2 -and $script:writes -eq 0) 'Both unreadable NTLM states aggregate as failures with no writes'

    Reset-Mocks
    $script:writeFails = 'RestrictSendingNTLMTraffic'
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context
    Set-WelaDomainNtlmAudit -Context $context
    $result = Complete-WelaConfiguration $context
    Assert ($result.ExitCode -eq 1 -and $result.Failed -eq 1) 'NTLM write failure aggregates in final exit code'
    Assert ($script:registry.AuditNTLMInDomain -eq 7) 'A failed outgoing control does not prevent domain configuration'

    Reset-Mocks
    $context = New-TestContext
    Set-WelaOutgoingNtlmPolicy -Context $context -WhatIf
    Set-WelaDomainNtlmAudit -Context $context -WhatIf
    Assert ($script:writes -eq 0) 'Context adapters also preserve standalone WhatIf behavior'
    Write-Host "PASS: $script:assertions NTLM integration assertions (mocked; no Windows changes)."
} finally {
    foreach ($context in $script:contexts) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $context.BackupPath) {
            Remove-Item -LiteralPath $context.BackupPath -Recurse -Force
        }
    }
}
