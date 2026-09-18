# Safe unit regressions: load only function definitions, never dispatch WELA or touch Windows policy.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '../WELA.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($functionName in @('Get-WelaOutgoingNtlmPolicySource', 'Get-WelaOutgoingNtlmState', 'Set-WelaOutgoingNtlmPolicy')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
    if (-not $definition) { throw "Missing function $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
    $script:assertions++
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-Equal $threw $true $Message
}
function Reset-Policy($Value) {
    $script:value = $Value
    $script:keyExists = $true
    $script:writes = 0
    $script:prompts = 0
    $script:readFails = $false
    $script:writeFails = $false
    $script:ignoreWrite = $false
    $script:response = 'Y'
    $script:rsop = @()
}
function Test-Path { param($LiteralPath, $ErrorAction) return $script:keyExists }
function Get-ItemProperty {
    param($LiteralPath, $ErrorAction)
    if ($script:readFails) { throw 'Access denied' }
    if ($null -eq $script:value) { return [pscustomobject]@{} }
    return [pscustomobject]@{ RestrictSendingNTLMTraffic = $script:value }
}
function New-Item { param($Path, [switch]$Force, $ErrorAction) $script:keyExists = $true }
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    if ($script:writeFails) { throw 'Access denied' }
    $script:writes++
    if (-not $script:ignoreWrite) { $script:value = $Value }
}
function Get-CimInstance { param($Namespace, $ClassName, $ErrorAction) if ($ClassName -eq 'RSOP_RegistryPolicySetting') { return $script:rsop } }
function Read-Host { param($Prompt) $script:prompts++; return $script:response }

$script:assertions = 0
foreach ($initial in @($null, 0, 1)) {
    Reset-Policy $initial
    Set-WelaOutgoingNtlmPolicy -Auto
    Assert-Equal $script:value 1 "Default audits initial value '$initial'"
    $expectedWrites = if ($initial -eq 1) { 0 } else { 1 }
    Assert-Equal $script:writes $expectedWrites 'Already audited hosts are idempotent'
}
Reset-Policy $null
$script:keyExists = $false
Set-WelaOutgoingNtlmPolicy -Auto
Assert-Equal $script:keyExists $true 'Missing key is created'
Assert-Equal $script:value 1 'Missing key gets audit mode'
Reset-Policy 2
Set-WelaOutgoingNtlmPolicy -Auto
Assert-Equal $script:value 2 'Auto preserves intentional deny'
Assert-Equal $script:writes 0 'Auto does not rewrite deny'
Assert-Equal ((Get-WelaOutgoingNtlmState).Description -like 'Deny all*authentication restriction*') $true 'Deny is reported as enforcement'
Set-WelaOutgoingNtlmPolicy -Mode Audit -Auto
Assert-Equal $script:value 1 'Explicit Audit may replace deny'
Set-WelaOutgoingNtlmPolicy -Mode Deny -Auto
Assert-Equal $script:value 2 'Only explicit Deny opts into enforcement'
Reset-Policy 42
Set-WelaOutgoingNtlmPolicy -Auto
Assert-Equal $script:writes 0 'Unknown value is preserved'
Assert-Equal ((Get-WelaOutgoingNtlmState).Description) 'Unknown registry value (42)' 'Unknown values are reported honestly'
Reset-Policy 0
$script:readFails = $true
Assert-Throws { Set-WelaOutgoingNtlmPolicy -Auto } 'Unreadable policy fails visibly'
Assert-Equal $script:writes 0 'Unreadable policy is never overwritten'
Reset-Policy 0
Set-WelaOutgoingNtlmPolicy -WhatIf
Assert-Equal $script:writes 0 'WhatIf does not mutate policy'
Assert-Equal $script:prompts 0 'WhatIf does not prompt without Auto'
Reset-Policy 2
$script:response = 'n'
Set-WelaOutgoingNtlmPolicy -Mode Audit
Assert-Equal $script:writes 0 'Declining preserves deny'
$script:response = ''
Set-WelaOutgoingNtlmPolicy -Mode Audit
Assert-Equal $script:value 1 'Confirmed explicit override succeeds'
Reset-Policy 0
$script:writeFails = $true
Assert-Throws { Set-WelaOutgoingNtlmPolicy -Auto } 'Write failure propagates'
Reset-Policy 0
$script:ignoreWrite = $true
Assert-Throws { Set-WelaOutgoingNtlmPolicy -Auto } 'Read-back mismatch propagates'
Reset-Policy 0
Assert-Equal ((Get-WelaOutgoingNtlmState).PolicySource -like 'Unknown*') $true 'No RSoP does not imply local provenance'
$script:rsop = @(
    [pscustomobject]@{ keyName = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; valueName = 'RestrictSendingNTLMTraffic'; precedence = 2; GPOID = 'Lower priority GPO' },
    [pscustomobject]@{ keyName = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; valueName = 'RestrictSendingNTLMTraffic'; precedence = 1; GPOID = 'Winning GPO' },
    [pscustomobject]@{ keyName = 'SYSTEM\Other'; valueName = 'RestrictSendingNTLMTraffic'; precedence = 0; GPOID = 'Unrelated GPO' }
)
$source = (Get-WelaOutgoingNtlmState).PolicySource
Assert-Equal ($source -like 'Last-applied RSoP GPO: Winning GPO*may be stale*') $true 'Matching RSoP priority and freshness limits are reported'
Write-Host "PASS: $script:assertions outgoing NTLM assertions (mocked; no host changes)."
