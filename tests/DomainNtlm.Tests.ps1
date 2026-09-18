# Safe unit regressions: load function definitions without dispatching WELA or changing host policy.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($functionName in @('Get-WelaDomainNtlmState', 'Set-WelaDomainNtlmAudit')) {
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
function Reset-Policy($Value, $ProductType = 2) {
    $script:value = $Value
    $script:productType = $ProductType
    $script:writes = 0
    $script:prompts = 0
    $script:reads = 0
    $script:keyExists = $true
    $script:roleFails = $false
    $script:readFails = $false
    $script:writeFails = $false
    $script:ignoreWrite = $false
    $script:response = 'Y'
}
function Get-CimInstance {
    param($ClassName, $Property, $ErrorAction)
    if ($script:roleFails) { throw 'CIM unavailable' }
    return [pscustomobject]@{ ProductType = $script:productType }
}
function Test-Path { param($LiteralPath, $ErrorAction) return $script:keyExists }
function Get-ItemProperty {
    param($LiteralPath, $ErrorAction)
    $script:reads++
    if ($script:readFails) { throw 'Access denied' }
    if ($null -eq $script:value) { return [pscustomobject]@{} }
    return [pscustomobject]@{ AuditNTLMInDomain = $script:value }
}
function New-Item { param($Path, [switch]$Force, $ErrorAction) $script:keyExists = $true }
function Set-ItemProperty {
    param($LiteralPath, $Name, $Value, $Type, $ErrorAction)
    if ($script:writeFails) { throw 'Access denied' }
    if ($Name -ne 'AuditNTLMInDomain') { throw "Unexpected write: $Name" }
    $script:writes++
    if (-not $script:ignoreWrite) { $script:value = $Value }
}
function Read-Host { param($Prompt) $script:prompts++; return $script:response }

$script:assertions = 0
foreach ($initial in @($null, 0, 2, 7)) {
    Reset-Policy $initial
    Set-WelaDomainNtlmAudit -Auto
    Assert-Equal $script:value 7 "DC initial value '$initial' reaches Enable all"
    $expectedWrites = if ($initial -eq 7) { 0 } else { 1 }
    Assert-Equal $script:writes $expectedWrites 'Already configured DCs are idempotent'
}
Reset-Policy 2
Assert-Equal ((Get-WelaDomainNtlmState).Description) 'Value 2 (not interpreted as Enable all)' 'Migration reports old value without inventing semantics'
foreach ($role in @(1, 3)) {
    Reset-Policy 2 $role
    Set-WelaDomainNtlmAudit -Auto
    Assert-Equal $script:writes 0 "No domain policy writes on non-DC ProductType $role"
    Assert-Equal $script:reads 0 'Non-DC domain registry is not read'
    Assert-Equal ((Get-WelaDomainNtlmState).Description -like 'Not applicable*') $true 'Non-DC is reported as not applicable'
    Assert-Equal $script:value 2 'Existing non-DC value is preserved'
}
foreach ($role in @($null, 0, 42)) {
    Reset-Policy 2 $role
    Set-WelaDomainNtlmAudit -Auto
    Assert-Equal $script:writes 0 'Unknown role never receives domain policy'
    Assert-Equal ((Get-WelaDomainNtlmState).Description -like 'Unknown*') $true 'Unknown role is not labeled non-DC'
}
Reset-Policy 2
$script:roleFails = $true
Set-WelaDomainNtlmAudit -Auto
Assert-Equal $script:writes 0 'Failed role discovery never receives domain policy'
Assert-Equal ((Get-WelaDomainNtlmState).Description -like 'Unknown*query failed*') $true 'Role errors are visible'
Reset-Policy 2
$script:readFails = $true
Assert-Throws { Set-WelaDomainNtlmAudit -Auto } 'Unreadable DC policy fails visibly'
Assert-Equal $script:writes 0 'Unreadable current value is preserved'
Reset-Policy $null
$script:keyExists = $false
Set-WelaDomainNtlmAudit -Auto
Assert-Equal $script:keyExists $true 'Missing DC policy key is created'
Assert-Equal $script:value 7 'Missing DC key receives Enable all'
Reset-Policy 2
Set-WelaDomainNtlmAudit -WhatIf
Assert-Equal $script:writes 0 'WhatIf preserves policy'
Assert-Equal $script:prompts 0 'WhatIf does not prompt without Auto'
$script:response = 'n'
Set-WelaDomainNtlmAudit
Assert-Equal $script:writes 0 'Declining preserves policy'
$script:response = ''
Set-WelaDomainNtlmAudit
Assert-Equal $script:value 7 'Confirming applies policy'
Reset-Policy 2
$script:writeFails = $true
Assert-Throws { Set-WelaDomainNtlmAudit -Auto } 'Write failure propagates'
Reset-Policy 2
$script:ignoreWrite = $true
Assert-Throws { Set-WelaDomainNtlmAudit -Auto } 'Read-back mismatch propagates'
Write-Host "PASS: $script:assertions domain NTLM assertions (mocked; no host changes)."
