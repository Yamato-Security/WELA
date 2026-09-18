# Executes only the exported writer's function definition with safe resolver and
# argument-builder fixtures. Native children emit diagnostics and exit; no auditpol
# command or Windows policy mutation is ever invoked.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$path = Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1'
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-WelaEffectiveAuditPolicy' }, $true)
if (-not $definition) { throw 'Native audit writer definition was not found.' }
. ([scriptblock]::Create($definition.Extent.Text))
Set-StrictMode -Version 2.0
$engine = (Get-Command -Name (Get-Process -Id $PID).Path -CommandType Application -ErrorAction Stop).Source
$guid = '0CCE922B-69AE-11D9-BED3-505054503030'
$script:assertions = 0; $script:lookups = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:assertions++
}
function Invoke-ExpectFailure([scriptblock]$Action, [string]$Pattern) {
    $caught = ''
    try { & $Action } catch { $caught = $_.ToString() }
    Assert ($caught -match $Pattern) "Expected '$Pattern'; observed '$caught'"
    return $caught
}
function Get-Command {
    param($Name, $CommandType, $ErrorAction)
    $script:lookups++
    if ($Name -ne 'auditpol.exe' -or $CommandType -ne 'Application' -or $ErrorAction -ne 'Stop') {
        throw 'Writer must resolve the auditpol application with a terminating lookup.'
    }
    if ($script:lookupFails) { throw 'Injected auditpol lookup failure' }
    [pscustomobject]@{ Source = $script:resolvedSource }
}
function Get-WelaAuditSetArguments {
    param($Guid, $Mask, $Mode)
    return $script:nativeArguments
}
$script:lookupFails = $true
$script:resolvedSource = $engine
$script:nativeArguments = @('-NoProfile', '-Command', 'exit 0')
$global:LASTEXITCODE = 0
$null = Invoke-ExpectFailure { Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 } 'Injected auditpol lookup failure'
Assert ($script:lookups -eq 1) 'A stale native zero cannot bypass a failed executable lookup'

$script:lookupFails = $false
$script:resolvedSource = Join-Path ([IO.Path]::GetTempPath()) ('wela-missing-native-' + [guid]::NewGuid().ToString('N') + '.exe')
$global:LASTEXITCODE = 0
$null = Invoke-ExpectFailure { Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 } 'not recognized|failed'
Assert ($null -eq $global:LASTEXITCODE) 'An executable disappearing after lookup cannot retain an earlier success code'

$script:resolvedSource = $engine
$script:nativeArguments = @('-NoProfile', '-Command', "[Console]::Error.WriteLine('writer native failure diagnostic'); exit 7")
$global:LASTEXITCODE = 0
$caught = Invoke-ExpectFailure { Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 } 'failed \(7\)'
Assert ($caught -match 'writer native failure diagnostic') 'Native exit failure retains stderr diagnostics'
Assert ($global:LASTEXITCODE -eq 7) 'The newly executed process exit code is observed'

$script:nativeArguments = @('-NoProfile', '-Command', "[Console]::Error.WriteLine('non-fatal native diagnostic'); exit 0")
$global:LASTEXITCODE = 7
$PSNativeCommandUseErrorActionPreference = $true
Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 3
Assert ($global:LASTEXITCODE -eq 0) 'A fresh zero succeeds even with stderr and a previous failure'
Assert ($ErrorActionPreference -eq 'Stop' -and $PSNativeCommandUseErrorActionPreference) 'Native preferences remain local to the writer'

# A malformed/inert executable fixture returns without updating a process exit code.
# This proves absence of a new code cannot be mistaken for the previous zero.
$script:resolvedSource = { 'Fixture produced no native exit status' }
$script:nativeArguments = @()
$global:LASTEXITCODE = 0
$null = Invoke-ExpectFailure { Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 } 'failed \(\)'
Assert ($null -eq $global:LASTEXITCODE) 'Missing new native exit status is rejected'

$script:lookupFails = $true
$before = $script:lookups
Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 0 -Mode minimum
Assert ($script:lookups -eq $before) 'An empty minimum policy does not resolve or execute a writer'
$global:LASTEXITCODE = 0 # Expected fixture failures must not fail the CI shell wrapper.
Write-Host "PASS: $script:assertions native audit writer assertions (safe native children; no policy changes)."
