# Read-only smoke test of real Windows commands, independent of the mock suite.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this smoke test on Windows.' }
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/Configuration.ps1')
$mask = Get-WelaAuditPolicyMask '0CCE922B-69AE-11D9-BED3-505054503030'
if ($mask -notin @(0, 1, 2, 3)) { throw "Unexpected process-creation audit mask: $mask" }
# Also exercise the real read-only auditpol command and its native exit status.
$csv = Invoke-WelaNative -FilePath auditpol.exe -Arguments @('/get', '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}', '/r')
if ($csv.Diagnostic -notmatch '0CCE922B-69AE-11D9-BED3-505054503030') { throw 'auditpol query returned no requested subcategory.' }
$caught = ''
try { Invoke-WelaNative -FilePath $env:ComSpec -Arguments @('/d', '/c', 'echo WELA-smoke-diagnostic 1>&2 & exit /b 9') }
catch { $caught = $_.ToString() }
if ($caught -notmatch 'exit: 9' -or $caught -notmatch 'WELA-smoke-diagnostic') {
    throw "Native exit/stderr capture failed: $caught"
}
Write-Host "Read-only Windows smoke checks passed (process creation audit mask: $mask). No Windows settings changed."
