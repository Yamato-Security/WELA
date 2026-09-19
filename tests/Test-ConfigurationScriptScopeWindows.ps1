# Actual script-scope helpers and Windows registry provider. Only a unique test
# key under HKCU and a temporary journal are written; no Windows logging changes.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this test on Windows.' }
$repo = Split-Path $PSScriptRoot -Parent
$script:ScriptRoot = $repo
. (Join-Path $repo 'scripts/Configuration.ps1')
# Deliberately keep all helper functions script-local, as in WELA.ps1 -File.
# Do not promote helpers or replace their calls with global mocks.
$token = [guid]::NewGuid().ToString('N')
$key = "HKCU:\Software\WELA-Configuration-Scope-$token"
$backup = Join-Path ([IO.Path]::GetTempPath()) "wela-script-scope-$token"
$ownsTestArtifacts = $false
function Assert-Scope($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Add-ScopeControls($Context, [string]$Root) {
    Set-WelaRegistryControl -Context $Context -Path "$Root\ParentA\Child" -Name Counter -Value 42
    Set-WelaRegistryControl -Context $Context -Path "$Root\ParentB\Child" -Name Label -Value 'second control' -Type String
}
try {
    if ((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $backup)) { throw 'Unique test artifact unexpectedly exists; refusing to use it.' }
    $ownsTestArtifacts = $true
    $context = New-WelaConfigurationContext -Auto -BackupPath $backup
    # These calls must resolve Get-WelaRegistryState and recursively resolve
    # New-WelaRegistryKey from ordinary script scope, then use real provider APIs.
    Add-ScopeControls -Context $context -Root $key
    $report = Complete-WelaConfiguration -Context $context
    Assert-Scope ($report.ExitCode -eq 0) 'Script-local registry helper chain resolves and verifies'
    Assert-Scope (@($report.Results | Where-Object Status -eq Applied).Count -eq 2) 'Both distinct control states remain available after their calling function returns'
    Assert-Scope ((Get-ItemProperty -LiteralPath "$key\ParentA\Child" -Name Counter).Counter -eq 42) 'Actual DWORD value was written and read back'
    Assert-Scope ((Get-ItemProperty -LiteralPath "$key\ParentB\Child" -Name Label).Label -eq 'second control') 'Actual string value was written and read back'
    $journal = @(Get-Content -LiteralPath (Join-Path $backup 'before.jsonl') | ConvertFrom-Json)
    Assert-Scope ($journal.Count -eq 2 -and -not $journal[0].Before.KeyExists -and -not $journal[1].Before.KeyExists) 'Missing nested registry parents were journaled before creation'
    Add-ScopeControls -Context $context -Root $key
    $report = Complete-WelaConfiguration -Context $context
    Assert-Scope ($report.ExitCode -eq 0 -and @($report.Results | Where-Object Status -eq AlreadyCompliant).Count -eq 2) 'Actual registry rerun is idempotent'
    Assert-Scope (@(Get-Content -LiteralPath (Join-Path $backup 'before.jsonl')).Count -eq 2) 'Compliant rerun writes no additional mutation journal records'

    # Exercise deferred native-policy and event-log readers in the same script
    # scope. DryRun prevents every native configuration or service mutation.
    $dry = New-WelaConfigurationContext -Auto -DryRun
    Set-WelaRegistryControl -Context $dry -Path "$key\ParentA\Child" -Name Counter -Value 99
    Set-WelaAuditPolicyControl -Context $dry -Policy @{ GUID = '0CCE922B-69AE-11D9-BED3-505054503030'; Name = 'Process Creation' }
    Set-WelaEventLogControl -Context $dry -Log Security -Property MaximumSizeInBytes -Desired 1
    $dryReport = Complete-WelaConfiguration -Context $dry
    Assert-Scope ($dryReport.ExitCode -eq 0) 'Deferred native API and event-log callbacks resolve script-local helpers'
    Assert-Scope ((Get-ItemProperty -LiteralPath "$key\ParentA\Child" -Name Counter).Counter -eq 42) 'DryRun leaves the actual registry value unchanged'
    Write-Host 'Script-scope Windows provider checks passed. Only a disposable HKCU test key and temp journal were changed.'
} finally {
    if ($ownsTestArtifacts -and (Test-Path -LiteralPath $key)) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop }
    if ($ownsTestArtifacts -and (Test-Path -LiteralPath $backup)) { Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction Stop }
}
