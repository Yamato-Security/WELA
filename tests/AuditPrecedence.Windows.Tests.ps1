# Read-only host observations; never change precedence, GPO or audit masks.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/Configuration.ps1')
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
$state = Get-WelaAuditPrecedenceState
if ($state.State -notin @('Enabled', 'Disabled', 'Not configured', 'Unknown')) { throw 'Invalid precedence observation' }
$current = Get-WelaEffectiveAuditPolicy
if ($current.Count -ne 59) { throw 'Audit policy API omitted catalog entries' }
if ($state.State -eq 'Unknown' -and -not $state.Diagnostic) { throw 'Unknown state must preserve diagnostics' }
Write-Host "Read-only precedence state: $($state.State); 59 effective masks read. No policy refresh or writes performed."
