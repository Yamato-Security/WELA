$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/LdapDiagnostics.ps1')
$result=Invoke-WelaLdapCommand -Action Audit
if ($result.Snapshot.Host.Status -notin @('Applicable','NotApplicable')) { throw 'Unexpected unknown native host applicability.' }
if ($result.Snapshot.Host.Status -eq 'NotApplicable' -and $result.Snapshot.Values.Count) { throw 'Non-DC incorrectly queried NTDS values.' }
Write-Host "PASS: native read-only LDAP applicability $($result.Snapshot.Host.Status); no registry writes or LDAP queries."
