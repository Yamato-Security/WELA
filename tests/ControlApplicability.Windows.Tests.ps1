$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/ControlApplicability.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1')
Import-Module (Join-Path $root 'modules/NativeProviders.psm1')
$report=Invoke-WelaDefaultEvidenceCommand -Action Capture
$snapshot=$report.Snapshot
if (-not (Test-WelaDefaultContextComplete $snapshot.Context)) { throw "Native snapshot context incomplete: $($snapshot.Context.Diagnostic)" }
if ($snapshot.EvidenceKind -ne 'ObservedState' -or $snapshot.Review.Reviewer) { throw 'Native observed state was incorrectly promoted to a reviewed default.' }
if (@($snapshot.Observations | Where-Object Kind -eq 'auditpol').Count -ne 59) { throw 'Canonical audit inventory incomplete.' }
$comparison=Get-WelaDefaultComparison $snapshot $snapshot
if ($comparison.ReferenceReview.Accepted -or @($comparison.Results | Where-Object DefaultSetting -ne 'Unknown').Count) { throw 'Observed state cannot establish defaults.' }
$controls=@(Get-WelaHistoricalControls -Context $snapshot.Context)
if ($controls[0].Applicability.Status -ne 'NotApplicable' -or $controls[0].Applicability.Remediation) { throw 'Server must not receive historical client Application Guard remediation.' }
$snapshot.Context | ConvertTo-Json -Depth 5 | Write-Host
$snapshot.Observations | Select-Object Id,Status,Value,Diagnostic | Format-Table -AutoSize | Out-Host
Write-Host 'PASS: native build/patch/join/role and policy/channel capture is read-only. This runner is not a clean-install reference.'
$global:LASTEXITCODE=0
