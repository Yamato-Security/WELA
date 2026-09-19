# Real read-only collector observations only. The source bundle below is explicitly synthetic.
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'This test requires Windows.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/ControlApplicability.ps1')
. (Join-Path $repo 'scripts/NativeValidation.ps1')
. (Join-Path $repo 'scripts/WefArrival.ps1')
. (Join-Path $PSScriptRoot 'fixtures/WefArrival.Fixture.ps1')
function Start-WelaProbeProcess {throw 'Native event generation is forbidden in this read-only test.'}
function Set-ItemProperty {throw 'Registry mutation is forbidden in this read-only test.'}
function Invoke-WelaNative {throw 'Native configuration commands are forbidden in this read-only test.'}
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-arrival-readonly-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
try {
    $before=Get-WelaArrivalCollector;$beforeKey=Get-WelaArrivalCollectorKey $before
    Assert ($before.Reader.UserSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -and $before.Computer -eq [Environment]::MachineName) 'Actual collector and current reader identities are observed'
    $fixture=New-WelaArrivalFixture (Join-Path $temp 'synthetic-source')
    $source=Import-WelaArrivalProbe $fixture.Directory
    $batch=Read-WelaArrivalEvents -SourceEvent $source.Event
    Assert ($batch.Channel -eq 'ForwardedEvents' -and -not $batch.Capped -and $batch.Xml.Count -eq 0) 'Native bounded query reads actual ForwardedEvents and finds no synthetic probe'
    $output=Join-Path $temp 'negative-result'
    $report=Invoke-WelaWefArrival $fixture.Directory $output
    Assert ($report.ExitCode -eq 1 -and $report.Status -eq 'Unverified' -and $report.ExactMatches -eq 0 -and $report.Query -and $report.CollectorAfter) 'Native negative verification preserves observations and never claims forwarding'
    Assert ($report.PolicyChanges -eq 0 -and $report.ReadyRuleCredit -eq 0) 'Read-only collection grants no policy or readiness credit'
    $acl=Get-Acl -LiteralPath $output
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    Assert ($acl.AreAccessRulesProtected -and @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -notin $allowed -or $_.AccessControlType -ne 'Allow'}).Count -eq 0) 'New output directory is private to the current user, SYSTEM and Administrators'
    foreach($artifact in $report.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $output $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Native observation output hashes match actual bytes'}
    Assert ((Get-WelaArrivalCollectorKey (Get-WelaArrivalCollector)) -ceq $beforeKey) 'Collector host, reader and channel settings remain unchanged'
    Write-Host "PASS: $script:checks native read-only WEF arrival checks. No event was generated or forwarded; cross-host positive acceptance is pending."
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
