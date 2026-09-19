# Safe fixtures through the public command/report and shared runner. No Windows writes.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/EventLogSettings.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeChannelAccess.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/NativeChannelConfiguration.ps1')
$script:ScriptRoot = $repo
$script:assertions = 0
$script:cleanup = New-Object 'System.Collections.Generic.List[string]'
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }; $script:assertions++
}
function New-FixtureState([string]$Name) {
    [pscustomobject]@{ Name = $Name; State = 'Disabled'; IsEnabled = $false; LogMode = 'Retain'; SecurityDescriptor = 'fixture-original'; MaximumSizeInBytes = [long]1048576; MetadataErrors = @{}; Error = $null }
}
function Reset-Fixture {
    $script:profile = Get-WelaNativeChannelProfile
    $global:WelaChannelFixture = @{ States = @{}; Reads = @{}; Writes = (New-Object 'System.Collections.Generic.List[object]'); DriftRead = 0; Failure = ''; Prompt = 'Y' }
    foreach ($control in $script:profile.controls) { $global:WelaChannelFixture.States[$control.channel] = New-FixtureState $control.channel }
    $script:capi = $script:profile.controls[0].channel
    $script:app = $script:profile.controls[1].channel
    $script:driver = $script:profile.controls[2].channel
    $script:backup = Join-Path ([IO.Path]::GetTempPath()) ('wela-channel-' + [guid]::NewGuid().ToString('N'))
    $global:WelaChannelFixture.Backup = $script:backup
    $script:cleanup.Add($script:backup)
}
function Get-WelaNativeChannel {
    param($Name)
    $f = $global:WelaChannelFixture
    if (-not $f.States.ContainsKey($Name)) { return New-FixtureState $Name }
    if (-not $f.Reads.ContainsKey($Name)) { $f.Reads[$Name] = 0 }
    $f.Reads[$Name]++
    if ($f.DriftRead -eq $f.Reads[$Name] -and $Name -eq $script:capi) { $f.States[$Name].SecurityDescriptor = 'fixture-concurrent' }
    return $f.States[$Name].PSObject.Copy()
}
# Windows ACL serialization is tested separately against the real .NET APIs. These
# token descriptors let the command/runner fail-path tests execute safely on Linux.
function Test-WelaChannelDescriptorEqual { param($First, $Second) return $First -and $Second -and $First -ceq $Second }
function Get-WelaChannelAccessPlan {
    param($SecurityDescriptor)
    [pscustomobject]@{
        State = $(if ($SecurityDescriptor -eq 'fixture-granted') { 'GrantPresent' } elseif ($SecurityDescriptor -eq 'fixture-original') { 'GrantRequired' } else { 'ManualReview' })
        ProposedDescriptor = 'fixture-granted'; EffectiveReadAccess = 'Not tested'; Diagnostic = 'Fixture ACL planner'
    }
}
function Read-Host { param($Prompt) return $global:WelaChannelFixture.Prompt }
function Invoke-WelaNative {
    param($FilePath, $Arguments)
    $f = $global:WelaChannelFixture
    Assert ($FilePath -eq 'wevtutil.exe' -and $Arguments[0] -eq 'sl') 'Only wevtutil channel settings are written'
    $journal = Join-Path $f.Backup 'before.jsonl'
    Assert (Test-Path -LiteralPath $journal) 'Recovery journal exists before native write'
    $record = @(Get-Content -LiteralPath $journal | ForEach-Object { $_ | ConvertFrom-Json })[-1]
    Assert ($record.Target.Channel -eq $Arguments[1] -and $record.Before.SecurityDescriptor -eq $f.States[$Arguments[1]].SecurityDescriptor) 'Journal holds the fresh original descriptor for this channel'
    $f.Writes.Add(@($Arguments))
    if ($f.Failure -eq 'native') { throw 'fixture native failure' }
    if ($f.Failure -eq 'false-success') { return }
    foreach ($argument in $Arguments) {
        if ($argument -eq '/e:true') { $f.States[$Arguments[1]].IsEnabled = $true; $f.States[$Arguments[1]].State = 'Enabled' }
        if ($argument -like '/ms:*') { $f.States[$Arguments[1]].MaximumSizeInBytes = [long]$argument.Substring(4) }
        if ($argument -like '/ca:*') { $f.States[$Arguments[1]].SecurityDescriptor = $argument.Substring(4) }
    }
}
$module = Get-Module NativeChannelAccess
& $module {
    function script:Get-WelaNativeChannel {
        param($Name)
        if ($global:WelaChannelFixture.States.ContainsKey($Name)) { return $global:WelaChannelFixture.States[$Name].PSObject.Copy() }
        [pscustomobject]@{ Name = $Name; State = 'Not installed'; IsEnabled = $null; LogMode = $null; SecurityDescriptor = $null; MaximumSizeInBytes = $null; MetadataErrors = @{}; Error = @{ Message = 'fixture missing registration' } }
    }
}
$savedOS = $env:OS
try {
    $env:OS = 'Windows_NT' # Only mocked readers/setters are reachable in this suite.
    Reset-Fixture
    Assert ($script:profile.controls.Count -eq 3) 'Profile declares exactly the three Appendix C channel examples'
    Assert ($script:profile.controls[0].sourceExampleBytes -eq 102432768 -and $script:profile.controls[1].sourceExampleBytes -eq 102432768) 'CAPI2/AppLocker preserve the exact source byte values'
    Assert ($script:profile.controls[2].sourceExampleBytes -eq 52432896) 'DriverFrameworks source is not approximated as 50 MiB'
    Assert ((ConvertTo-WelaEventLogBytes 52432896) -eq 52494336) 'Applied minimum rounds upward to Windows 64 KiB units'
    $caught = $false; try { Get-WelaNativeChannelProfile -Id 'unknown' } catch { $caught = $true }
    Assert $caught 'Unknown channel profile is rejected'
    $out = $script:backup + '.json'; $script:cleanup.Add($out)
    $report = Invoke-WelaNativeChannelCommand -Action Plan -GrantEventLogReaders -ResultsPath $out
    $json = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
    Assert ($json.Controls[0].Desired.AccessChangeRequested -and $json.Controls[0].Desired.SecurityDescriptor -eq 'fixture-granted') 'Public JSON contains explicit proposed CAPI2 ACL'
    Assert ($json.QueryInventory.Count -eq 18 -and $json.ExcludedQueries.Count -eq 2) 'Both queries inventory 18 unique native channels and exclude EMET/Sysmon'
    Assert (@($json.QueryInventory | Where-Object { $_.Channel.Name -like '*Sysmon*' }).Count -eq 0) 'Sysmon is outside native inventory'
    Assert (($json.QueryInventory | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-CAPI2/Operational' }).Queries[0].QueryIds[0] -eq '2') 'Inventory preserves source query IDs'
    Assert ($json.ForwardingReadiness -eq 'Not verified' -and @($json.QueryInventory | Where-Object EffectiveReadAccess -ne 'Not tested').Count -eq 0) 'Public export does not infer identity access or forwarding from ACEs'
    Assert (($json.QueryInventory | Where-Object { $_.Channel.Name -eq 'Security' }).Channel.State -eq 'Not installed') 'Inventory retains absent channel evidence'
    Assert ($global:WelaChannelFixture.Writes.Count -eq 0 -and -not (Test-Path $script:backup)) 'Plan performs no mutation or journal creation'
    $report = Invoke-WelaNativeChannelCommand -Action Audit -QuerySet Baseline
    Assert ($report.QueryInventory.Count -eq 12) 'Baseline query selection inventories its twelve native channels'
    $report = Invoke-WelaNativeChannelCommand -Action Audit -QuerySet Suspect
    Assert ($report.QueryInventory.Count -eq 8 -and $report.ExcludedQueries.Count -eq 0) 'Suspect selection remains distinct'

    Reset-Fixture
    $report = Invoke-WelaNativeChannelCommand -Action Configure -GrantEventLogReaders -Auto -BackupPath $script:backup
    Assert ($report.ExitCode -eq 0 -and $report.Scope -eq 'native-channel-settings-only') 'Configure succeeds only for requested channel settings'
    Assert ($global:WelaChannelFixture.Writes.Count -eq 3) 'Configure changes only three declared channels'
    Assert ($global:WelaChannelFixture.States[$script:capi].IsEnabled -and $global:WelaChannelFixture.States[$script:capi].SecurityDescriptor -eq 'fixture-granted') 'CAPI2 enablement and ACL are read back'
    Assert (-not $global:WelaChannelFixture.States[$script:app].IsEnabled -and $global:WelaChannelFixture.States[$script:app].SecurityDescriptor -eq 'fixture-original') 'AppLocker size control preserves disabled state and ACL'
    Assert ($global:WelaChannelFixture.States[$script:driver].MaximumSizeInBytes -eq 52494336) 'DriverFrameworks applied size matches rounded source bytes'
    Assert (@($global:WelaChannelFixture.Writes | Where-Object { ($_ -join ' ') -match '/[ar][bt]:' }).Count -eq 0) 'No retention settings are modified'
    Assert ($report.Controls[0].Access.State -eq 'GrantPresent' -and $report.Controls[0].Access.EffectiveReadAccess -eq 'Not tested') 'Structural readback never becomes an effective-access claim'
    $json = @(Get-Content (Join-Path $script:backup 'before.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert ($json[0].Before.MaximumSizeInBytes -eq 1048576 -and $json[0].Before.SecurityDescriptor -eq 'fixture-original' -and $json[0].Before.LogMode -eq 'Retain') 'Journal includes original bytes, full descriptor and retention mode'

    Reset-Fixture
    $global:WelaChannelFixture.States[$script:capi].MaximumSizeInBytes = [long]4294967296
    $report = Invoke-WelaNativeChannelCommand -Action Configure -Auto -BackupPath $script:backup
    Assert ($global:WelaChannelFixture.States[$script:capi].MaximumSizeInBytes -eq 4294967296) 'Existing larger buffer is preserved'
    Assert (@($global:WelaChannelFixture.Writes | Where-Object { ($_ -join ' ') -like '*/ca:*' }).Count -eq 0) 'No ACL change without separate opt-in'
    Assert ($report.Controls[0].Access.State -eq 'GrantRequired' -and $report.Controls[0].Prerequisites.Count -ge 2) 'Omitted ACL opt-in remains an unmet profile prerequisite'

    Reset-Fixture
    $report = Invoke-WelaNativeChannelCommand -Action Configure -GrantEventLogReaders -DryRun -BackupPath $script:backup
    Assert ($report.DryRun -and $report.Skipped -eq 3 -and $global:WelaChannelFixture.Writes.Count -eq 0 -and -not (Test-Path $script:backup)) 'Dry run does no native writes and creates no backup directory'
    Reset-Fixture
    $global:WelaChannelFixture.Prompt = 'n'
    $report = Invoke-WelaNativeChannelCommand -Action Configure -GrantEventLogReaders -BackupPath $script:backup
    Assert ($report.Skipped -eq 3 -and $global:WelaChannelFixture.Writes.Count -eq 0) 'Declining prompts preserves every channel'

    foreach ($driftRead in @(2, 3, 5)) {
        Reset-Fixture; $global:WelaChannelFixture.DriftRead = $driftRead
        $report = Invoke-WelaNativeChannelCommand -Action Configure -GrantEventLogReaders -Auto -QuerySet Baseline -BackupPath $script:backup
        Assert ($report.ExitCode -eq 1) "Drift at observation $driftRead cannot report success"
        $writes = @($global:WelaChannelFixture.Writes | Where-Object { $_[1] -eq $script:capi })
        Assert ($writes.Count -eq $(if ($driftRead -eq 5) { 1 } else { 0 })) "Plan-to-initial/prewrite drift rejects stale ACL; final drift is detected ($driftRead)"
    }
    foreach ($failure in @('native', 'false-success', 'denied', 'missing', 'acl')) {
        Reset-Fixture; $global:WelaChannelFixture.Failure = $failure
        if ($failure -eq 'denied') { $global:WelaChannelFixture.States[$script:capi].State = 'Unknown'; $global:WelaChannelFixture.States[$script:capi].SecurityDescriptor = $null }
        if ($failure -eq 'missing') { $global:WelaChannelFixture.States[$script:capi].State = 'Not installed' }
        if ($failure -eq 'acl') { $global:WelaChannelFixture.States[$script:capi].SecurityDescriptor = 'fixture-deny' }
        $report = Invoke-WelaNativeChannelCommand -Action Configure -GrantEventLogReaders -Auto -BackupPath $script:backup
        Assert ($report.ExitCode -eq 1 -and $report.Results[0].Status -eq 'Failed') "Failure $failure remains explicit and nonzero"
        if ($failure -in @('denied', 'missing', 'acl')) { Assert (@($global:WelaChannelFixture.Writes | Where-Object { $_[1] -eq $script:capi }).Count -eq 0) "$failure never writes CAPI2" }
    }
    Reset-Fixture
    $plan = @(Get-WelaNativeChannelPlan -Profile $script:profile -GrantEventLogReaders)
    $context = New-WelaConfigurationContext -Auto -BackupPath $script:backup
    New-Item -ItemType Directory -Path (Join-Path $script:backup 'before.jsonl') | Out-Null
    Set-WelaNativeChannelControls -Context $context -Plan $plan -Profile $script:profile.id
    Assert ($global:WelaChannelFixture.Writes.Count -eq 0 -and $context.Results[0].Status -eq 'Failed') 'Journal failure blocks all writes'
    $caught = $false; try { Invoke-WelaNativeChannelCommand -Action Audit -DryRun } catch { $caught = $true }
    Assert $caught 'Unsupported dry-run action is rejected before reads/writes'
    Reset-Fixture
    $report = Invoke-WelaNativeChannelCommand -Action Plan -ResultsPath (Join-Path $script:backup 'missing/results.json')
    Assert ($report.ExitCode -eq 1) 'Failed report export has a nonzero result'
    Write-Host "PASS: $script:assertions native channel command/runner assertions. No Windows settings were changed."
} finally {
    $env:OS = $savedOS
    & $module { Remove-Item Function:script:Get-WelaNativeChannel }
    Remove-Variable -Name WelaChannelFixture -Scope Global -ErrorAction SilentlyContinue
    foreach ($path in $script:cleanup) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
}
