$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/NativeChannelConfiguration.ps1')
. (Join-Path $root 'scripts/AuditNotifications.ps1')
$script:count=0; $script:cleanup=@()
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Reject([scriptblock]$Action,[string]$Pattern) {
    $message=''; try { & $Action | Out-Null } catch { $message=$_.Exception.Message }
    Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'."
}
function Reset-Fixture {
    $script:values=@{}; $script:types=@{}; $script:writes=@(); $script:journal=$null
    $script:hostStatus='Supported'; $script:build=22631; $script:product=1
    $script:channel='Enabled'; $script:logMode='Circular'; $script:admxError=$false
    $script:channelPromptDrift=$false; $script:policyDrift=$false; $script:postWriteReads=0
    $script:readError=$false; $script:writeError=$false; $script:ignored=$false; $script:race=$false
}
function Get-WelaNotificationHost { [pscustomobject]@{Status=$script:hostStatus;Build=$script:build;ProductType=$script:product;Diagnostic='fixture'} }
function Get-WelaOneSettingsDefinitionEvidence {
    if ($script:admxError) { throw 'mapping missing' }
    [pscustomobject]@{Path='fixture';Sha256='abc';Mapping='DWORD1'}
}
function Get-WelaRegistryState {
    param($Path,$Name)
    if ($script:readError) { throw 'read denied' }
    if ($script:policyDrift -and $script:writes.Count -gt 0 -and $Name -eq 'EnableOneSettingsAuditing') { $script:postWriteReads++; if ($script:postWriteReads -ge 2) { $script:values[$Name]=0 } }
    if ($script:race -and $script:journal -and (Test-Path $script:journal)) { $script:values[$Name]=0; $script:types[$Name]='DWord' }
    [pscustomobject]@{KeyExists=$true;ValueExists=$script:values.ContainsKey($Name);Value=$script:values[$Name];Type=$script:types[$Name]}
}
function Get-WelaNativeChannel {
    param($Name)
    [pscustomobject]@{Name=$Name;State=$script:channel;IsEnabled=($script:channel -eq 'Enabled');MaximumSizeInBytes=1048576;LogMode=$script:logMode;SecurityDescriptor='O:SYG:SYD:(A;;0x1;;;SY)'}
}
function New-WelaRegistryKey { param($Path) }
function Set-ItemProperty {
    param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
    Assert ($script:journal -and (Test-Path $script:journal)) 'Write requires a pre-change journal.'
    if ($script:writeError) { throw 'write denied' }
    $script:writes+=$Name
    if (-not $script:ignored) { $script:values[$Name]=$Value; $script:types[$Name]=$Type }
}
function New-FixtureContext([switch]$DryRun) {
    $path=Join-Path ([IO.Path]::GetTempPath()) ('wela-notification-'+[guid]::NewGuid().ToString('N'))
    $script:cleanup+=$path; $script:journal=Join-Path $path 'before.jsonl'
    New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath $path
}
try {
    Reset-Fixture
    $plan=@(Get-WelaNotificationPlan)
    Assert ($plan.Count -eq 2 -and $script:writes.Count -eq 0) 'Audit/plan enumerate two independent controls without writing.'
    Assert ($plan[1].Before.WarningGeneration -like 'Not expected*') 'Circular overwrite cannot claim threshold warnings.'
    $script:logMode='AutoBackup'
    Assert ((Get-WelaNotificationPlan SecurityWarning).Before.WarningGeneration -like 'Unknown*') 'AutoBackup event behavior requires validation.'
    $script:logMode='Retain'
    Assert ((Get-WelaNotificationPlan SecurityWarning).Before.WarningGeneration -like 'Conditional*') 'Retain policy is no event proof.'
    Reject { Invoke-WelaNotificationCommand -Action Configure } 'explicit NotificationControl'
    Reject { Invoke-WelaNotificationCommand -Control SecurityWarning -EnablePrivacyChannel } 'requires the OneSettings'
    Reject { Invoke-WelaNotificationCommand -DryRun } 'requires Configure'
    foreach ($v in @(0,91)) { Reject { Get-WelaNotificationPlan -WarningPercent $v } 'validat' }
    $script:values.WarningLevel=70; $script:types.WarningLevel='DWord'
    $row=Get-WelaNotificationPlan SecurityWarning -WarningPercent 90
    Assert ($row.Status -eq 'PolicyMatches' -and $row.Desired -eq 70) 'Preserve an existing stricter threshold.'
    $row=Get-WelaNotificationPlan SecurityWarning -WarningPercent 60
    Assert ($row.Status -eq 'ChangeRequired' -and $row.Desired -eq 60) 'Explicit lower maximum is actionable.'
    foreach ($scenario in @('apply','dry','stale','race','read','write','ignored','drift','type','admx','channel','unsupported','unknownvalue')) {
        Reset-Fixture
        if ($scenario -eq 'type') { $script:values.EnableOneSettingsAuditing='1'; $script:types.EnableOneSettingsAuditing='String' }
        if ($scenario -eq 'unknownvalue') { $script:values.EnableOneSettingsAuditing=2; $script:types.EnableOneSettingsAuditing='DWord' }
        if ($scenario -eq 'admx') { $script:admxError=$true }
        if ($scenario -eq 'channel') { $script:channel='Not installed' }
        if ($scenario -eq 'unsupported') { $script:product=3; $script:build=26100 }
        $plan=@(Get-WelaNotificationPlan OneSettings)
        if ($scenario -eq 'stale') { $script:values.EnableOneSettingsAuditing=0; $script:types.EnableOneSettingsAuditing='DWord' }
        if ($scenario -eq 'race') { $script:race=$true }
        if ($scenario -eq 'read') { $script:readError=$true }
        if ($scenario -eq 'write') { $script:writeError=$true }
        if ($scenario -eq 'ignored') { $script:ignored=$true }
        $context=New-FixtureContext -DryRun:($scenario -eq 'dry')
        Set-WelaNotificationControls -Context $context -Plan $plan
        if ($scenario -eq 'drift') { $script:values.EnableOneSettingsAuditing=0 }
        $report=Complete-WelaConfiguration $context
        switch ($scenario) {
            'apply' {
                Assert ($report.ExitCode -eq 0 -and $script:values.EnableOneSettingsAuditing -eq 1) 'Write is read back and verified.'
                $journal=Get-Content $script:journal -Raw | ConvertFrom-Json
                Assert (-not $journal.Before.Policy.ValueExists -and $journal.Before.DefinitionEvidence.Sha256 -eq 'abc') 'Journal retains absent state and policy mapping evidence.'
                $plan=@(Get-WelaNotificationPlan OneSettings)
                Set-WelaNotificationControls $context $plan
                Assert ($script:writes.Count -eq 1 -and $context.Results[1].Status -eq 'AlreadyCompliant') 'Repeat configuration is idempotent.'
            }
            'dry' { Assert ($report.ExitCode -eq 0 -and $script:writes.Count -eq 0 -and -not (Test-Path $context.BackupPath)) 'Dry-run does not write settings or journal.' }
            'ignored' { Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 1) 'Ignored native write fails verification.' }
            'drift' { Assert ($report.ExitCode -eq 1 -and $context.Results[0].Status -eq 'Overridden') 'Final policy drift fails.' }
            default { Assert ($report.ExitCode -eq 1 -and $script:writes.Count -eq 0) "$scenario must block the write." }
        }
    }
    Reset-Fixture
    $script:product=2; $script:build=20348
    Assert ((Get-WelaNotificationPlan OneSettings).Before.Status -eq 'Supported') 'CIS explicitly includes Server 2022 DC; template and channel still required.'
    $script:build=26100
    $rows=@(Get-WelaNotificationPlan)
    Assert ($rows[0].Status -eq 'Unknown' -and $rows[1].Status -eq 'ChangeRequired') 'Unknown OneSettings applicability cannot hide the independent Security threshold.'
    # Exercise command orchestration with a real runner and stubbed channel writes.
    function Get-WelaNativeChannelPlan { param($Profile) [pscustomobject]@{Channel=$Profile.controls[0].channel} }
    function Set-WelaNativeChannelControls {
        param($Context,$Plan,$Profile,$ValidatePrerequisites)
        Assert ($null -ne $ValidatePrerequisites) 'Shared channel runner must receive the producer prerequisite callback.'
        if ($script:channelPromptDrift) { $script:values.EnableOneSettingsAuditing=0 }
        & $ValidatePrerequisites $Plan[0]
        $script:channelCalls++
    }
    Reset-Fixture; $script:channelCalls=0
    $context=New-FixtureContext -DryRun
    $report=Invoke-WelaNotificationCommand -Action Configure -Control OneSettings -EnablePrivacyChannel -Auto -BackupPath $context.BackupPath
    Assert ($report.ExitCode -eq 0 -and $script:channelCalls -eq 1) 'Explicit channel request follows successful policy write.'
    Reset-Fixture; $script:channelCalls=0; $script:writeError=$true
    $context=New-FixtureContext -DryRun
    $report=Invoke-WelaNotificationCommand -Action Configure -Control OneSettings -EnablePrivacyChannel -Auto -BackupPath $context.BackupPath
    Assert ($report.ExitCode -eq 1 -and $script:channelCalls -eq 0) 'Failed policy must not enable the channel.'
    Reset-Fixture; $script:channelCalls=0; $script:policyDrift=$true
    $context=New-FixtureContext -DryRun
    $resultPath=Join-Path ([IO.Path]::GetTempPath()) ('wela-notification-export-'+[guid]::NewGuid().ToString('N')+'.json')
    $script:cleanup+=$resultPath
    $report=Invoke-WelaNotificationCommand -Action Configure -Control OneSettings -EnablePrivacyChannel -Auto -BackupPath $context.BackupPath -ResultsPath $resultPath
    $export=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    Assert ($report.ExitCode -eq 1 -and $script:channelCalls -eq 0) 'OneSettings drift to zero blocks the dependent channel action.'
    Assert ($export.ExitCode -eq 1 -and @($export.Results | Where-Object Id -eq 'AuditNotifications/PrivacyChannelDependency').Count -eq 1) 'Dependency failure retains final drift results and JSON export.'
    Reset-Fixture; $script:channelCalls=0
    $context=New-FixtureContext -DryRun
    $report=Invoke-WelaNotificationCommand -Action Configure -Control OneSettings -EnablePrivacyChannel -Auto -DryRun -BackupPath $context.BackupPath
    Assert ($report.ExitCode -eq 0 -and $script:channelCalls -eq 1 -and $script:writes.Count -eq 0) 'Dry-run may preview a channel after a policy change that has not been written.'
    Reset-Fixture; $script:channelCalls=0; $script:channelPromptDrift=$true
    $context=New-FixtureContext -DryRun
    $report=Invoke-WelaNotificationCommand -Action Configure -Control OneSettings -EnablePrivacyChannel -Auto -BackupPath $context.BackupPath
    Assert ($report.ExitCode -eq 1 -and $script:channelCalls -eq 0) 'Producer callback blocks policy drift at the shared channel prompt/write boundary.'
    $exe=(Get-Process -Id $PID).Path
    $ErrorActionPreference='Continue'
    try { $output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') configure -Profile wela-2.2.0 -NotificationControl SecurityWarning 2>&1; $code=$LASTEXITCODE } finally { $ErrorActionPreference='Stop' }
    Assert ($code -ne 0 -and ($output -join "`n") -match 'Notification options require') 'Wrong-command options fail before profile mutation.'
    Write-Host "PASS: $script:count notification checks."
    $global:LASTEXITCODE=0
} finally { foreach ($path in $script:cleanup) { if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force } } }
