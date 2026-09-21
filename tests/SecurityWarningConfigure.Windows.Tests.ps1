param([switch]$AllowDisposableWarningWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableWarningWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
. (Join-Path $repo 'scripts/Configuration.ps1')
$engine=(Get-Process -Id $PID).Path
$root=Join-Path $env:RUNNER_TEMP ('wela-security-warning-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$path='HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security';$name='WarningLevel'
$count=0;$failure=$null;$cleanupErrors=@()
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 25|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 25 -Compress}
function Masks($Value){@($Value.Keys|Sort-Object|ForEach-Object{"$_=$($Value[$_])"}) -join ';'}
function Warning {Get-WelaRegistryState $path $name}
function Unselected {
    $key=Get-Item -LiteralPath $path
    try{
        $values=@(foreach($n in @($key.GetValueNames()|Sort-Object)){
            if($n -ine $name){[pscustomobject][ordered]@{Name=$n;Type=[string]$key.GetValueKind($n);Value=$key.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}
        })
        $subkeys=@($key.GetSubKeyNames()|Sort-Object)
    }finally{$key.Dispose()}
    [pscustomobject][ordered]@{OtherSecurityValues=$values;SecuritySubkeys=$subkeys;SecurityAcl=(Get-Acl -LiteralPath $path).Sddl;SecurityChannel=Get-WelaNativeChannel Security;ApplicationChannel=Get-WelaNativeChannel Application;OneSettings=Get-WelaRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' EnableOneSettingsAuditing;CrashOnAuditFail=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' CrashOnAuditFail;EventLogService=[string](Get-Service EventLog).Status}
}
function Public([string]$Label,[string[]]$Arguments,[int]$Expected=0){
    $prior=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') audit-notifications @Arguments 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
    $output|Set-Content -LiteralPath (Join-Path $root ($Label+'.txt')) -Encoding UTF8
    Assert ($code -eq $Expected) "Public $Label exited $code, expected $Expected : $output"
}
$before=Warning;$unselected=Unselected;$masks=Get-WelaEffectiveAuditPolicy
Assert $before.KeyExists 'Existing Security registry key is required; fixture never creates/removes it.'
Save 'original.json' @{Warning=$before;Unselected=$unselected;Masks=$masks;Engine=$PSVersionTable.PSVersion.ToString();OS=[Environment]::OSVersion.VersionString}
$base=@('-NotificationControl','SecurityWarning')
try{
    # Remove only the selected value to exercise absence rather than a fabricated default.
    if((Warning).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}
    $seed=Warning
    Public 'plan' ($base+@('-NotificationAction','Plan','-WarningPercent','90','-ResultsPath',(Join-Path $root 'plan.json')))
    $plan=Get-Content (Join-Path $root 'plan.json') -Raw|ConvertFrom-Json
    Assert ($plan.Plan.Count -eq 1 -and $plan.Plan[0].Definition.Id -ceq 'SecurityWarning' -and $plan.Plan[0].Desired -eq 90 -and -not $plan.Plan[0].Before.Policy.ValueExists) 'Public Plan retains actual absence and exactly one selected control.'
    $dryBackup=Join-Path $root 'dry-backup'
    Public 'dry' ($base+@('-NotificationAction','Configure','-WarningPercent','90','-Auto','-DryRun','-BackupPath',$dryBackup,'-ResultsPath',(Join-Path $root 'dry.json')))
    $dry=Get-Content (Join-Path $root 'dry.json') -Raw|ConvertFrom-Json
    Assert ($dry.ExitCode -eq 0 -and $dry.DryRun -and $dry.Results[0].Status -ceq 'Skipped' -and -not(Test-Path $dryBackup)) 'Public dry run reports a skipped proposal and creates no journal.'
    Assert ((Key (Warning)) -ceq (Key $seed) -and (Key (Unselected)) -ceq (Key $unselected) -and (Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $masks)) 'Plan/DryRun preserve the selected absence, unrelated native state and all59 masks.'
    $cases=@(
        @{Id='absent';Before=$null;Maximum=90;Desired=90;Status='Applied'},
        @{Id='zero';Before=0;Maximum=80;Desired=80;Status='Applied'},
        @{Id='higher';Before=95;Maximum=70;Desired=70;Status='Applied'},
        @{Id='earlier';Before=25;Maximum=90;Desired=25;Status='AlreadyCompliant'}
    )
    foreach($case in $cases){
        if($null -ne $case.Before){$null=New-ItemProperty -LiteralPath $path -Name $name -Value $case.Before -PropertyType DWord -Force}
        $prior=Warning;$backup=Join-Path $root ($case.Id+'-backup');$results=Join-Path $root ($case.Id+'.json')
        Public $case.Id ($base+@('-NotificationAction','Configure','-WarningPercent',[string]$case.Maximum,'-Auto','-BackupPath',$backup,'-ResultsPath',$results))
        $report=Get-Content $results -Raw|ConvertFrom-Json;$after=Warning
        Assert ($report.ExitCode -eq 0 -and $report.Scope -ceq 'audit-notifications' -and $report.Results.Count -eq 1 -and $report.Results[0].Status -ceq $case.Status) 'Each selected native case has one accurate result and narrow scope.'
        Assert ($after.Type -ceq 'DWord' -and $after.Value -eq $case.Desired -and $report.Current[0].Before.Policy.Value -eq $case.Desired) 'Native DWORD readback and public current state match the exact intended threshold.'
        Assert ($report.PrivacyChannelPlan.Count -eq 0 -and $report.EventGeneration -match 'Not verified') 'No privacy-channel operation or warning event claim is implied.'
        $journalPath=Join-Path $backup 'before.jsonl'
        if($case.Status -eq 'Applied'){
            $journal=@(Get-Content $journalPath|ConvertFrom-Json)
            Assert ($journal.Count -eq 1 -and $journal[0].Target.Name -ceq $name -and $journal[0].Target.Path -ceq $path -and (Key $journal[0].Before.Policy) -ceq (Key $prior)) 'The one native change has exact typed original journal evidence.'
            Assert ((Key $report.Results[0].Before.Policy) -ceq (Key $prior) -and (Key $report.Results[0].After.Policy) -ceq (Key $after)) 'Applied result binds exact native before and after policy.'
        }else{Assert (-not(Test-Path $journalPath)) 'An earlier existing warning is preserved without a write journal.'}
        Assert ((Key (Unselected)) -ceq (Key $unselected) -and (Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $masks)) 'Each public Configure preserves siblings, ACL, channels, service, audit masks, OneSettings and CrashOnAuditFail.'
    }
    $repeatPath=Join-Path $root 'repeat.json';$repeatBackup=Join-Path $root 'repeat-backup'
    Public 'repeat' ($base+@('-NotificationAction','Configure','-WarningPercent','90','-Auto','-BackupPath',$repeatBackup,'-ResultsPath',$repeatPath))
    $repeat=Get-Content $repeatPath -Raw|ConvertFrom-Json
    Assert ($repeat.Results[0].Status -ceq 'AlreadyCompliant' -and (Warning).Value -eq 25 -and -not(Test-Path (Join-Path $repeatBackup 'before.jsonl'))) 'Repeated Configure is idempotent and preserves the earlier threshold.'
    # Fixture-owned wrong type must remain wrong rather than being coerced and overwritten.
    Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
    $null=New-ItemProperty -LiteralPath $path -Name $name -Value 'fixture-not-a-dword' -PropertyType String
    $invalid=Warning;$invalidPath=Join-Path $root 'invalid.json';$invalidBackup=Join-Path $root 'invalid-backup'
    Public 'invalid' ($base+@('-NotificationAction','Configure','-WarningPercent','90','-Auto','-BackupPath',$invalidBackup,'-ResultsPath',$invalidPath)) 1
    $refused=Get-Content $invalidPath -Raw|ConvertFrom-Json
    Assert ($refused.ExitCode -eq 1 -and $refused.Results[0].Status -ceq 'Failed' -and (Key (Warning)) -ceq (Key $invalid) -and -not(Test-Path (Join-Path $invalidBackup 'before.jsonl'))) 'Actual wrong type yields failure and is preserved without a native write journal.'
    Save 'completed.json' @{Status='Passed';Assertions=$count;Scope='Actual named policy configuration only. No warning generation, log exhaustion, retention changes, GPO refresh, ingestion or Sigma proof.'}
}catch{$failure=$_.ToString();throw}finally{
    try{
        if((Warning).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}
        if($before.ValueExists){$null=New-ItemProperty -LiteralPath $path -Name $name -Value $before.Value -PropertyType $before.Type}
    }catch{$cleanupErrors+=$_.ToString()}
    $warningOk=$false;$otherOk=$false;$masksOk=$false
    try{$warningOk=(Key (Warning)) -ceq (Key $before);$otherOk=(Key (Unselected)) -ceq (Key $unselected);$masksOk=(Masks (Get-WelaEffectiveAuditPolicy)) -ceq (Masks $masks)}catch{$cleanupErrors+=$_.ToString()}
    Save 'cleanup.json' @{Failure=$failure;Errors=$cleanupErrors;WarningRestored=$warningOk;UnselectedPreserved=$otherOk;All59MasksPreserved=$masksOk;Complete=($warningOk -and $otherOk -and $masksOk -and -not $cleanupErrors.Count)}
    if(-not $warningOk -or -not $otherOk -or -not $masksOk -or $cleanupErrors.Count){throw 'Native warning fixture cleanup failed; inspect retained evidence.'}
}
Write-Host "PASS: $count native public Security warning assertions and exact cleanup."
exit 0
