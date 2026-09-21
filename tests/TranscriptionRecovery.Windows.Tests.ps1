param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){Write-Host 'Skipped: actual Windows transcription recovery requires Windows.';exit 0}
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'This native mutation fixture requires explicit consent on a disposable GitHub-hosted runner.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
foreach($file in @('Configuration','AuditRecovery','PowerShellTranscription','TranscriptionRecovery')){. (Join-Path $script:ScriptRoot ('scripts/'+$file+'.ps1'))}
$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
$root=New-WelaRecoveryOutput (Join-Path $env:RUNNER_TEMP ('wela-transcription-recovery-'+[guid]::NewGuid().ToString('N')))
$before=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))
$protectedBefore=Get-WelaTranscriptRecoveryProtectedPolicy
Write-WelaRecoveryArtifact (Join-Path $root 'original-policy.json') $before
Write-WelaRecoveryArtifact (Join-Path $root 'original-protected-policy.json') $protectedBefore
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
$policyRoot='SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$originalParents=@{}
foreach($path in @($policyRoot,($policyRoot+'\Transcription'))){$key=$base.OpenSubKey($path);$originalParents[$path]=($null -ne $key);if($key){$key.Dispose()}}
$base.Dispose()
$hostExe=Join-Path $PSHOME $(if($PSVersionTable.PSEdition -eq 'Desktop'){'powershell.exe'}else{'pwsh.exe'})
$native51=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
$restored=$false;$touched=$false
function Set-FixtureValue([string]$Name,$Value,[string]$Type='DWord') {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$base.CreateSubKey($policyRoot+'\Transcription')
    try{if($null -eq $Value){$key.DeleteValue($Name,$false)}else{$key.SetValue($Name,$Value,[Microsoft.Win32.RegistryValueKind]$Type)};$key.Flush()}finally{$key.Dispose();$base.Dispose()}
}
function Invoke-WelaTranscriptFixtureCli {
    param([string[]]$Parameters,[string]$Log,[switch]$ExpectFailure)
    $global:LASTEXITCODE=$null
    $priorPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        & $hostExe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:ScriptRoot 'WELA.ps1') @Parameters *> $Log
        $code=$global:LASTEXITCODE
    } finally {$ErrorActionPreference=$priorPreference}
    if($ExpectFailure){Assert ($null -ne $code -and $code -ne 0) 'native public CLI refuses unsupported or stale recovery'}
    elseif($code -ne 0){throw "Public CLI failed ($code): $(Get-Content $Log -Raw)"}
    $global:LASTEXITCODE=0
}
try {
    foreach($scenario in @('Enabled','DisabledAbsentDirectory','AbsentEnablement','Drift')) {
        $case=New-WelaRecoveryOutput (Join-Path $root $scenario)
        $old=New-WelaRecoveryOutput (Join-Path $case 'old-transcripts')
        $new=New-WelaRecoveryOutput (Join-Path $case 'new-transcripts')
        $touched=$true
        Set-FixtureValue EnableTranscripting 0
        Set-FixtureValue OutputDirectory $(if($scenario -eq 'DisabledAbsentDirectory'){$null}else{$old}) String
        Set-FixtureValue EnableTranscripting $(if($scenario -eq 'AbsentEnablement'){$null}elseif($scenario -eq 'DisabledAbsentDirectory'){0}else{1})
        $caseBefore=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))
        $preserved=Get-WelaTranscriptRecoveryProtectedPolicy
        Write-WelaRecoveryArtifact (Join-Path $case 'fixture-before.json') $caseBefore
        $backup=Join-Path $case 'configure-backup';$original=Join-Path $case 'configure-result.json'
        Invoke-WelaTranscriptFixtureCli @('powershell-transcription','-TranscriptionAction','Configure','-TranscriptDirectory',$new,'-Auto','-BackupPath',$backup,'-ResultsPath',$original) (Join-Path $case 'configure.log')
        $configured=ConvertFrom-WelaRecoveryJson (Get-Content $original -Raw)
        Assert ($configured.Results.Count -eq 1 -and $configured.Results[0].Status -eq 'Applied') 'actual public Configure creates the exact completed composite history'
        $planDirectory=Join-Path $case 'plan';$planPath=Join-Path $planDirectory 'plan.json'
        Invoke-WelaTranscriptFixtureCli @('transcription-recovery','-TranscriptRecoveryJournalPath',(Join-Path $backup 'before.jsonl'),'-TranscriptRecoveryOriginalResultsPath',$original,'-TranscriptRecoveryOutputPath',$planDirectory) (Join-Path $case 'plan.log')
        $plan=ConvertFrom-WelaRecoveryJson (Get-Content $planPath -Raw)
        $planHash=(Get-FileHash $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert ($plan.Context.Reader.UserSid -and $plan.Sources.'scripts/TranscriptionRecovery.ps1' -and $plan.SigmaEvtxCredit -eq 0) 'native plan binds reader/code and grants no EVTX credit'
        $restoreDirectory=Join-Path $case 'restore'
        $restoreArguments=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-TranscriptRecoveryPlanPath',$planPath,'-TranscriptRecoveryPlanHash',$planHash,'-TranscriptRecoveryOutputPath',$restoreDirectory,'-Auto')
        if($scenario -eq 'Drift') {
            Set-FixtureValue EnableTranscripting 0
            Invoke-WelaTranscriptFixtureCli ($restoreArguments+@('-TranscriptRecoveryAllowTemporarySuspension')) (Join-Path $case 'drift-refusal.log') -ExpectFailure
            Assert (-not (Test-Path $restoreDirectory) -and (Get-WelaTranscriptRegistryValue -Name EnableTranscripting).Value -eq 0) 'actual changed native policy is preserved before any output/write'
            continue
        }
        if($plan.RequiresTemporarySuspension) {
            Invoke-WelaTranscriptFixtureCli $restoreArguments (Join-Path $case 'consent-refusal.log') -ExpectFailure
            Assert (-not (Test-Path $restoreDirectory) -and (Get-WelaTranscriptRegistryValue -Name EnableTranscripting).Value -eq 1) 'no suspension consent preserves the enabled policy'
            $restoreArguments += '-TranscriptRecoveryAllowTemporarySuspension'
        }
        $previewArguments=@('transcription-recovery','-TranscriptRecoveryAction','Restore','-TranscriptRecoveryPlanPath',$planPath,'-TranscriptRecoveryPlanHash',$planHash,'-DryRun')
        if($plan.RequiresTemporarySuspension){$previewArguments += '-TranscriptRecoveryAllowTemporarySuspension'}
        Invoke-WelaTranscriptFixtureCli $previewArguments (Join-Path $case 'preview.log')
        Assert ((Get-WelaRecoveryKey @(Get-WelaTranscriptPolicy @('Registry64','Registry32'))) -ceq (Get-WelaRecoveryKey $plan.ExpectedPolicy)) 'actual public preview leaves both native registry views unchanged'
        Invoke-WelaTranscriptFixtureCli $restoreArguments (Join-Path $case 'restore.log')
        $report=ConvertFrom-WelaRecoveryJson (Get-Content (Join-Path $restoreDirectory 'result.json') -Raw)
        Assert ($report.Status -eq 'Restored' -and $report.ExitCode -eq 0) 'actual public Restore completes'
        Assert ((Get-WelaRecoveryKey @(Get-WelaTranscriptPolicy @('Registry64','Registry32'))) -ceq (Get-WelaRecoveryKey $caseBefore)) 'native restore matches original typed policy including value absence in both views'
        Assert ((Get-WelaRecoveryKey (Get-WelaTranscriptRecoveryProtectedPolicy)) -ceq (Get-WelaRecoveryKey $preserved)) 'all other machine/user PowerShell policy remains exact'
        $pending=@(Get-ChildItem $restoreDirectory '*-pending.json');$confirmed=@(Get-ChildItem $restoreDirectory '*-confirmed.json')
        Assert ($pending.Count -eq $plan.Steps.Count -and $confirmed.Count -eq $plan.Steps.Count) 'every actual native write has separate durable pending and confirmed receipts'
        if($scenario -eq 'Enabled') {
            $marker='WELA_RECOVERED_TRANSCRIPT_'+[guid]::NewGuid().ToString('N')
            & $native51 -NoLogo -NoProfile -Command "Write-Output '$marker'" *> (Join-Path $case 'benign-session.log')
            Assert ($LASTEXITCODE -eq 0) 'fresh built-in Windows PowerShell session completes after recovery'
            $matching=@(Get-ChildItem -LiteralPath $old -Recurse -File -Filter '*.txt'|Where-Object {(Get-Content $_.FullName -Raw).Contains($marker)})
            Assert ($matching.Count -eq 1) 'one real fresh Windows PowerShell transcript contains the benign marker at the restored destination'
            Write-WelaRecoveryArtifact (Join-Path $case 'transcript-marker.json') ([pscustomobject]@{Marker=$marker;Path=$matching[0].FullName;Sha256=(Get-FileHash $matching[0].FullName).Hash;Scope='Disposable local fixture only; no production/central assertion'})
        }
    }
} finally {
    if($touched) {
        Set-FixtureValue EnableTranscripting 0
        foreach($name in @('OutputDirectory','EnableInvocationHeader','EnableTranscripting')) {
            $value=$before[0].Machine.$name
            Set-FixtureValue $name $(if($value.ValueExists){$value.Value}else{$null}) $(if($value.ValueExists){$value.Type}else{'DWord'})
        }
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        try {
            foreach($path in @(($policyRoot+'\Transcription'),$policyRoot)) {
                if($originalParents[$path]){continue}
                $key=$base.OpenSubKey($path)
                $empty=$null -ne $key -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0
                if($key){$key.Dispose()};if($empty){$base.DeleteSubKey($path,$false)}
            }
        } finally {$base.Dispose()}
    }
    $after=@(Get-WelaTranscriptPolicy @('Registry64','Registry32'))
    $restored=(Get-WelaRecoveryKey $after) -ceq (Get-WelaRecoveryKey $before) -and (Get-WelaRecoveryKey (Get-WelaTranscriptRecoveryProtectedPolicy)) -ceq (Get-WelaRecoveryKey $protectedBefore)
    Write-WelaRecoveryArtifact (Join-Path $root 'cleanup.json') ([pscustomobject]@{CleanupVerified=$restored;Checks=$script:checks;Engine=$PSVersionTable.PSVersion.ToString();Computer=$env:COMPUTERNAME;After=$after})
    if(-not $restored){throw "Exact native policy cleanup failed; retained private evidence at $root"}
}
Write-Host "Passed $script:checks actual native transcription recovery assertions; exact policy cleanup verified. Evidence: $root"
