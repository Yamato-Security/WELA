# Resume only a reviewed, still-running CA instance recorded as RestartPending.
function Get-WelaAdcsResumeSources {
    $root=Split-Path $PSScriptRoot -Parent
    $items=foreach($name in @('WELA.ps1','scripts/AdcsAuditing.ps1','scripts/AdcsRestartResume.ps1','scripts/Configuration.ps1','scripts/AuditRecovery.ps1','scripts/WefArrival.ps1','modules/AuditProfiles.psm1','config/audit_profiles.json')) {
        [pscustomobject][ordered]@{Name=$name;Sha256=(Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
    @($items)
}
function Read-WelaAdcsResumeFile {
    param([string]$Path)
    $full=Resolve-WelaArrivalPath $Path
    $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -lt 1 -or $stream.Length -gt 4194304){throw 'AD CS resume input must contain 1 byte to 4 MiB.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($read -eq 0){throw 'AD CS resume input ended early.'};$offset+=$read}
        if($stream.Length -ne $bytes.Length){throw 'AD CS resume input length changed.'}
        [pscustomobject][ordered]@{Path=$full;Sha256=(Get-WelaArrivalHash $bytes);Text=([Text.UTF8Encoding]::new($false,$true)).GetString($bytes).TrimStart([char]0xfeff)}
    }finally{$stream.Dispose()}
}
function Get-WelaAdcsResumeContext {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'AD CS resume requires native 64-bit Windows.'}
    $machine=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid
    $guid=[guid]::Empty
    if(-not $machine.ValueExists -or $machine.Type -cne 'String' -or -not [guid]::TryParse([string]$machine.Value,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Actual machine identity is unavailable.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if($identity.ImpersonationLevel -ne [Security.Principal.TokenImpersonationLevel]::None -or -not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'AD CS resume requires a non-impersonated elevated administrator.'}
        [pscustomobject][ordered]@{Computer=[Environment]::MachineName;MachineGuid=$guid.ToString();UserSid=$identity.User.Value;UserName=$identity.Name;GroupSids=@($identity.Groups.Value|Sort-Object);ElevatedAdministrator=$true;ImpersonationLevel=[string]$identity.ImpersonationLevel}
    }finally{$identity.Dispose()}
}
function Assert-WelaAdcsResumeState {
    param($State)
    Assert-WelaAdcsPrerequisites $State
    if(-not (Test-WelaAdcsControl $State Filter) -or @($State.Service.Dependents|Where-Object Status -ne 'Stopped').Count){throw 'Resume requires AuditFilter DWORD127 and no running dependent services.'}
    $null=ConvertTo-WelaArrivalUtc $State.Service.StartUtc
    if($State.Service.ProcessId -le 0){throw 'Running CA process identity is unavailable.'}
}
function New-WelaAdcsResumePlan {
    param([string]$JournalPath,[string]$ResultsPath)
    $source=Get-WelaAdcsSource
    $journal=Read-WelaAdcsResumeFile $JournalPath;$results=Read-WelaAdcsResumeFile $ResultsPath
    $report=ConvertFrom-WelaRecoveryJson $results.Text
    if($report.Kind -cne 'WelaAdcsAuditing' -or ($report.SchemaVersion -isnot [int] -and $report.SchemaVersion -isnot [long]) -or $report.SchemaVersion -ne 1 -or $report.Action -cne 'Configure' -or $report.Activation -cne 'RestartPending' -or ($report.ExitCode -isnot [int] -and $report.ExitCode -isnot [long]) -or $report.ExitCode -ne 1 -or $report.PolicyState -cne 'PolicyMatches' -or $report.Configuration.DryRun -isnot [bool] -or $report.Configuration.DryRun -or $report.Results -isnot [array]){throw 'Original dedicated AD CS results must record a failed, non-dry-run Configure with RestartPending and matching policy.'}
    foreach($name in @('Id','SchemaSha256','AuditGuid','AuditMask','AuditMode','Precedence','AuditFilter','SourceUrl')){
        if((Get-WelaRecoveryKey $report.Source.$name) -cne (Get-WelaRecoveryKey $source.$name)){throw "Original AD CS source differs: $name"}
    }
    if((Get-WelaRecoveryKey $report.Results) -cne (Get-WelaRecoveryKey $report.Configuration.Results)){throw 'Original AD CS result copies disagree.'}
    $rows=@($report.Results|Where-Object Id -ceq 'ADCS/Filter')
    if($rows.Count -ne 1 -or $rows[0].Kind -cne 'AdcsAudit' -or $rows[0].Status -cne 'Failed'){throw 'One failed ADCS/Filter result is required.'}
    $row=$rows[0]
    $entries=@($journal.Text -split '\r?\n'|Where-Object {$_ -match '\S'}|ForEach-Object {ConvertFrom-WelaRecoveryJson $_})
    if($entries.Count -lt 1 -or $entries.Count -gt 3){throw 'A dedicated AD CS journal must contain 1..3 entries.'}
    $seen=@{}
    foreach($entry in $entries){
        if(($entry.Version -isnot [int] -and $entry.Version -isnot [long]) -or $entry.Version -ne 1 -or $entry.Kind -cne 'AdcsAudit' -or $entry.Id -cnotin @('ADCS/Precedence','ADCS/AuditMask','ADCS/Filter') -or $seen.ContainsKey($entry.Id) -or $entry.ComputerName -ine $report.After.Host.Computer){throw 'Unexpected, duplicate or wrong-host AD CS journal entry.'}
        $seen[$entry.Id]=$entry
        $time=ConvertTo-WelaArrivalUtc $entry.RecordedUtc
        if($time -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'AD CS journal timestamp is in the future.'}
    }
    if(-not $seen.ContainsKey('ADCS/Filter')){throw 'The original filter journal entry is missing.'}
    $filter=$seen['ADCS/Filter']
    foreach($name in @('Before','Target','Desired')){
        if((Get-WelaRecoveryKey $filter.$name) -cne (Get-WelaRecoveryKey $row.$name)){throw "Original journal/result $name mismatch."}
    }
    if($filter.Target.Path -cne $filter.Before.Path -or $filter.Target.Name -cne 'AuditFilter' -or $filter.Target.Service -cne 'CertSvc' -or $filter.Target.ActiveCa -cne $filter.Before.Active.Value -or (Get-WelaRecoveryKey $filter.Target.Certificates) -cne (Get-WelaRecoveryKey $filter.Before.Certificates) -or
        $filter.Desired.Type -cne 'DWord' -or $filter.Desired.Value -ne 127 -or $filter.Desired.RestartIfChanged -isnot [bool] -or -not $filter.Desired.RestartIfChanged){throw 'Original journal does not select this CA filter and authorized restart.'}
    Assert-WelaAdcsPrerequisites $filter.Before
    $prior=$filter.Before.Filter
    if($prior.KeyExists -isnot [bool] -or -not $prior.KeyExists -or $prior.ValueExists -isnot [bool] -or
        ($prior.ValueExists -and ($prior.Type -cne 'DWord' -or ($prior.Value -isnot [int] -and $prior.Value -isnot [long]) -or $prior.Value -lt 0 -or $prior.Value -ge 127)) -or
        (-not $prior.ValueExists -and ($null -ne $prior.Value -or $null -ne $prior.Type))){throw 'Original filter state does not demonstrate a supported change to 127.'}
    Assert-WelaAdcsResumeState $report.After
    if((Get-WelaAdcsStateKey $filter.Before Filter) -cne (Get-WelaAdcsStateKey $report.After Filter)){throw 'Pending evidence contains CA, certificate, prerequisite or service drift.'}
    $context=Get-WelaAdcsResumeContext
    $actual=Get-WelaAdcsSnapshot;Assert-WelaAdcsResumeState $actual
    if($context.Computer -ine $actual.Host.Computer -or (Get-WelaAdcsStateKey $actual) -cne (Get-WelaAdcsStateKey $report.After)){throw 'Current CA no longer matches the recorded pending instance; review it instead of replaying a restart.'}
    $last=Get-WelaAdcsSnapshot;Assert-WelaAdcsResumeState $last
    if((Get-WelaAdcsStateKey $last) -cne (Get-WelaAdcsStateKey $actual)){throw 'CA changed during restart planning.'}
    [pscustomobject][ordered]@{Kind='WelaAdcsRestartPlan';SchemaVersion=1;Journal=[pscustomobject]@{Path=$journal.Path;Sha256=$journal.Sha256};OriginalResults=[pscustomobject]@{Path=$results.Path;Sha256=$results.Sha256};SourceId=$source.Id;Context=$context;Expected=$report.After;Sources=@(Get-WelaAdcsResumeSources);ReadyRuleCredit=0;Scope='Resume one still-running recorded CA after AuditFilter write; no registry, audit-policy, dependent-service or certificate changes. Hashes establish consistency, not authorship.'}
}
function Write-WelaAdcsResumeArtifact {
    param([string]$Root,[string]$Name,[string]$Text)
    $null=Resolve-WelaArrivalPath $Root
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    if($bytes.Length -gt 4194304){throw 'AD CS resume artifact exceeds four MiB.'}
    $stream=[IO.File]::Open((Join-Path $Root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true);$stream.Position=0;$hash=[Security.Cryptography.SHA256]::Create();try{$readback=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}}finally{$stream.Dispose()}
    if($readback -cne (Get-WelaArrivalHash $bytes)){throw 'AD CS resume artifact readback differs.'}
    [pscustomobject]@{Name=$Name;Sha256=$readback;Bytes=$bytes.Length}
}
function Assert-WelaAdcsResumeFresh {
    param($Plan,[string]$PlanPath,[string]$PlanHash)
    if((Read-WelaAdcsResumeFile $PlanPath).Sha256 -cne $PlanHash){throw 'Reviewed restart plan changed.'}
    if((Get-WelaRecoveryKey @(Get-WelaAdcsResumeSources)) -cne (Get-WelaRecoveryKey $Plan.Sources)){throw 'Restart implementation or source profile changed.'}
    if((Read-WelaAdcsResumeFile $Plan.Journal.Path).Sha256 -cne $Plan.Journal.Sha256 -or (Read-WelaAdcsResumeFile $Plan.OriginalResults.Path).Sha256 -cne $Plan.OriginalResults.Sha256){throw 'Original restart evidence changed.'}
    if((Get-WelaRecoveryKey (Get-WelaAdcsResumeContext)) -cne (Get-WelaRecoveryKey $Plan.Context)){throw 'Actual restart operator or machine identity changed.'}
    $current=Get-WelaAdcsSnapshot;Assert-WelaAdcsResumeState $current
    if((Get-WelaAdcsStateKey $current) -cne (Get-WelaAdcsStateKey $Plan.Expected)){throw 'Current CA drifted from the reviewed pending instance.'}
    $current
}
function Invoke-WelaAdcsRestartResume {
    param([ValidateSet('Plan','Resume')][string]$Action='Plan',[string]$JournalPath,[string]$ResultsPath,[string]$PlanPath,[string]$PlanHash,[string]$OutputPath,[switch]$AllowRestart,[switch]$DryRun)
    $ErrorActionPreference='Stop'
    if($Action -eq 'Plan'){
        if(-not $JournalPath -or -not $ResultsPath -or -not $OutputPath -or $PlanPath -or $PlanHash -or $AllowRestart -or $DryRun){throw 'Restart Plan requires JournalPath, ResultsPath and a new OutputPath only.'}
        $plan=New-WelaAdcsResumePlan $JournalPath $ResultsPath
        $output=New-WelaArrivalOutput $OutputPath ([IO.Path]::GetDirectoryName($plan.Journal.Path))
        $artifact=Write-WelaAdcsResumeArtifact $output 'plan.json' ($plan|ConvertTo-Json -Depth 20)
        return [pscustomobject]@{Status='Planned';ExitCode=0;OutputPath=$output;PlanHash=$artifact.Sha256;Plan=$plan;ReadyRuleCredit=0}
    }
    if($JournalPath -or $ResultsPath -or -not $PlanPath -or $PlanHash -cnotmatch '^[0-9a-f]{64}$' -or (-not $DryRun -and (-not $AllowRestart -or -not $OutputPath)) -or ($DryRun -and $OutputPath)){throw 'Resume requires a reviewed PlanPath and exact PlanHash; execution additionally requires AllowRestart and a new OutputPath. DryRun writes no files.'}
    $inputFile=Read-WelaAdcsResumeFile $PlanPath
    if($inputFile.Sha256 -cne $PlanHash){throw 'Reviewed restart plan hash differs.'}
    $plan=ConvertFrom-WelaRecoveryJson $inputFile.Text
    if($plan.Kind -cne 'WelaAdcsRestartPlan' -or $plan.SchemaVersion -ne 1){throw 'Unsupported restart plan.'}
    $rebuilt=New-WelaAdcsResumePlan $plan.Journal.Path $plan.OriginalResults.Path
    if((Get-WelaRecoveryKey $rebuilt) -cne (Get-WelaRecoveryKey $plan)){throw 'Restart plan differs from independently rebuilt evidence and current context.'}
    $before=Assert-WelaAdcsResumeFresh $plan $inputFile.Path $PlanHash
    if($DryRun){return [pscustomobject]@{Status='WouldRestart';ExitCode=0;Before=$before;ReadyRuleCredit=0}}
    $output=New-WelaArrivalOutput $OutputPath ([IO.Path]::GetDirectoryName($inputFile.Path))
    $artifacts=New-Object 'System.Collections.Generic.List[object]'
    $result=[pscustomobject][ordered]@{Kind='WelaAdcsRestartResult';SchemaVersion=1;Status='Refused';ExitCode=1;OutputPath=$output;PlanHash=$PlanHash;Before=$before;After=$null;RestartAttempted=$false;StartedUtc=$null;FinishedUtc=$null;Diagnostic='';ReadyRuleCredit=0;EventGeneration='Unverified';Artifacts=@()}
    try {
        $artifacts.Add((Write-WelaAdcsResumeArtifact $output 'reviewed-plan.json' $inputFile.Text))
        $pending=[pscustomobject]@{Kind='WelaAdcsRestartPending';PlanHash=$PlanHash;Before=$before;RecordedUtc=[DateTime]::UtcNow.ToString('o');Scope='Intent receipt only; no restart or ownership claim.'}
        $artifacts.Add((Write-WelaAdcsResumeArtifact $output 'pending.json' ($pending|ConvertTo-Json -Depth 20)))
        $null=Assert-WelaAdcsResumeFresh $plan $inputFile.Path $PlanHash
        $result.StartedUtc=[DateTime]::UtcNow.ToString('o');$result.RestartAttempted=$true
        Restart-WelaAdcsService
        $after=Get-WelaAdcsSnapshot;$result.After=$after;Assert-WelaAdcsResumeState $after
        if((Get-WelaAdcsStateKey $before Restart) -cne (Get-WelaAdcsStateKey $after Restart) -or (ConvertTo-WelaArrivalUtc $after.Service.StartUtc) -le (ConvertTo-WelaArrivalUtc $before.Service.StartUtc) -or (ConvertTo-WelaArrivalUtc $after.Service.StartUtc) -lt (ConvertTo-WelaArrivalUtc $result.StartedUtc).AddSeconds(-1)){throw 'A newer CA process with preserved identity, settings and service state was not verified.'}
        if((Get-WelaRecoveryKey (Get-WelaAdcsResumeContext)) -cne (Get-WelaRecoveryKey $plan.Context) -or (Get-WelaRecoveryKey @(Get-WelaAdcsResumeSources)) -cne (Get-WelaRecoveryKey $plan.Sources)){throw 'Operator, host or implementation changed during restart.'}
        if((Read-WelaAdcsResumeFile $inputFile.Path).Sha256 -cne $PlanHash -or (Read-WelaAdcsResumeFile $plan.Journal.Path).Sha256 -cne $plan.Journal.Sha256 -or (Read-WelaAdcsResumeFile $plan.OriginalResults.Path).Sha256 -cne $plan.OriginalResults.Sha256){throw 'Reviewed plan or original evidence changed during restart.'}
        $final=Get-WelaAdcsSnapshot;Assert-WelaAdcsResumeState $final
        if((Get-WelaAdcsStateKey $final) -cne (Get-WelaAdcsStateKey $after)){throw 'Final CA state drifted after restart.'}
        $result.After=$final;$result.Status='RestartObserved';$result.ExitCode=0
    }catch{$result.Status=if($result.RestartAttempted){'RestartAttemptedUnverified'}else{'Refused'};$result.Diagnostic=$_.Exception.Message}
    $result.FinishedUtc=[DateTime]::UtcNow.ToString('o');$result.Artifacts=@($artifacts.ToArray())
    $null=Write-WelaAdcsResumeArtifact $output 'result.json' ($result|ConvertTo-Json -Depth 20)
    $result
}
