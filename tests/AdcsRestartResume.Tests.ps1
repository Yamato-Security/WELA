$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$repo/scripts/Configuration.ps1"
. "$repo/scripts/AdcsAuditing.ps1"
. "$repo/scripts/AuditRecovery.ps1"
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/AdcsRestartResume.ps1"
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
$script:count=0;$script:ordinal=0
function Assert($Condition,$Message){if(-not $Condition){throw $Message};$script:count++}
function Rejects($Action,$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message"}
function Clone($Value){ConvertFrom-WelaRecoveryJson ($Value|ConvertTo-Json -Depth 20)}
function Reg($Value,$Type='DWord'){[pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=$Value;Type=$Type}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-ca-resume-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
$source=Get-WelaAdcsSource
$script:base=[pscustomobject]@{Status='Supported';Diagnostic='fixture';CapturedUtc=[DateTime]::UtcNow.ToString('o');Host=[pscustomobject]@{Computer='CAHOST';DnsHostName='CAHOST';Build=20348;UBR=1;Edition='ServerDatacenter';ProductType=3;DomainRole=2;DomainJoined=$false;Domain='WORKGROUP'};Active=(Reg 'CA-A' String);Path='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA-A';CaType=(Reg 3);CertificateHashes=(Reg @('A'*40) MultiString);Certificates=@([pscustomobject]@{Thumbprint=('A'*40);Sha256=('b'*64);Subject='CN=CA-A';SerialNumber='01'});Filter=(Reg 127);Service=[pscustomobject]@{Name='CertSvc';Status='Running';StartMode='Auto';ProcessId=100;StartUtc=[DateTime]::UtcNow.AddHours(-1).ToString('o');Dependents=@()};AuditMask=3;Precedence=(Reg 1)}
$script:context=[pscustomobject]@{Computer='CAHOST';MachineGuid='920a91c5-aa3e-4ea4-a685-bff000e13cde';UserSid='S-1-5-21-1-2-3-1000';UserName='CAHOST\Reader';GroupSids=@('S-1-5-32-544');ElevatedAdministrator=$true;ImpersonationLevel='None'}
$script:writer=(Get-Command Write-WelaAdcsResumeArtifact).ScriptBlock
function Get-WelaAdcsResumeContext {Clone $script:context}
function Get-WelaAdcsSnapshot {Clone $script:current}
function Write-WelaAdcsResumeArtifact {param($Root,$Name,$Text)
    if($script:failArtifact -ceq $Name){throw 'Injected receipt failure'}
    $artifact=&$script:writer $Root $Name $Text
    if($Name -ceq 'pending.json'){$script:pendingSeen=$true;if($script:pendingHook){&$script:pendingHook}}
    $artifact
}
function Restart-WelaAdcsService {
    Assert $script:pendingSeen 'Durable pending receipt precedes every restart.'
    $script:restarts++
    if($script:restartFailure){throw 'Injected restart failure'}
    if(-not $script:silentNoRestart){$script:current.Service.ProcessId=101;$script:current.Service.StartUtc=[DateTime]::UtcNow.ToString('o')}
    if($script:restartHook){&$script:restartHook}
}
function New-Case {
    $script:ordinal++;$case=Join-Path $temp ([string]$script:ordinal);$null=New-Item -ItemType Directory $case
    $journalDir=Join-Path $case 'original';$null=New-Item -ItemType Directory $journalDir
    $script:current=Clone $script:base;$script:restarts=0;$script:pendingSeen=$false;$script:pendingHook=$null;$script:restartHook=$null;$script:restartFailure=$false;$script:silentNoRestart=$false;$script:failArtifact=''
    $prior=Clone $script:base;$prior.Filter=Reg 0
    $target=[pscustomobject]@{Path=$prior.Path;Name='AuditFilter';Service='CertSvc';ActiveCa=$prior.Active.Value;Certificates=$prior.Certificates}
    $desired=[pscustomobject]@{Value=127;Type='DWord';RestartIfChanged=$true}
    $row=[pscustomobject]@{Id='ADCS/Filter';Kind='AdcsAudit';Target=$target;Desired=$desired;Before=$prior;After=$null;Status='Failed';Diagnostic='Injected restart failure';Source=$source}
    $entry=[pscustomobject]@{Version=1;ComputerName='CAHOST';RecordedUtc=[DateTime]::UtcNow.ToString('o');Id=$row.Id;Kind=$row.Kind;Target=$target;Before=$prior;Desired=$desired}
    $report=[pscustomobject]@{Kind='WelaAdcsAuditing';SchemaVersion=1;Action='Configure';Activation='RestartPending';ExitCode=1;PolicyState='PolicyMatches';Source=$source;Results=@($row);Configuration=[pscustomobject]@{DryRun=$false;Results=@($row)};After=(Clone $script:base)}
    $caseInfo=[pscustomobject]@{Root=$case;Journal=(Join-Path $journalDir 'before.jsonl');Results=(Join-Path $case 'original-results.json');Entry=$entry;Report=$report;Plan=$null}
    Save-Case $caseInfo
    $caseInfo
}
function Save-Case($Case){[IO.File]::WriteAllText($Case.Journal,($Case.Entry|ConvertTo-Json -Depth 20 -Compress));[IO.File]::WriteAllText($Case.Results,($Case.Report|ConvertTo-Json -Depth 20))}
function Plan-Case($Case){$Case.Plan=Invoke-WelaAdcsRestartResume -JournalPath $Case.Journal -ResultsPath $Case.Results -OutputPath (Join-Path $Case.Root 'plan');$Case.Plan}
function Resume-Case($Case,[switch]$DryRun){$params=@{Action='Resume';PlanPath=(Join-Path $Case.Root 'plan/plan.json');PlanHash=$Case.Plan.PlanHash};if($DryRun){$params.DryRun=$true}else{$params.AllowRestart=$true;$params.OutputPath=Join-Path $Case.Root 'resume'};Invoke-WelaAdcsRestartResume @params}
try {
    $case=New-Case;$plan=Plan-Case $case
    Assert ($plan.Status -eq 'Planned' -and $plan.PlanHash -cmatch '^[0-9a-f]{64}$' -and $script:restarts -eq 0) 'Plan reviews original evidence without a restart.'
    $dry=Resume-Case $case -DryRun;Assert ($dry.Status -eq 'WouldRestart' -and $script:restarts -eq 0 -and -not (Test-Path (Join-Path $case.Root 'resume'))) 'DryRun changes no service and writes no receipt.'
    $result=Resume-Case $case
    Assert ($result.ExitCode -eq 0 -and $result.Status -eq 'RestartObserved' -and $script:restarts -eq 1 -and $result.ReadyRuleCredit -eq 0 -and $result.EventGeneration -eq 'Unverified') 'One observed restart preserves the explicit event/Sigma limit.'
    Assert ((Get-WelaAdcsStateKey $result.Before Restart) -ceq (Get-WelaAdcsStateKey $result.After Restart)) 'All observed CA settings and service properties survive.'
    foreach($artifact in $result.Artifacts){Assert ((Get-FileHash (Join-Path $result.OutputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Receipt bytes match retained hashes.'}
    Rejects {Resume-Case $case} 'no longer matches';Assert ($script:restarts -eq 1) 'Replaying a successfully resumed plan cannot restart again.'
    foreach($change in @({param($c)$c.Report.Activation='Unverified'},{param($c)$c.Report.Action='Audit'},{param($c)$c.Report.Configuration.DryRun=$true},{param($c)$c.Report.Source=Clone $c.Report.Source;$c.Report.Source.SchemaSha256='0'*64},{param($c)$c.Entry.ComputerName='OTHER'},{param($c)$c.Entry.Desired=Clone $c.Entry.Desired;$c.Entry.Desired.Value=1},{param($c)$c.Report.Results[0].Status='Applied'},{param($c)$c.Report.After.Service.StartUtc=[DateTime]::UtcNow.AddMinutes(-5).ToString('o')})){
        $case=New-Case;&$change $case;Save-Case $case
        Rejects {Plan-Case $case} 'Original|original|journal|source|pending|Pending|failed ADCS/Filter';Assert ($script:restarts -eq 0) 'Invalid historical evidence cannot authorize a restart.'
    }
    foreach($change in @({$script:current.Active.Value='CA-B'},{$script:current.Certificates[0].Sha256='c'*64},{$script:current.Filter=Reg 64},{$script:current.Filter=Reg 127 String},{$script:current.AuditMask=0},{$script:current.Precedence=Reg 1 String},{$script:current.Service.Status='Stopped'},{$script:current.Service.StartMode='Disabled'},{$script:current.Service.Dependents=@([pscustomobject]@{Name='dependent';Status='Running'})},{$script:current.Service.ProcessId=999})){
        $case=New-Case;$null=Plan-Case $case;&$change
        Rejects {Resume-Case $case} 'requires|require|must|matches|CA';Assert ($script:restarts -eq 0) 'Fresh CA/filter/policy/dependency/process drift prevents restart.'
    }
    $case=New-Case;$null=Plan-Case $case
    Rejects {Invoke-WelaAdcsRestartResume -Action Resume -PlanPath (Join-Path $case.Root 'plan/plan.json') -PlanHash $case.Plan.PlanHash -OutputPath (Join-Path $case.Root 'unauthorized')} 'AllowRestart'
    Rejects {Invoke-WelaAdcsRestartResume -Action Resume -PlanPath (Join-Path $case.Root 'plan/plan.json') -PlanHash ('0'*64) -AllowRestart -OutputPath (Join-Path $case.Root 'bad-hash')} 'hash differs'
    $planPath=Join-Path $case.Root 'plan/plan.json';$bad=ConvertFrom-WelaRecoveryJson ([IO.File]::ReadAllText($planPath));$bad|Add-Member NoteProperty Unexpected 'data';[IO.File]::WriteAllText($planPath,($bad|ConvertTo-Json -Depth 20));$case.Plan.PlanHash=(Get-FileHash $planPath).Hash.ToLowerInvariant()
    Rejects {Resume-Case $case} 'independently rebuilt'
    foreach($change in @({$script:current.Service.ProcessId=777},{$script:current.AuditMask=1},{$script:current.Filter=Reg 63},{$script:current.Service.Dependents=@([pscustomobject]@{Name='late';Status='Running'})})){
        $case=New-Case;$null=Plan-Case $case;$script:pendingHook=$change;$result=Resume-Case $case
        Assert ($result.Status -eq 'Refused' -and $result.ExitCode -eq 1 -and -not $result.RestartAttempted -and $script:restarts -eq 0) 'Drift after durable journaling is refused before service mutation.'
    }
    $case=New-Case;$null=Plan-Case $case;$script:failArtifact='pending.json';$result=Resume-Case $case
    Assert ($result.ExitCode -eq 1 -and $script:restarts -eq 0 -and -not $result.RestartAttempted) 'Failed pending receipt prevents restart.'
    foreach($mode in @('fail','silent','drift')){
        $case=New-Case;$null=Plan-Case $case
        switch($mode){'fail'{$script:restartFailure=$true}'silent'{$script:silentNoRestart=$true}'drift'{$script:restartHook={$script:current.Filter=Reg 1}}}
        $result=Resume-Case $case
        Assert ($result.ExitCode -eq 1 -and $result.Status -eq 'RestartAttemptedUnverified' -and $script:restarts -eq 1) 'Restart failure, false success or changed readback remains unverified without rollback.'
    }
    $case=New-Case;[IO.File]::WriteAllText($case.Results,'{"Kind":"WelaAdcsAuditing","kind":"other"}')
    Rejects {Plan-Case $case} 'Duplicate'
    Write-Host "AD CS restart resume: $script:count assertions passed. Service operations mocked."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
