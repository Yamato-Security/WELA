$ErrorActionPreference='Stop';$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -Force
foreach($name in @('WefArrival','EvtxRecovery','WecUpdate','TargetedSaclPlanning','SelectedSaclConfiguration','RegistrySaclRecovery')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Throws($Action,$Pattern){$message='';try{&$Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function Clone($Value){ConvertFrom-WelaEvtxJson (ConvertTo-Json -InputObject $Value -Depth 32)}
function Save($Path,$Value){[IO.File]::WriteAllText($Path,(ConvertTo-Json -InputObject $Value -Depth 32),[Text.UTF8Encoding]::new($false))}
function Get-WelaSelectedSaclContext {[pscustomobject]@{Computer='fixture';Role='Client';Build=26100;Detail=[pscustomobject]@{UBR=1};Key='fixture-context'}}
$script:policies=@{};foreach($row in (Import-WelaAuditProfiles).catalog){$script:policies[$row.guid]=3}
function Get-WelaEffectiveAuditPolicy {$script:policies}
function Get-WelaAuditPrecedenceState {[pscustomobject]@{Registry=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1}}}
function Get-WelaSaclUserInventory {[pscustomobject]@{Users=@();Complete=$true;Diagnostics=@()}}
function Get-WelaSaclTargetObservation {throw 'Unselected targets must not be observed.'}
$catalog=Get-WelaSelectedSaclCatalog -Profile wela-2.2.0 -IncludeOptional -Context (Get-WelaSelectedSaclContext)
$fixtureSelection=@($catalog.Rows|Where-Object {$_.Definition.Scope -ceq 'registry'})[0]
$nativePath=Resolve-WelaSelectedSaclNativePath $fixtureSelection.Definition
$script:before=[pscustomobject]@{Path=$nativePath;Kind='Registry';Identity=($nativePath+':1000');IsDirectory=$false;DescriptorBase64='YmVmb3Jl';Owner='S-1-5-18';Group='S-1-5-18';DaclBase64='ZGFjbA==';ControlFlags=32788;SecurityInformation=511;DescriptorScope='WinSDK-defined sections 0x1ff; future sections unobserved';Aces=@([pscustomobject]@{Binary='b3RoZXI=';Type=2;Flags=64;Mask=1;Sid='S-1-5-18';Ordinary=$true})}
$script:after=$null;$script:current=$null;$script:scenario='';$script:mutations=0
function Get-WelaSelectedSaclSnapshot {param($Definition) if($Definition.Path -cne $fixtureSelection.Definition.Path){throw 'Unselected target read.'};Clone $script:current}
function Get-WelaSelectedSaclChildNames {param($Definition,$Snapshot,$Maximum) [pscustomobject]@{Names=@();Truncated=$false}}
function Write-WelaSelectedSaclNative {
    param($Definition,$Before,$Ace)
    $script:current=Clone $Before;$script:current.Identity=$nativePath+':1001';$script:current.DescriptorBase64='YWZ0ZXI='
    $script:current.Aces+=@([pscustomobject]@{Binary='YWRkZWQ=';Type=2;Flags=$Ace.Flags;Mask=$Ace.Mask;Sid=$Ace.Sid;Ordinary=$true})
    $script:after=Clone $script:current;Clone $script:current
}
function Get-WelaRegistryRecoveryDescriptorObservation {
    param($Snapshot)
    $known=if($Snapshot.DescriptorBase64 -ceq $script:before.DescriptorBase64){Clone $script:before}elseif($Snapshot.DescriptorBase64 -ceq $script:after.DescriptorBase64){Clone $script:after}else{throw 'Unknown mocked native descriptor bytes.'}
    $known.Identity=$Snapshot.Identity;$known
}
function Get-WelaRegistryRecoveryAddition {param($Before,$After,$Ace) if($Before.DescriptorBase64 -cne $script:before.DescriptorBase64 -or $After.DescriptorBase64 -cne $script:after.DescriptorBase64){throw 'Native descriptor append proof differs.'};'YWRkZWQ='}
function Get-WelaRegistryRecoverySnapshot {param($Definition) if($script:scenario -ceq 'children'){throw 'Recovery requires empty registry descendants.'};Clone $script:current}
$script:sourceReader=(Get-Command Get-WelaRegistryRecoverySources).ScriptBlock
function Get-WelaRegistryRecoverySources {$sources=&$script:sourceReader;if(($script:scenario -ceq 'source-after-pending' -and (Test-Path (Join-Path $script:out 'pending.json'))) -or ($script:scenario -ceq 'source-after-write' -and $script:mutations -gt 0)){$sources.'WELA.ps1'='0'*64};if($script:scenario -ceq 'plan-after-pending' -and (Test-Path (Join-Path $script:out 'pending.json'))){[IO.File]::AppendAllText($script:planPath,' ')};$sources}
function Get-WelaRegistryRecoveryContext {
    $machine=if($script:scenario -ceq 'host-after-write' -and $script:mutations -gt 0){'00000000-0000-0000-0000-000000000002'}else{'00000000-0000-0000-0000-000000000001'}
    $token=if($script:scenario -ceq 'token-after-write' -and $script:mutations -gt 0){'different-token'}else{'fixture-token'}
    [pscustomobject][ordered]@{Host=[pscustomobject]@{Computer='fixture';MachineGuid=$machine};Selected=(Get-WelaSelectedSaclContext);Token=$token;AuditMasks='fixture59';Precedence='fixtureDWORD1'}
}
function Open-WelaRegistryRecoveryTarget {
    param($Definition)
    $object=[pscustomobject]@{WriteAttempted=$false;AfterObservation=$null}
    $object|Add-Member ScriptMethod Remove {
        param($Identity,$Descriptor,$Added)
        Assert ((Test-Path (Join-Path $script:out 'pending.json')) -and $Identity -ceq $script:current.Identity -and $Descriptor -ceq $script:current.DescriptorBase64 -and $Added -ceq 'YWRkZWQ=') 'Durable intent and exact current removal arguments precede native adapter.'
        if($script:scenario -ceq 'native-refusal'){throw 'Native prewrite refusal.'}
        $this.WriteAttempted=$true;$script:mutations++;$script:current=Clone $script:before;$script:current.Identity=$nativePath+':1002';$this.AfterObservation=Clone $script:current
        if($script:scenario -ceq 'native-partial'){throw 'Native write completed but after-state is unverified.'}
        if($script:scenario -ceq 'original-after-write'){[IO.File]::AppendAllText($script:originalPath,' ')}
        if($script:scenario -ceq 'artifact-after-write'){[IO.File]::AppendAllText((Join-Path $script:out 'pending.json'),' ')}
        Clone $script:current
    }
    $object|Add-Member ScriptMethod Dispose {if($script:scenario -ceq 'dispose-failure'){throw 'Native privilege restore failed.'}}
    $object
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-registry-recovery-unit-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
function New-Original {
    $script:scenario='';$script:mutations=0;$script:current=Clone $script:before
    $script:caseRoot=Join-Path $temp ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $script:caseRoot
    $script:originalPath=Join-Path $script:caseRoot 'original.json';$script:journal=Join-Path $script:caseRoot 'journal';$script:resultPath=Join-Path $script:caseRoot 'result.json'
    $null=Invoke-WelaSelectedSacl -Action Plan -Profile wela-2.2.0 -Ids $fixtureSelection.Id -IncludeOptional -IncludeChildren -ResultsPath $script:originalPath
    $result=Invoke-WelaSelectedSacl -Action Configure -Profile wela-2.2.0 -Ids $fixtureSelection.Id -IncludeOptional -IncludeChildren -PlanPath $script:originalPath -BackupPath $script:journal -ResultsPath $script:resultPath -Auto
    Assert ($result.Results[0].Status -ceq 'Applied') 'Original portable history comes from the real shared selected-SACL executor with only native boundaries replaced.'
    $script:pendingPath=Join-Path $script:journal ($fixtureSelection.Id+'.pending.json');$script:confirmedPath=Join-Path $script:journal ($fixtureSelection.Id+'.confirmed.json')
}
function Build-Plan {New-WelaRegistryRecoveryPlan $script:originalPath $script:pendingPath $script:confirmedPath $script:resultPath}
function Prepare-Recovery {
    New-Original
    $script:review=Join-Path $script:caseRoot 'review'
    $report=Invoke-WelaRegistrySaclRecovery -OriginalPlanPath $script:originalPath -PendingPath $script:pendingPath -ConfirmedPath $script:confirmedPath -OriginalResultsPath $script:resultPath -OutputPath $script:review
    Assert ($report.Status -ceq 'ReviewRequired' -and -not $report.WriteAttempted) ('Plan failed: '+$report.Diagnostic)
    $script:planPath=Join-Path $script:review 'plan.json';$script:hash=$report.PlanHash;$script:out=Join-Path $script:caseRoot 'restore'
}
function Restore-Review {param([switch]$OmitReduction,[switch]$OmitInheritance) Invoke-WelaRegistrySaclRecovery -Action Restore -PlanPath $script:planPath -PlanHash $script:hash -OutputPath $script:out -AllowAuditReduction:(-not $OmitReduction) -AllowInheritance:(-not $OmitInheritance)}
try{
    foreach($empty in @($null,@(),[pscustomobject]@{})){Assert-WelaRegistryRecoveryEmptyCatalog $empty;Assert $true 'Known empty catalogue representations are accepted.'}
    foreach($invalid in @($true,'',1,@('target'),[pscustomobject]@{Path='target'})){Throws {Assert-WelaRegistryRecoveryEmptyCatalog $invalid} 'must be empty'}
    Prepare-Recovery;$result=Restore-Review
    Assert ($result.Status -ceq 'AddedAceRemoved' -and $result.WriteAttempted -and $script:mutations -eq 1 -and $result.ReadyRuleCredit -eq 0) ('Exact recovery failed: '+$result.Diagnostic)
    Assert ((Test-Path (Join-Path $script:out 'pending.json')) -and (Test-Path (Join-Path $script:out 'confirmed.json'))) 'Separate durable intent and completion exist.'
    foreach($artifact in $result.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $script:out $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Retained recovery hash matches real bytes.'}
    $script:out=Join-Path $script:caseRoot 'replay';$replay=Restore-Review;Assert ($replay.Status -ceq 'Refused' -and -not $replay.WriteAttempted -and $script:mutations -eq 1) 'Recovered original plan cannot remove another ACE.'
    foreach($case in @('reduction','inheritance')){Prepare-Recovery;$result=Restore-Review -OmitReduction:($case -ceq 'reduction') -OmitInheritance:($case -ceq 'inheritance');Assert ($result.Status -ceq 'Refused' -and -not $result.WriteAttempted -and -not(Test-Path (Join-Path $script:out 'pending.json'))) 'Each consent refuses before intent and mutation.'}
    $mutations=@(
        @{File='originalPath';Change={$args[0].Kind=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].IncludeChildren=$false};Pattern='child consent'},
        @{File='originalPath';Change={$args[0].Rows[0].Status=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].Rows[0].Definition.Kind=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].Rows[0].Before.Kind=$true};Pattern='metadata|registry|catalog'},
        @{File='originalPath';Change={$args[0].Sources[0].Sha256=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].Sources[0].Path=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].Rows[0].Ace.Flags='194'};Pattern='integer'},
        @{File='originalPath';Change={$args[0].Rows[0].Before.Owner='S-1-1-0'};Pattern='metadata'},
        @{File='originalPath';Change={$args[0].Rows[0].DescendantsBefore.Status=$true};Pattern='mistyped'},
        @{File='originalPath';Change={$args[0].Rows[0].DescendantsBefore.Entries=@('child')};Pattern='empty'},
        @{File='originalPath';Change={$args[0].Rows[0].DescendantsBefore.Maximum=129};Pattern='empty'},
        @{File='pendingPath';Change={$args[0].State=$true};Pattern='mistyped'},
        @{File='pendingPath';Change={$args[0].ContextKey='other'};Pattern='scope'},
        @{File='pendingPath';Change={$args[0].After=$args[0].Before};Pattern='Pending'},
        @{File='confirmedPath';Change={$args[0].Kind=$true};Pattern='mistyped'},
        @{File='confirmedPath';Change={$args[0].Before.DaclBase64='changed'};Pattern='metadata'},
        @{File='confirmedPath';Change={$args[0].DescendantsAfter.Diagnostics=@('incomplete')};Pattern='empty'},
        @{File='confirmedPath';Change={$args[0].DescendantVerification.Status=$true};Pattern='mistyped'},
        @{File='resultPath';Change={$args[0].Results[0].Status=$true};Pattern='mistyped'},
        @{File='resultPath';Change={$args[0].DryRun=$true};Pattern='non-dry-run'},
        @{File='resultPath';Change={$args[0].ExitCode=$true};Pattern='integer'},
        @{File='resultPath';Change={$args[0].Plan.SchemaVersion=$true};Pattern='integer'},
        @{File='resultPath';Change={$args[0].BackupPath='somewhere-else'};Pattern='Receipt paths'},
        @{File='originalPath';Change={$args[0].CapturedUtc=[DateTime]::UtcNow.AddDays(1).ToString('o')};Pattern='timestamps'}
    )
    foreach($test in $mutations){New-Original;$path=Get-Variable -Name $test.File -ValueOnly;$data=ConvertFrom-WelaEvtxJson ([IO.File]::ReadAllText($path));&$test.Change $data;Save $path $data;Throws {Build-Plan} $test.Pattern;Assert ($script:mutations -eq 0) 'Invalid original history cannot reach a native writer.'}
    foreach($case in @('descriptor','lastwrite','children')){Prepare-Recovery;if($case -ceq 'descriptor'){$script:current.DescriptorBase64='ZGlmZmVyZW50'}elseif($case -ceq 'lastwrite'){$script:current.Identity=$nativePath+':9999'}else{$script:scenario='children'};$result=Restore-Review;Assert ($result.Status -ceq 'Refused' -and -not $result.WriteAttempted) 'Current descriptor, benign-value last-write and child drift refuse recovery.'}
    foreach($case in @('source-after-pending','plan-after-pending','native-refusal','native-partial','token-after-write','host-after-write','source-after-write','original-after-write','artifact-after-write','dispose-failure')){
        Prepare-Recovery;$script:scenario=$case;$result=Restore-Review
        $attempted=$case -in @('native-partial','token-after-write','host-after-write','source-after-write','original-after-write','artifact-after-write','dispose-failure')
        Assert ($result.ExitCode -eq 1 -and $result.WriteAttempted -eq $attempted -and $result.Status -ceq $(if($attempted){'WriteAttemptedUnverified'}else{'Refused'})) ("Failure state $case : "+$result.Diagnostic)
        Assert (-not(Test-Path (Join-Path $script:out 'confirmed.json')) -and (Test-Path (Join-Path $script:out 'pending.json'))) 'Unverified operations retain intent but never confirmed completion.'
    }
    Prepare-Recovery;$forged=ConvertFrom-WelaEvtxJson ([IO.File]::ReadAllText($script:planPath));$forged.AddedAce=$true;Save $script:planPath $forged;$script:hash=(Get-FileHash -LiteralPath $script:planPath).Hash.ToLowerInvariant();$result=Restore-Review;Assert ($result.Status -ceq 'Refused' -and -not $result.WriteAttempted) 'A freshly hashed forged instruction cannot replace the independently rebuilt plan.'
    Prepare-Recovery;[IO.File]::AppendAllText($script:planPath,' ');$result=Restore-Review;Assert ($result.Status -ceq 'Refused' -and -not $result.WriteAttempted) 'Exact reviewed file hash refuses byte drift.'
    New-Original;$text=[IO.File]::ReadAllText($script:originalPath);[IO.File]::WriteAllText($script:originalPath,($text -replace '"Kind"\s*:\s*"WelaSelectedSaclPlan"','"Kind": "WelaSelectedSaclPlan", "Kind": true'));Throws {Build-Plan} 'Duplicate|duplicate'
    New-Original;$plan=ConvertFrom-WelaEvtxJson ([IO.File]::ReadAllText($script:originalPath));$plan.CapturedUtc=([DateTimeOffset]::Parse([string]$plan.CapturedUtc)).UtcDateTime;Save $script:originalPath $plan;$null=Build-Plan;Assert $true 'Canonical UTC DateTime materialization remains supported.'
}finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}}
Write-Host "Passed $script:count registry recovery assertions; only native/context boundaries mocked."
$global:LASTEXITCODE=0
