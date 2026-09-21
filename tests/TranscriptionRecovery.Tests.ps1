$ErrorActionPreference='Stop'
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ScriptRoot 'scripts/Configuration.ps1')
. (Join-Path $script:ScriptRoot 'scripts/AuditRecovery.ps1')
. (Join-Path $script:ScriptRoot 'scripts/PowerShellTranscription.ps1')
. (Join-Path $script:ScriptRoot 'scripts/TranscriptionRecovery.ps1')
$script:artifactWriter=(Get-Command Write-WelaRecoveryArtifact).ScriptBlock
function Write-WelaRecoveryArtifact {
    param($Path,$Value)
    if($script:failArtifact -and [IO.Path]::GetFileName($Path) -eq $script:failArtifact){throw 'injected durable artifact failure'}
    & $script:artifactWriter $Path $Value
}
$script:checks=0;$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-transcript-recovery-test-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory $root
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{& $Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'"}
function Copy-Value($Value){ConvertFrom-WelaRecoveryJson (Get-WelaRecoveryKey $Value)}
function Typed($Value,$Type='DWord'){[pscustomobject]@{KeyExists=$true;ValueExists=($null -ne $Value);Value=$Value;Type=$(if($null -ne $Value){$Type}else{$null})}}
function Get-WelaTranscriptRecoveryContext {[pscustomobject]@{Host=[pscustomobject]@{Computer='fixture';MachineGuid=$script:machine};Reader='fixture-reader'}}
function Get-WelaTranscriptRecoverySources {[pscustomobject]@{Code=$script:code}}
function Assert-WelaTranscriptRecoveryLocalPath {param($Path) if(-not $Path -or $Path.StartsWith('\\')){throw 'local path fixture refusal'}}
function Get-WelaTranscriptRecoveryProtectedPolicy {return ,$script:protected}
function Get-WelaTranscriptCapability {[pscustomobject]@{Status='Supported';Views=@('Registry64','Registry32')}}
function Get-WelaTranscriptPolicy {param($Views) Copy-Value $script:policy}
function Get-WelaTranscriptDestination {param($Path) [pscustomobject]@{RequestedPath=$Path;Path=$Path;Status='Observed';ConfigureAllowed=$true;CreationTimeUtc='fixture';Acl=$script:acl}}
function Get-WelaTranscriptState {param($OutputDirectory) [pscustomobject]@{Capability=(Get-WelaTranscriptCapability);Policy=(Get-WelaTranscriptPolicy);Destination=(Get-WelaTranscriptDestination $OutputDirectory)}}
function Set-WelaTranscriptRecoveryValue {
    param($Name,$Value)
    $script:writes++
    Assert (Test-Path (Join-Path $script:restoreOutput ('{0:d3}-pending.json' -f $script:writes))) 'each actual write has a durable pending receipt first'
    if($script:writes -eq $script:failWrite){throw 'injected write failure'}
    foreach($view in $script:policy){$view.Machine.$Name=Copy-Value $Value}
    if($script:writes -eq $script:driftWrite){$script:protected=@('changed independent module policy')}
}
function Read-Host {param($Prompt) if($script:promptDrift){$script:policy[0].Machine.EnableInvocationHeader=Typed 1;$script:policy[1].Machine.EnableInvocationHeader=Typed 1};'y'}
function New-Fixture($Enable=1,$Directory='C:\Old') {
    $script:machine='stable';$script:code='stable';$script:acl='private';$script:protected=@('module','script-block','unrelated');$script:writes=0;$script:failWrite=-1;$script:driftWrite=-1;$script:promptDrift=$false;$script:failArtifact=$null
    $script:fixture=Join-Path $root ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $script:fixture
    $beforePolicy=@(foreach($view in @('Registry64','Registry32')){[pscustomobject]@{View=$view;Machine=[pscustomobject]@{EnableTranscripting=(Typed $Enable);OutputDirectory=(Typed $Directory String);EnableInvocationHeader=(Typed 0)};CurrentUser=[pscustomobject]@{EnableTranscripting=(Typed $null);OutputDirectory=(Typed $null);EnableInvocationHeader=(Typed $null)}}})
    $script:policy=Copy-Value $beforePolicy
    foreach($view in $script:policy){$view.Machine.EnableTranscripting=Typed 1;$view.Machine.OutputDirectory=Typed 'C:\New' String}
    $before=[pscustomobject]@{Capability=(Get-WelaTranscriptCapability);Policy=$beforePolicy;Destination=(Get-WelaTranscriptDestination 'C:\New')}
    $after=Get-WelaTranscriptState 'C:\New'
    $target=[pscustomobject]@{Hive='LocalMachine';SubKey='SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';OutputDirectory='C:\New'}
    $desired=[pscustomobject]@{EnableTranscripting=[pscustomobject]@{Type='DWord';Value=1};OutputDirectory=[pscustomobject]@{Type='String';Value='C:\New'};EnableInvocationHeader='Preserve'}
    $script:entry=[pscustomobject]@{Version=1;ComputerName='fixture';RecordedUtc=[datetime]::UtcNow.ToString('o');Id='PowerShellTranscription/CisV4L2';Kind='PowerShellTranscription';Before=$before;Target=$target;Desired=$desired}
    $script:original=[pscustomobject]@{ExitCode=0;Failed=0;Skipped=0;DryRun=$false;Action='Configure';Scope='windows-powershell-transcription-policy-only';Results=@([pscustomobject]@{Id=$script:entry.Id;Kind=$script:entry.Kind;Before=$before;After=$after;Target=$target;Desired=$desired;Status='Applied'})}
    Save-History
    $script:restoreOutput=Join-Path $script:fixture 'restore'
}
function Save-History {
    $script:journal=Join-Path $script:fixture 'before.jsonl';$script:originalPath=Join-Path $script:fixture 'original.json'
    Get-WelaRecoveryKey $script:entry|Set-Content -LiteralPath $script:journal -Encoding UTF8
    Get-WelaRecoveryKey $script:original|Set-Content -LiteralPath $script:originalPath -Encoding UTF8
}
function Plan-Fixture {
    $script:planResult=Invoke-WelaTranscriptRecovery -JournalPath $script:journal -OriginalResultsPath $script:originalPath -OutputPath (Join-Path $script:fixture 'plan')
    $script:planPath=Join-Path $script:planResult.OutputPath 'plan.json'
    $script:restoreParameters=@{Action='Restore';PlanPath=$script:planPath;PlanHash=$script:planResult.PlanSha256;OutputPath=$script:restoreOutput;Auto=$true}
}
try {
    New-Fixture;Plan-Fixture
    Assert ($script:planResult.RequiresTemporarySuspension -and $script:writes -eq 0) 'plan exposes a required temporary suspension without changes'
    Reject {Invoke-WelaTranscriptRecovery @script:restoreParameters} 'explicit.*TemporarySuspension'
    Assert (-not (Test-Path $script:restoreOutput)) 'missing suspension consent creates no recovery output'
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
    Assert ($report.Status -eq 'Restored' -and $report.ExitCode -eq 0 -and $script:writes -eq 3) 'enabled destination recovery completes three verified writes'
    $confirmed=@(Get-ChildItem $script:restoreOutput '*-confirmed.json'|ForEach-Object {ConvertFrom-WelaRecoveryJson (Get-Content $_.FullName -Raw)})
    Assert ($confirmed[0].Step.Name -eq 'EnableTranscripting' -and $confirmed[0].Step.Value.Value -eq 0 -and $confirmed[1].Step.Name -eq 'OutputDirectory' -and $confirmed[2].Step.Value.Value -eq 1) 'explicit suspension precedes destination and original enablement comes last'
    Assert ($confirmed[0].Before[0].Machine.EnableTranscripting.Value -eq 1 -and $confirmed[0].After[0].Machine.EnableTranscripting.Value -eq 0) 'confirmed receipts retain distinct before/after step snapshots'
    Assert ($script:policy[0].Machine.OutputDirectory.Value -eq 'C:\Old' -and $script:policy[0].Machine.EnableInvocationHeader.Value -eq 0) 'original directory restored and header retained'
    Assert ($report.SigmaEvtxCredit -eq 0) 'recovery grants no EVTX credit'
    Reject {Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension} 'Current policy/destination differs'
    foreach($before in @(0,$null)) {
        New-Fixture $before;Plan-Fixture
        $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
        Assert ($report.Status -eq 'Restored' -and $script:policy[0].Machine.EnableTranscripting.Value -eq $before) 'disabled or absent original enablement is recovered exactly'
        Assert ($script:writes -eq $(if($null -eq $before){3}else{2})) 'only required ordered steps are written'
    }
    New-Fixture 0 $null;Plan-Fixture
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters
    Assert ($report.Status -eq 'Restored' -and -not $script:policy[0].Machine.OutputDirectory.ValueExists -and $script:policy[0].Machine.OutputDirectory.KeyExists) 'absent output value restored with key retained'
    New-Fixture 1 $null
    Reject {Plan-Fixture} 'absent output directory requires'
    New-Fixture 0 'C:\New';Plan-Fixture
    $preview=$script:restoreParameters.Clone();$preview.Remove('OutputPath')
    $report=Invoke-WelaTranscriptRecovery @preview -DryRun
    Assert ($report.Status -eq 'WouldRestore' -and $script:writes -eq 0 -and -not (Test-Path $script:restoreOutput)) 'preview is read-only'
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters
    Assert ($report.Status -eq 'Restored' -and $script:writes -eq 1) 'unchanged destination restores enablement only'
    foreach($alter in @('wrong-host','failed','mismatch','type','duplicate','shared-view')) {
        New-Fixture
        switch($alter){
            'wrong-host' {$script:entry.ComputerName='other'}
            'failed' {$script:original.Results[0].Status='Failed'}
            'mismatch' {$script:original.Results[0].Desired=Copy-Value $script:original.Results[0].Desired;$script:original.Results[0].Desired.EnableTranscripting.Value=0}
            'type' {$script:entry.Before.Policy[0].Machine.EnableTranscripting=Typed '1' String;$script:entry.Before.Policy[1].Machine.EnableTranscripting=Typed '1' String}
            'duplicate' {$script:original.Results += $script:original.Results[0]}
            'shared-view' {$script:entry.Before.Policy[1].Machine.EnableTranscripting=Typed 0}
        }
        Save-History
        Reject {Plan-Fixture} 'history|Applied|differs|DWORD|shared|Shared'
        Assert ($script:writes -eq 0) 'unsupported or inconsistent source evidence never mutates'
    }
    foreach($alter in @('source','host','policy','directory','protected','plan')) {
        New-Fixture;Plan-Fixture
        switch($alter){
            'source' {$script:code='changed'}
            'host' {$script:machine='changed'}
            'policy' {foreach($view in $script:policy){$view.Machine.EnableTranscripting=Typed 0}}
            'directory' {$script:acl='changed'}
            'protected' {$script:protected=@('changed')}
            'plan' {Add-Content -LiteralPath $script:planPath ' '}
        }
        Reject {Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension} 'differs|different'
        Assert ($script:writes -eq 0) 'drift before restore causes no mutation'
    }
    New-Fixture;Plan-Fixture;$script:promptDrift=$true;$script:restoreParameters.Auto=$false
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 0) 'prompt-time typed policy drift blocks the first write'
    New-Fixture;Plan-Fixture;$script:failWrite=2
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 2 -and $script:policy[0].Machine.EnableTranscripting.Value -eq 0 -and $script:policy[0].Machine.OutputDirectory.Value -eq 'C:\New') 'partial failure stops and reports the actual suspended state'
    Assert ((Test-Path (Join-Path $script:restoreOutput '001-confirmed.json')) -and (Test-Path (Join-Path $script:restoreOutput '002-pending.json')) -and -not (Test-Path (Join-Path $script:restoreOutput '003-pending.json'))) 'partial receipts preserve confirmed versus uncertain steps'
    New-Fixture;Plan-Fixture;$script:driftWrite=1
    $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
    Assert ($report.ExitCode -eq 1 -and $script:writes -eq 1 -and $report.Diagnostic -match 'Preserved PowerShell policy changed') 'independent policy drift after a write stops all later writes'
    foreach($name in @('001-pending.json','001-confirmed.json')) {
        New-Fixture;Plan-Fixture;$script:failArtifact=$name
        $report=Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension
        Assert ($report.ExitCode -eq 1 -and $script:writes -eq $(if($name -like '*pending*'){0}else{1})) 'durable receipt failure stops before any further native writes'
    }
    New-Fixture;Plan-Fixture;$script:failArtifact='result.json'
    Reject {Invoke-WelaTranscriptRecovery @script:restoreParameters -AllowTemporarySuspension} 'durable artifact failure'
    Assert ($script:writes -eq 3 -and (Test-Path (Join-Path $script:restoreOutput '003-confirmed.json'))) 'result persistence failure fails outward while durable final confirmation remains'
    Reject {ConvertFrom-WelaRecoveryJson '{"x":1,"X":2}'} 'Duplicate'
    Reject {ConvertFrom-WelaRecoveryJson '{x:1}'} 'strict JSON'
    Write-Host "Passed $script:checks transcription recovery assertions; no Windows policy changes."
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
