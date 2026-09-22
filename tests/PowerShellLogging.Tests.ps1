$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/PowerShellLogging.ps1')
$script:count=0;$script:ScriptRoot=$repo;$script:writes=0;$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-pslogging-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
function Assert($Value,$Message){if(-not $Value){throw "FAIL: $Message"};$script:count++}
function Reject([scriptblock]$Action,[string]$Pattern){$message='';try{&$Action}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected rejection $Pattern; got $message"}
function CloneFixture($Value){ConvertTo-WelaPsLoggingKey $Value|ConvertFrom-Json}
function Row($Path,$Values=@(),$Children=@()){[pscustomobject]@{Path=$Path;Values=@($Values);Children=@($Children);Access='original-acl'}}
function Fixture {
    [pscustomobject][ordered]@{Host=[pscustomobject]@{Computer='fixture';Build=20348};Engine=[pscustomobject]@{Target='Windows PowerShell 5.1'};Sources=@('sha');Machine=[pscustomobject]@{Exists=$true;Keys=@((Row '' @() @('ModuleLogging','ScriptBlockLogging','Transcription')),(Row 'ModuleLogging' @([pscustomobject]@{Name='EnableModuleLogging';Type='DWord';Value=0}) @('ModuleNames')),(Row 'ModuleLogging\ModuleNames' @([pscustomobject]@{Name='existing';Type='String';Value='Existing.Module'})),(Row 'ScriptBlockLogging' @([pscustomobject]@{Name='EnableScriptBlockLogging';Type='DWord';Value=0},[pscustomobject]@{Name='EnableScriptBlockInvocationLogging';Type='DWord';Value=1})),(Row 'Transcription' @([pscustomobject]@{Name='EnableTranscripting';Type='DWord';Value=1})))};CurrentUser=@('preserved-user');PowerShellCoreMachine=@('preserved-core');PowerShellCoreUser=@('preserved-core-user');ProtectedEventLogging=@('preserved-protected');Channel=@('preserved-channel')}
}
function Mutate($Before,$Definition){
    $after=CloneFixture $Before;$after.Machine.Exists=$true
    $allowed=@('');$p='';foreach($segment in $Definition.Path.Split('\')){$p=if($p){$p+'\'+$segment}else{$segment};$allowed+=$p}
    foreach($path in $allowed){if(-not @($after.Machine.Keys|Where-Object Path -ieq $path).Count){$after.Machine.Keys+=Row $path}}
    foreach($key in $after.Machine.Keys){$key.Children=@($after.Machine.Keys|Where-Object {$_.Path -and $(if($_.Path.Contains('\')){$_.Path.Substring(0,$_.Path.LastIndexOf('\'))}else{''}) -ceq $key.Path}|ForEach-Object {$_.Path.Split('\')[-1]}|Sort-Object)}
    $row=@($after.Machine.Keys|Where-Object Path -ieq $Definition.Path)[0];$row.Values=@($row.Values|Where-Object Name -ine $Definition.Name)+[pscustomobject]@{Name=$Definition.Name;Type=$Definition.Type;Value=$Definition.Value};$row.Values=@($row.Values|Sort-Object Name);$after.Machine.Keys=@($after.Machine.Keys|Sort-Object Path);return $after
}
function Get-WelaPsLoggingSnapshot {CloneFixture $script:observed}
function Set-WelaPsLoggingValue {param($Definition)$script:writes++;if($script:failWrite){throw 'injected native write failure'};$script:observed=Mutate $script:observed $Definition;if($script:corrupt){$script:observed.CurrentUser=@('changed-user')}}
function Reset {$script:observed=Fixture;$script:writes=0;$script:failWrite=$false;$script:corrupt=$false}
try {
    foreach($action in @('Plan','Configure')){Reject {Assert-WelaPsLoggingSelection $action @() @()} 'explicit'}
    Reject {Assert-WelaPsLoggingSelection Configure @('Module') @()} 'ModuleName'
    Reject {Assert-WelaPsLoggingSelection Plan @('ScriptBlock') @('x')} 'Module selection'
    foreach($name in @('','C:\module','Mod*','../a','a?','a\b',('x'*129))){Reject {Assert-WelaPsLoggingSelection Plan @('Module') @($name)} 'literal'}
    Reject {Assert-WelaPsLoggingSelection Plan @('Module','module') @('a')} 'unique'
    Reject {Assert-WelaPsLoggingSelection Plan @('Module') @('A','a')} 'unique'
    Assert-WelaPsLoggingSelection Plan @('Module') @('*');Assert $true 'Explicit all-module accepted'
    Assert-WelaPsLoggingSelection Audit @() @();Assert $true 'Unselected Audit accepted'
    $definitions=@(Get-WelaPsLoggingDefinitions @('Module','ScriptBlock') @('Microsoft.PowerShell.Utility'))
    Assert ($definitions.Count -eq 3 -and $definitions[0].Type -eq 'String' -and $definitions[1].Name -eq 'EnableModuleLogging' -and $definitions[2].Name -eq 'EnableScriptBlockLogging') 'Name-before-enable ordering'
    Reset;$before=CloneFixture $script:observed;$report=Invoke-WelaPowerShellLogging -Action Audit
    Assert ($report.ExitCode -eq 0 -and $script:writes -eq 0 -and $report.ReadyRuleCredit -eq 0) 'Audit is read-only with zero readiness credit'
    $plan=Invoke-WelaPowerShellLogging -Action Plan -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility
    Assert ($plan.Plan.Controls.Count -eq 3 -and @($plan.Plan.Controls|Where-Object Status -eq ChangeRequired).Count -eq 3) 'Plan identifies all selected values'
    $dry=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -DryRun -BackupPath (Join-Path $root 'dry')
    Assert ($dry.ExitCode -eq 0 -and $dry.Skipped -eq 3 -and $script:writes -eq 0 -and -not (Test-Path (Join-Path $root 'dry'))) 'Dry run creates no journal or write'
    $run=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'run')
    Assert ($run.ExitCode -eq 0 -and $script:writes -eq 3 -and @($run.Results|Where-Object Status -eq Applied).Count -eq 3) 'Three exact writes applied'
    $journal=@(Get-Content (Join-Path $root 'run/before.jsonl')|ForEach-Object {$_|ConvertFrom-Json})
    Assert ($journal.Count -eq 3 -and (ConvertTo-WelaPsLoggingKey $journal[0].Before) -ceq (ConvertTo-WelaPsLoggingKey $before)) 'Complete original snapshot journaled before any mutation'
    Assert ((Get-WelaPsLoggingValue $script:observed.Machine 'ModuleLogging\ModuleNames' 'existing').Value -ceq 'Existing.Module') 'Other module names retained'
    Assert ((Get-WelaPsLoggingValue $script:observed.Machine 'ScriptBlockLogging' EnableScriptBlockInvocationLogging).Value -eq 1) 'Invocation logging retained'
    Assert ((ConvertTo-WelaPsLoggingKey $script:observed.CurrentUser) -ceq (ConvertTo-WelaPsLoggingKey $before.CurrentUser)) 'User policy retained'
    $again=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'again')
    Assert ($again.ExitCode -eq 0 -and $script:writes -eq 3 -and @($again.Results|Where-Object Status -eq AlreadyCompliant).Count -eq 3) 'Repeat is idempotent'
    Reset;$script:observed.Machine=[pscustomobject]@{Exists=$false;Keys=@()}
    $absent=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'absent')
    Assert ($absent.ExitCode -eq 0 -and $script:writes -eq 3) 'Absent root creates only declared ancestors'
    foreach($case in @(@{Type='String';Value='0'},@{Type='DWord';Value=2})){
        Reset;$value=Get-WelaPsLoggingValue $script:observed.Machine 'ScriptBlockLogging' EnableScriptBlockLogging;$value.Type=$case.Type;$value.Value=$case.Value
        $bad=Invoke-WelaPowerShellLogging -Action Configure -Control ScriptBlock -Auto -BackupPath (Join-Path $root ([guid]::NewGuid().ToString('N')))
        Assert ($bad.ExitCode -eq 1 -and $script:writes -eq 0) 'Wrong type/unknown DWORD refused before write'
    }
    Reset;$badName=Get-WelaPsLoggingValue $script:observed.Machine 'ModuleLogging\ModuleNames' existing;$badName.Type='DWord';$badName.Value=1
    $bad=Invoke-WelaPowerShellLogging -Action Configure -Control Module -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'badname')
    Assert ($bad.ExitCode -eq 1 -and -not (Test-Path (Join-Path $root 'badname'))) 'Unknown module value fails entire preflight'
    Reset;$script:failWrite=$true;$failed=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'writefailure')
    Assert ($failed.ExitCode -eq 1 -and $script:writes -eq 1) 'Native failure stops later writes'
    Reset;$script:corrupt=$true;$failed=Invoke-WelaPowerShellLogging -Action Configure -Control Module,ScriptBlock -ModuleName Microsoft.PowerShell.Utility -Auto -BackupPath (Join-Path $root 'corrupt')
    Assert ($failed.ExitCode -eq 1 -and $script:writes -eq 1) 'Preservation failure stops later writes'
    Reset;$snapshot=CloneFixture $script:observed;$definition=$definitions[0];$after=Mutate $snapshot $definition;Assert-WelaPsLoggingTransition $snapshot $after $definition;Assert $true 'Exact additive transition accepted'
    foreach($property in @('Host','Sources','CurrentUser','PowerShellCoreMachine','PowerShellCoreUser','ProtectedEventLogging','Channel')){$changed=CloneFixture $after;$changed.$property='drift';Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'Unselected state'}
    $changed=CloneFixture $after;$changed.Machine.Keys[0].Access='new-acl';Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'descriptor'
    $changed=CloneFixture $after;$changed.Machine.Keys=@($changed.Machine.Keys|Where-Object Path -ne Transcription);Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'disappeared'
    $changed=CloneFixture $after;$changed.Machine.Keys+=Row 'extra';Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'unrequested'
    $changed=CloneFixture $after;(Get-WelaPsLoggingValue $changed.Machine 'Transcription' EnableTranscripting).Value=0;Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'Unrelated policy values'
    $changed=CloneFixture $after;$changed.Machine.Keys[0].Children+= 'extra';Reject {Assert-WelaPsLoggingTransition $snapshot $changed $definition} 'subkeys'
    Reset;$script:promptBefore=CloneFixture $script:observed
    function Read-Host {param($Prompt)$script:observed.Host.Computer='changed-during-prompt';'Y'}
    $drift=Invoke-WelaPowerShellLogging -Action Configure -Control ScriptBlock -BackupPath (Join-Path $root 'drift')
    Assert ($drift.ExitCode -eq 1 -and $script:writes -eq 0) 'Prompt-time drift refused before mutation'
    Remove-Item Function:\Read-Host
    Reset;Set-Content -LiteralPath (Join-Path $root 'existing.json') -Value 'keep';Reject {Invoke-WelaPowerShellLogging -ResultsPath (Join-Path $root 'existing.json')} 'new file';Assert ((Get-Content -Raw (Join-Path $root 'existing.json')).Trim() -ceq 'keep') 'Existing report preserved'
    foreach($options in @(@{Auto=$true},@{DryRun=$true},@{BackupPath='x'})){Reject {Invoke-WelaPowerShellLogging @options} 'require PowerShellLoggingAction Configure'}
    Write-Host "PASS: $script:count scoped PowerShell logging assertions."
} finally {Remove-Item -LiteralPath $root -Recurse -Force}
