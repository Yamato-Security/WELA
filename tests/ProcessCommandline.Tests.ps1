$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/ProcessCommandline.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-test-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$count=0;$sequence=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 12 -Compress}
function Reset($Value,$Type='DWord'){
    $script:policy=[pscustomobject][ordered]@{KeyExists=$true;ValueExists=($null -ne $Value);Value=$Value;Type=$(if($null -ne $Value){$Type}else{$null})}
    $script:unselected=[pscustomobject]@{Values=@();Children=@()};$script:writes=0;$script:reads=0;$script:failRead=$false;$script:failWrite=$false;$script:ignoreWrite=$false;$script:promptChange=$null;$script:onRead=$null
}
function Get-WelaProcessCommandlineSnapshot {
    $script:reads++;if($script:onRead){& $script:onRead};if($script:failRead){throw 'Access denied'}
    [pscustomobject][ordered]@{Host=[pscustomobject][ordered]@{Build=26100;ProductType=3;DomainRole=2;PartOfDomain=$false};Policy=($script:policy|ConvertTo-Json|ConvertFrom-Json);Unselected=($script:unselected|ConvertTo-Json -Depth 12|ConvertFrom-Json)}
}
function Get-WelaProcessCommandlinePrerequisite {[pscustomobject]@{State='SuccessMissing';Mask=0}}
function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
    Assert ($LiteralPath -ceq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -and $Name -ceq 'ProcessCreationIncludeCmdLine_Enabled' -and $Value -eq 1 -and $Type -ceq 'DWord') 'Only the one exact audit-only target may be written.'
    $script:writes++;if($script:failWrite){throw 'Write denied'};if(-not $script:ignoreWrite){$script:policy.ValueExists=$true;$script:policy.Value=1;$script:policy.Type='DWord'}
}
function New-WelaRegistryKey {param($Path) Assert (-not $script:policy.KeyExists) 'Only an absent key may be created.';$script:policy.KeyExists=$true}
function Read-Host {param($Prompt) if($script:promptChange){& $script:promptChange};return 'Y'}
function Configure([switch]$DryRun,[switch]$Prompt){
    $script:sequence++;$script:backup=Join-Path $root ('case-'+$script:sequence)
    Invoke-WelaProcessCommandline -Action Configure -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath $script:backup
}
try{
    foreach($initial in @($null,0,1)){
        Reset $initial;$old=Key $script:policy;$r=Configure
        Assert ($r.ExitCode -eq 0 -and $r.Scope -ceq 'process-commandline-policy-only' -and $r.ReadyRuleCredit -eq 0) 'Public report scopes success to one policy, without detection credit.'
        Assert ($script:policy.Value -eq 1 -and $script:writes -eq $(if($initial -eq 1){0}else{1})) 'Absent/disabled are enabled; existing enabled policy is idempotent.'
        if($initial -ne 1){$j=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json);Assert ($j.Count -eq 1 -and (Key $j[0].Before.Policy) -ceq $old) 'Typed original snapshot is durable before the one write.'}
        else{Assert (-not(Test-Path (Join-Path $backup 'before.jsonl'))) 'Already configured mode does not journal a write.'}
    }
    foreach($value in @(2,42,'1')) {
        Reset $value $(if($value -is [string]){'String'}else{'DWord'});$r=Configure
        Assert ($r.ExitCode -eq 1 -and $script:writes -eq 0 -and $r.Results[0].Status -ceq 'Failed') 'Unknown values/types remain untouched.'
    }
    Reset $null;$script:policy.KeyExists=$false;$r=Configure
    Assert ($r.ExitCode -eq 0 -and $script:policy.KeyExists -and $script:writes -eq 1) 'Missing Audit key is created without replacing the parent.'
    Reset 0;$r=Configure -DryRun;Assert ($script:writes -eq 0 -and $r.DryRun -and -not(Test-Path $backup)) 'Dry run has no policy or journal-directory mutation.'
    Reset 0;$script:failRead=$true;$r=Configure;Assert ($r.ExitCode -eq 1 -and $script:writes -eq 0) 'An unreadable policy fails closed.'
    foreach($kind in @('failWrite','ignoreWrite')){
        Reset 0;Set-Variable -Scope Script -Name $kind -Value $true;$r=Configure
        Assert ($r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Failed') 'Native failure and ignored-write readback cannot report success.'
    }
    foreach($changed in @(1,2,42)){
        Reset 0;$script:changed=$changed;$script:promptChange={$script:policy.Value=$script:changed};$r=Configure -Prompt
        Assert ($r.ExitCode -eq 1 -and $script:writes -eq 0 -and $script:policy.Value -eq $changed) 'Prompt-time drift refuses writes after preserving the exact original receipt.'
    }
    Reset 0;$script:onRead={if($script:reads -eq 5){$script:policy.Value=0}};$r=Configure
    Assert ($script:writes -eq 1 -and $r.ExitCode -eq 1 -and $r.Results[0].Status -ceq 'Overridden') 'A later policy change fails final verification.'
    Reset 0;$script:promptChange={$script:unselected.Values=@('new sibling')};$r=Configure -Prompt;Assert ($r.ExitCode -eq 1 -and $script:writes -eq 0) 'Unrelated policy drift refuses mutation.'
    Reset 0;$r=Invoke-WelaProcessCommandline -Action Plan;Assert ($r.Plan.Status -ceq 'ChangeRequired' -and $script:writes -eq 0) 'Plan is current-host assessment and does not mutate policy.'
    foreach($action in @('Audit','Plan')){foreach($option in @('Auto','DryRun','BackupPath')){
        $a=@{Action=$action};$a[$option]=$(if($option -eq 'BackupPath'){'unused'}else{$true});$threw=$false;try{Invoke-WelaProcessCommandline @a}catch{$threw=$true};Assert $threw 'Read-only actions reject mutation-only options.'
    }}
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count scoped process command-line assertions."
exit 0
