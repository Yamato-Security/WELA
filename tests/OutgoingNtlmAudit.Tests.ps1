$ErrorActionPreference='Stop';$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/OutgoingNtlmAudit.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('wela-ntlm-test-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$count=0;$sequence=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 12 -Compress}
function Reset($Value,$Type='DWord'){
    $script:policy=[pscustomobject][ordered]@{KeyExists=$true;ValueExists=($null -ne $Value);Value=$Value;Type=$(if($null -ne $Value){$Type}else{$null})}
    $script:writes=0;$script:reads=0;$script:failRead=$false;$script:failWrite=$false;$script:ignoreWrite=$false;$script:promptChange=$null;$script:onRead=$null
}
function Get-WelaOutgoingAuditSnapshot {
    $script:reads++;if($script:onRead){& $script:onRead};if($script:failRead){throw 'Access denied'}
    [pscustomobject][ordered]@{Host=[pscustomobject][ordered]@{Build=26100;ProductType=3;DomainRole=2;PartOfDomain=$false};Policy=($script:policy|ConvertTo-Json|ConvertFrom-Json)}
}
function Get-WelaOutgoingNtlmPolicySource {'Unknown (fixture has no RSoP ownership evidence)'}
function Set-ItemProperty {param($LiteralPath,$Name,$Value,$Type,$ErrorAction)
    Assert ($LiteralPath -ceq 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -and $Name -ceq 'RestrictSendingNTLMTraffic' -and $Value -eq 1 -and $Type -ceq 'DWord') 'Only the one exact audit-only target may be written.'
    $script:writes++;if($script:failWrite){throw 'Write denied'};if(-not $script:ignoreWrite){$script:policy.ValueExists=$true;$script:policy.Value=1;$script:policy.Type='DWord'}
}
function Read-Host {param($Prompt) if($script:promptChange){& $script:promptChange};return 'Y'}
function Configure([string]$Mode='PreserveOrAudit',[switch]$DryRun,[switch]$Prompt){
    $script:sequence++;$script:backup=Join-Path $root ('case-'+$script:sequence)
    Invoke-WelaOutgoingAuditCommand -Action Configure -Mode $Mode -Auto:(-not $Prompt) -DryRun:$DryRun -BackupPath $script:backup
}
try{
    foreach($initial in @($null,0,1)){
        Reset $initial;$old=Key $script:policy;$r=Configure
        Assert ($r.ExitCode -eq 0 -and $r.Scope -ceq 'outgoing-ntlm-audit-policy-only' -and $r.ReadyRuleCredit -eq 0) 'Public report scopes success to one policy, without detection credit.'
        Assert ($script:policy.Value -eq 1 -and $script:writes -eq $(if($initial -eq 1){0}else{1})) 'Absent/allow are audited; existing audit is idempotent.'
        if($initial -ne 1){$j=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json);Assert ($j.Count -eq 1 -and (Key $j[0].Before.Policy) -ceq $old) 'Typed original snapshot is durable before the one write.'}
        else{Assert (-not(Test-Path (Join-Path $backup 'before.jsonl'))) 'Already configured mode does not journal a write.'}
    }
    Reset 2;$r=Configure;Assert ($script:writes -eq 0 -and $r.Results[0].Status -ceq 'Skipped' -and $r.Plan.Status -ceq 'PreservedEnforcement' -and $script:policy.Value -eq 2) 'Default mode preserves and identifies authentication enforcement.'
    Reset 2;$r=Configure Audit;Assert ($script:writes -eq 1 -and $script:policy.Value -eq 1 -and $r.Results[0].Status -ceq 'Applied') 'Explicit audit mode authorizes replacing deny with auditing.'
    foreach($value in @(42,'1')){foreach($mode in @('PreserveOrAudit','Audit')){
        Reset $value $(if($value -is [string]){'String'}else{'DWord'});$r=Configure $mode
        Assert ($r.ExitCode -eq 1 -and $script:writes -eq 0 -and $r.Results[0].Status -ceq 'Failed') 'Unknown values/types remain untouched even in explicit Audit mode.'
    }}
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
    Reset 0;$r=Invoke-WelaOutgoingAuditCommand -Action Plan;Assert ($r.Plan.Status -ceq 'ChangeRequired' -and $script:writes -eq 0) 'Plan is current-host assessment and does not mutate policy.'
    foreach($action in @('Audit','Plan')){foreach($option in @('Auto','DryRun','BackupPath')){
        $a=@{Action=$action};$a[$option]=$(if($option -eq 'BackupPath'){'unused'}else{$true});$threw=$false;try{Invoke-WelaOutgoingAuditCommand @a}catch{$threw=$true};Assert $threw 'Read-only actions reject mutation-only options.'
    }}
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
Write-Host "PASS: $count scoped outgoing NTLM assertions."
exit 0
