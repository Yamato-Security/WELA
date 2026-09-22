param([switch]$AllowDisposableAuditWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableAuditWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/OutgoingNtlmAudit.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $repo 'modules/NativeProviders.psm1') -Force
$engine=(Get-Process -Id $PID).Path;$count=0;$failure=$null;$errors=@()
$root=Join-Path $env:RUNNER_TEMP ('wela-outgoing-audit-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';$name='RestrictSendingNTLMTraffic'
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Masks {$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
function Other {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$k=$null
    try{
        $k=$base.OpenSubKey('SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0');if(-not $k){throw 'Existing MSV1_0 key required.'}
        $values=@($k.GetValueNames()|Sort-Object|Where-Object {$_ -ine $name}|ForEach-Object{[pscustomobject][ordered]@{Name=$_;Type=$k.GetValueKind($_).ToString();Value=$k.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}})
        $children=@($k.GetSubKeyNames()|Sort-Object)
        $security=if($PSVersionTable.PSVersion.Major -ge 6){[Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($k)}else{$k.GetAccessControl()}
        $acl=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)
    }finally{if($k){$k.Dispose()};$base.Dispose()}
    [pscustomobject][ordered]@{Values=$values;Children=$children;Access=$acl;DomainPolicy=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' AuditNTLMInDomain;NtlmChannel=Get-WelaNativeChannel 'Microsoft-Windows-NTLM/Operational';SecurityChannel=Get-WelaNativeChannel Security;NetlogonService=[string](Get-Service Netlogon).Status}
}
function Public([string]$Label,[string[]]$Arguments){
    $prior=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') outgoing-ntlm @Arguments 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
    $output|Set-Content -LiteralPath (Join-Path $root ($Label+'.txt')) -Encoding UTF8
    Assert ($code -eq 0) "Public $Label exited $code : $output"
    Get-Content -Raw -LiteralPath (Join-Path $root ($Label+'.json'))|ConvertFrom-Json
}
$original=Get-WelaOutgoingAuditSnapshot
Assert ($original.Host.ProductType -eq 3 -and $original.Host.DomainRole -eq 2 -and -not $original.Host.PartOfDomain) 'Actual unjoined disposable Server is required.'
Assert (-not $original.Policy.ValueExists -or ($original.Policy.Type -ceq 'DWord' -and $original.Policy.Value -in @(0,1))) 'Fixture never replaces pre-existing enforcement or an unknown policy.'
$other=Other;$masks=Masks
Save 'original.json' @{Snapshot=$original;Unselected=$other;Masks=$masks;UBR=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR;Engine=$PSVersionTable.PSVersion.ToString();Commit=$env:GITHUB_SHA}
try{
    foreach($case in @('absent','allow')){
        if((Get-WelaRegistryState $path $name).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}
        if($case -eq 'allow'){$null=New-ItemProperty -LiteralPath $path -Name $name -PropertyType DWord -Value 0}
        $prepared=Get-WelaOutgoingAuditSnapshot
        $plan=Public ($case+'-plan') @('-NtlmAction','Plan','-ResultsPath',(Join-Path $root ($case+'-plan.json')))
        Assert ($plan.Plan.Status -ceq 'ChangeRequired' -and (Key $plan.Plan.Before) -ceq (Key $prepared)) 'Public plan retains the exact native absence/allow state and actual host.'
        $dryBackup=Join-Path $root ($case+'-dry-backup')
        $dry=Public ($case+'-dry') @('-NtlmAction','Configure','-Auto','-DryRun','-BackupPath',$dryBackup,'-ResultsPath',(Join-Path $root ($case+'-dry.json')))
        Assert ($dry.DryRun -and $dry.Results[0].Status -ceq 'Skipped' -and -not(Test-Path $dryBackup) -and (Key (Get-WelaOutgoingAuditSnapshot)) -ceq (Key $prepared)) 'Dry run preserves policy and creates no journal directory.'
        $backup=Join-Path $root ($case+'-backup')
        $report=Public $case @('-NtlmAction','Configure','-Auto','-BackupPath',$backup,'-ResultsPath',(Join-Path $root ($case+'.json')))
        $after=Get-WelaOutgoingAuditSnapshot
        Assert ($report.Scope -ceq 'outgoing-ntlm-audit-policy-only' -and $report.Results.Count -eq 1 -and $report.Results[0].Status -ceq 'Applied') 'Exactly one native outgoing policy is applied through public CLI.'
        Assert ($after.Policy.Type -ceq 'DWord' -and $after.Policy.Value -eq 1 -and (Key $report.Results[0].After) -ceq (Key $after)) 'Native audit-only readback matches the public result.'
        $journal=@(Get-Content (Join-Path $backup 'before.jsonl')|ConvertFrom-Json)
        Assert ($journal.Count -eq 1 -and (Key $journal[0].Before) -ceq (Key $prepared) -and $journal[0].Target.Path -ceq $path -and $journal[0].Target.Name -ceq $name) 'One original journal retains the actual typed policy and native context.'
        $repeatBackup=Join-Path $root ($case+'-repeat-backup')
        $repeat=Public ($case+'-repeat') @('-NtlmAction','Configure','-Auto','-BackupPath',$repeatBackup,'-ResultsPath',(Join-Path $root ($case+'-repeat.json')))
        Assert ($repeat.Results[0].Status -ceq 'AlreadyCompliant' -and -not(Test-Path (Join-Path $repeatBackup 'before.jsonl'))) 'Repeated configuration is idempotent without another original journal.'
        $audit=Public ($case+'-audit') @('-NtlmAction','Audit','-ResultsPath',(Join-Path $root ($case+'-audit.json')))
        Assert ($audit.Plan.Status -ceq 'AlreadyCompliant' -and $audit.ReadyRuleCredit -eq 0 -and $audit.EventGeneration -like 'Not verified*') 'Audit distinguishes registry compliance from event or authentication proof.'
        Assert ((Key (Other)) -ceq (Key $other) -and (Masks) -ceq $masks) 'Incoming/domain policies, siblings, access descriptor, channels, service and all59 masks remain unchanged.'
    }
    Save 'completed.json' @{Status='Passed';Assertions=$count;NativeWrites=2;Scope='Only outgoing audit DWORD1. No network authentication attempt, enforcement, event generation, GPO refresh or Sigma proof.'}
}catch{$failure=$_.ToString();throw}finally{
    try{
        if((Get-WelaRegistryState $path $name).ValueExists){Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop}
        if($original.Policy.ValueExists){$null=New-ItemProperty -LiteralPath $path -Name $name -Value $original.Policy.Value -PropertyType $original.Policy.Type}
    }catch{$errors+=$_.ToString()}
    $checks=[ordered]@{}
    foreach($pair in @(@('Policy',{(Key (Get-WelaOutgoingAuditSnapshot)) -ceq (Key $original)}),@('Unselected',{(Key (Other)) -ceq (Key $other)}),@('All59Masks',{(Masks) -ceq $masks}))){try{$checks[$pair[0]]=& $pair[1]}catch{$checks[$pair[0]]=$false;$errors+=$_.ToString()}}
    $complete=$errors.Count -eq 0 -and @($checks.Values|Where-Object {-not $_}).Count -eq 0
    Save 'cleanup.json' @{Complete=$complete;Checks=$checks;Errors=$errors;Failure=$failure;Assertions=$count}
    if(-not $complete){throw 'Outgoing NTLM native fixture cleanup failed.'}
}
Write-Host "PASS: $count native public outgoing NTLM assertions and exact cleanup."
exit 0
