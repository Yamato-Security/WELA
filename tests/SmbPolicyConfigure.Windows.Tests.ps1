param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Explicit opt-in on a disposable GitHub-hosted Windows runner is required.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/SmbAuditing.ps1')
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
$os=Get-CimInstance Win32_OperatingSystem;$computer=Get-CimInstance Win32_ComputerSystem
if($os.ProductType -ne 3 -or [int]$os.BuildNumber -notin @(20348,26100) -or $computer.DomainRole -ne 2 -or $computer.PartOfDomain){throw 'An unjoined disposable Server 2022/2025 is required.'}
$root=Join-Path $env:RUNNER_TEMP ('wela-smb-policy-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $root
$engine=(Get-Process -Id $PID).Path;$definitions=@(Get-WelaSmbAuditDefinitions);$count=0;$failure=$null;$errors=@()
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 24 -Compress}
function Save($Name,$Value){ConvertTo-Json -InputObject $Value -Depth 24|Set-Content -LiteralPath (Join-Path $root $Name) -Encoding UTF8}
function Masks { $m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';' }
function Runtime {
    foreach($side in @('Server','Client')){
        $cmd="Get-Smb${side}Configuration";$c=& $cmd -ErrorAction Stop
        [pscustomobject][ordered]@{Side=$side;Properties=@($c.CimInstanceProperties|Sort-Object Name|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;Type=$_.CimType.ToString();Value=$_.Value}})}
    }
}
function Policies {foreach($d in $definitions){[pscustomobject]@{Definition=$d;Policy=Get-WelaRegistryState $d.Path $d.Name}}}
function Keys {
    foreach($component in @('LanmanServer','LanmanWorkstation')){
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64);$k=$null
        try{
            $k=$base.OpenSubKey("SOFTWARE\Policies\Microsoft\Windows\$component")
            if(-not $k){[pscustomobject][ordered]@{Component=$component;Exists=$false;Values=@();Children=@();Access=$null};continue}
            $acl=if($PSVersionTable.PSVersion.Major -ge 6){[Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($k)}else{$k.GetAccessControl()}
            [pscustomobject][ordered]@{Component=$component;Exists=$true;Values=@($k.GetValueNames()|Sort-Object|ForEach-Object{[pscustomobject][ordered]@{Name=$_;Type=$k.GetValueKind($_).ToString();Value=$k.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}});Children=@($k.GetSubKeyNames()|Sort-Object);Access=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group)}
        }finally{if($k){$k.Dispose()};$base.Dispose()}
    }
}
function OtherKeys {
    $all=@(Keys)
    foreach($k in $all){$names=@($definitions|Where-Object Component -eq $k.Component|ForEach-Object Name);$k.Values=@($k.Values|Where-Object Name -NotIn $names)}
    return $all
}
function Public([string]$Name,[string[]]$Arguments,[int]$Expected=0){
    $prior=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$output=& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'WELA.ps1') smb-auditing @Arguments 2>&1|Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$prior}
    $output|Set-Content -LiteralPath (Join-Path $root ($Name+'.txt')) -Encoding UTF8
    Assert ($code -eq $Expected) "Public $Name exited $code : $output"
    Get-Content -Raw -LiteralPath (Join-Path $root ($Name+'.json'))|ConvertFrom-Json
}
$before=@(Policies);$keys=@(Keys);$runtime=@(Runtime);$masks=Masks
$services=@(Get-Service LanmanServer,LanmanWorkstation|Sort-Object Name|Select-Object Name,Status)
Save 'original.json' @{Policies=$before;Keys=$keys;Runtime=$runtime;Masks=$masks;Services=$services;Build=[int]$os.BuildNumber;UBR=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR;Engine=$PSVersionTable.PSVersion.ToString();PartOfDomain=$computer.PartOfDomain;DomainRole=$computer.DomainRole}
try{
    $initial=@(Get-WelaSmbAuditPlan)
    if([int]$os.BuildNumber -eq 20348){Assert (@($initial|Where-Object Status -ne NotApplicable).Count -eq 0) 'All six policies are genuinely not applicable on Server 2022.'}
    else{
        Assert (@($initial|Where-Object {$_.Status -notin @('ChangeRequired','PolicyConfigured')}).Count -eq 0) 'All six policies require exact local ADMX and readable native runtime before fixture writes.'
        foreach($d in $definitions){New-WelaRegistryKey $d.Path;$null=New-ItemProperty -LiteralPath $d.Path -Name $d.Name -Value 0 -PropertyType DWord -Force}
    }
    $prepared=@(Policies);$other=@(OtherKeys);Save 'prepared.json' $prepared
    $plan=Public plan @('-SmbAction','Plan','-ResultsPath',(Join-Path $root 'plan.json'))
    Assert ($plan.Controls.Count -eq 6) 'Public Plan accounts for exactly six controls.'
    $dry=Public dry @('-SmbAction','Configure','-DryRun','-BackupPath',(Join-Path $root 'dry-backup'),'-ResultsPath',(Join-Path $root 'dry.json'))
    Assert ($dry.DryRun -and @($dry.Results|Where-Object Status -eq Applied).Count -eq 0 -and -not(Test-Path (Join-Path $root 'dry-backup'))) 'Dry run does not change policy or create original journals.'
    Assert ((Key @(Policies)) -ceq (Key $prepared) -and (Key @(Runtime)) -ceq (Key $runtime)) 'Plan and DryRun preserve exact typed policy and full native runtime.'
    $applied=Public apply @('-SmbAction','Configure','-Auto','-BackupPath',(Join-Path $root 'apply-backup'),'-ResultsPath',(Join-Path $root 'apply.json'))
    Assert ($applied.Scope -ceq 'smb-audit-policies-only' -and $applied.Results.Count -eq 6) 'Public Configure retains narrow scope and all six outcomes.'
    if([int]$os.BuildNumber -eq 20348){
        Assert (@($applied.Results|Where-Object Status -ne Skipped).Count -eq 0 -and -not(Test-Path (Join-Path $root 'apply-backup/before.jsonl'))) 'Unsupported Server 2022 has six skipped controls and no policy writes.'
    }else{
        Assert (@($applied.Results|Where-Object Status -ne Applied).Count -eq 0) 'Server 2025 actually applied all six policy DWORDs.'
        $journal=@(Get-Content (Join-Path $root 'apply-backup/before.jsonl')|ConvertFrom-Json);Assert ($journal.Count -eq 6) 'Every actual write has an original journal entry.'
        foreach($row in $applied.Results){
            $j=@($journal|Where-Object Id -eq $row.Id);$p=@($prepared|Where-Object {$_.Definition.Path -ceq $row.Target.Path -and $_.Definition.Name -ceq $row.Target.Name})
            Assert ($j.Count -eq 1 -and $p.Count -eq 1 -and (Key $j[0].Before.Policy) -ceq (Key $p[0].Policy)) 'Each journal matches the actual typed original policy.'
            Assert ($row.After.Policy.Type -ceq 'DWord' -and $row.After.Policy.Value -eq 1 -and $row.After.PolicyRegistryConfigured) 'Actual native readback verifies each DWORD without inferring runtime state.'
        }
        $repeat=Public repeat @('-SmbAction','Configure','-Auto','-BackupPath',(Join-Path $root 'repeat-backup'),'-ResultsPath',(Join-Path $root 'repeat.json'))
        Assert (@($repeat.Results|Where-Object Status -ne AlreadyCompliant).Count -eq 0 -and -not(Test-Path (Join-Path $root 'repeat-backup/before.jsonl'))) 'Repeated public Configure is idempotent without another journal.'
    }
    Assert ((Key @(OtherKeys)) -ceq (Key $other) -and (Key @(Runtime)) -ceq (Key $runtime) -and (Masks) -ceq $masks) 'Sibling values, access descriptors, children, complete SMB runtime and all59 audit masks are preserved.'
    Save 'completed.json' @{Status='Passed';Assertions=$count;ActualPolicyWrites=$(if([int]$os.BuildNumber -eq 26100){6}else{0});Scope='Policy registry only; no SMB traffic, activation, GPO refresh, event generation or Sigma proof.'}
}catch{$failure=$_.ToString();throw}finally{
    foreach($row in $before){try{
        $d=$row.Definition;$old=$row.Policy;$now=Get-WelaRegistryState $d.Path $d.Name
        if($old.ValueExists){$null=New-ItemProperty -LiteralPath $d.Path -Name $d.Name -Value $old.Value -PropertyType $old.Type -Force}
        elseif($now.ValueExists){Remove-ItemProperty -LiteralPath $d.Path -Name $d.Name -ErrorAction Stop}
    }catch{$errors+=$_.ToString()}}
    foreach($k in $keys|Where-Object {-not $_.Exists}){try{
        $path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\$($k.Component)"
        if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path;if($item.ValueCount -ne 0 -or $item.SubKeyCount -ne 0){throw 'A fixture-created key is not empty; it was preserved.'};Remove-Item -LiteralPath $path -ErrorAction Stop}
    }catch{$errors+=$_.ToString()}}
    $checks=[ordered]@{}
    foreach($pair in @(@('Policies',{(Key @(Policies)) -ceq (Key $before)}),@('Keys',{(Key @(Keys)) -ceq (Key $keys)}),@('Runtime',{(Key @(Runtime)) -ceq (Key $runtime)}),@('AuditMasks',{(Masks) -ceq $masks}),@('Services',{(Key @(Get-Service LanmanServer,LanmanWorkstation|Sort-Object Name|Select-Object Name,Status)) -ceq (Key $services)}))){try{$checks[$pair[0]]=& $pair[1]}catch{$checks[$pair[0]]=$false;$errors+=$_.ToString()}}
    $complete=$errors.Count -eq 0 -and @($checks.Values|Where-Object {-not $_}).Count -eq 0
    Save 'cleanup.json' @{Complete=$complete;Checks=$checks;Errors=$errors;Failure=$failure;Assertions=$count}
    if(-not $complete){throw 'SMB native policy fixture cleanup failed; inspect retained receipts.'}
}
Write-Host "PASS: $count native public SMB policy assertions and exact cleanup."
exit 0
