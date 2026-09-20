param([switch]$AllowDisposableSaclWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableSaclWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'This mutating fixture requires explicit opt-in on a disposable GitHub-hosted Windows runner.'}
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/Configuration.ps1')
. (Join-Path $root 'scripts/TargetedSaclPlanning.ps1')
. (Join-Path $root 'scripts/SelectedSaclConfiguration.ps1')
$script:count=0
function Assert($Condition,$Message){if(-not $Condition){throw $Message};$script:count++}
function Fingerprint($Map){(@($Map.Keys|Sort-Object|ForEach-Object{"$_=$($Map[$_])"}) -join ';')}
$beforePolicy=Get-WelaEffectiveAuditPolicy
$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$beforePrecedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
$privilegeBefore=(Invoke-WelaNative whoami.exe @('/priv','/fo','csv')).Diagnostic
$nonce=[guid]::NewGuid().ToString('N');$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-sacl-'+$nonce)
$regSub='Software\WELASelectedSacl_'+$nonce;$regProvider='HKCU:\'+$regSub
$file=Join-Path $temp 'probe.txt';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$policyGuids=@('0CCE921D-69AE-11D9-BED3-505054503030','0CCE921E-69AE-11D9-BED3-505054503030')
$restored=$false
try {
    $null=New-Item -ItemType Directory -Path $temp
    [IO.File]::WriteAllText($file,'WELA selected-SACL disposable fixture')
    $null=New-Item -Path $regProvider
    $fileDefinition=[pscustomobject]@{Path=$file;Kind='FileSystem';Resolution='Resolved';PrincipalSid='S-1-1-0';Propagation='None';Inheritance='None';Rights=@('ReadData');AuditFlags=@('Success');PolicyMode='minimum';PolicySelected=$true;RequiredPolicyMask=1}
    $regDefinition=[pscustomobject]@{Path=('Registry::HKEY_USERS\'+$sid+'\'+$regSub);Kind='Registry';Resolution='Resolved';PrincipalSid='S-1-1-0';Propagation='None';Inheritance='None';Rights=@('SetValue');AuditFlags=@('Success');PolicyMode='minimum';PolicySelected=$true;RequiredPolicyMask=1}
    Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
    foreach($guid in $policyGuids){Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum}
    $snapshots=@{}
    foreach($definition in @($fileDefinition,$regDefinition)){
        Write-Host ("Reading full native descriptor for owned "+$definition.Kind+" fixture.")
        $before=Get-WelaSelectedSaclSnapshot $definition
        Assert ($before.SecurityInformation -eq 511 -and $before.DescriptorScope -match 'future sections unobserved') 'Native receipt records all current SDK sections with its bounded observation scope.'
        $ace=Get-WelaSelectedSaclAce $definition $before
        Assert (-not(Test-WelaSelectedSaclAce $before $ace)) 'Fresh owned target has no requested audit ACE.'
        Assert-WelaSelectedSaclPrerequisites $definition $ace
        $after=Write-WelaSelectedSaclNative $definition $before $ace
        Assert-WelaSelectedSaclPreserved $before $after $ace
        Assert ((Get-WelaSelectedSaclSnapshotKey (Get-WelaSelectedSaclSnapshot $definition)) -ceq (Get-WelaSelectedSaclSnapshotKey $after)) 'Native readback is stable after additive SACL write.'
        Assert (Test-WelaSelectedSaclAce $after $ace) 'Requested explicit native audit ACE matches on re-read, providing idempotence input.'
        $snapshots[$definition.Kind]=$after
        $caught='';try{Write-WelaSelectedSaclNative $definition $before $ace|Out-Null}catch{$caught=$_.Exception.Message}
        Assert ($caught -match 'changed after') 'Stale descriptor is refused by the real native handle writer.'
    }
    $started=[DateTime]::UtcNow.AddSeconds(-1)
    $null=[IO.File]::ReadAllText($file)
    $valueName='Probe_'+$nonce
    New-ItemProperty -LiteralPath $regProvider -Name $valueName -PropertyType String -Value $nonce | Out-Null
    $found=@{};$deadline=[DateTime]::UtcNow.AddSeconds(20)
    while($found.Count -lt 2 -and [DateTime]::UtcNow -lt $deadline){
        $events=@();try{$events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4657,4663);StartTime=$started} -MaxEvents 512 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){throw}}
        foreach($event in $events){
            try {
                $xml=[xml]$event.ToXml();$data=@{};foreach($node in $xml.Event.EventData.Data){$data[[string]$node.Name]=[string]$node.'#text'}
                if($event.ProviderName -ne 'Microsoft-Windows-Security-Auditing'){continue}
                if($event.Id -eq 4663 -and $data.ObjectName -ieq $file -and [Convert]::ToInt64(($data.ProcessId -replace '^0x',''),16) -eq $PID){$found.FileSystem=$event.ToXml()}
                $expectedRegistry='\REGISTRY\USER\'+$sid+'\'+$regSub
                if($event.Id -eq 4657 -and $data.ObjectName -ieq $expectedRegistry -and $data.ObjectValueName -ceq $valueName -and $data.NewValue -ceq $nonce){$found.Registry=$event.ToXml()}
            }finally{if($event -is [IDisposable]){$event.Dispose()}}
        }
        if($found.Count -lt 2){Start-Sleep -Milliseconds 250}
    }
    Assert ($found.ContainsKey('FileSystem')) 'Benign exact file read generated matched native4663 XML.'
    Assert ($found.ContainsKey('Registry')) 'Benign unique registry value write generated matched native4657 XML.'
    foreach($kind in @('FileSystem','Registry')){Write-Host ("Native fixture evidence "+$kind+': '+$found[$kind])}
    Assert ((Invoke-WelaNative whoami.exe @('/priv','/fo','csv')).Diagnostic -ceq $privilegeBefore) 'Native target adapters restore process privilege state after success and refused writes.'
    Write-Host "PASS: $script:count actual selected-SACL assertions on owned disposable targets only; no Sigma/backend/descendant claim."
} finally {
    foreach($guid in $policyGuids){Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $beforePolicy[$guid] -Mode exact}
    if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type $beforePrecedence.Type -Value $beforePrecedence.Value}
    else{Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue}
    $afterPolicy=Get-WelaEffectiveAuditPolicy;$afterPrecedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
    if((Fingerprint $beforePolicy) -cne (Fingerprint $afterPolicy) -or ($beforePrecedence|ConvertTo-Json -Compress) -cne ($afterPrecedence|ConvertTo-Json -Compress)){throw "Fixture policy restoration failed; retain owned evidence at $temp and $regProvider."}
    if(Test-Path -LiteralPath $regProvider){Remove-Item -LiteralPath $regProvider -Recurse -Force}
    if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}
    $restored=$true
    Write-Host 'PASS: all59 native audit masks and typed precedence restored; only owned disposable targets removed.'
}
$global:LASTEXITCODE=0
