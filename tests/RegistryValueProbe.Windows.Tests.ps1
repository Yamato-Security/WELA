param([switch]$AllowDisposableRegistryProbe)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableRegistryProbe -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable GitHub-hosted Windows fixture required.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -Force
foreach($name in @('Configuration','WefArrival','ChannelRead','WmiProbe','FileAccessProbe','RegistryValueProbe','SelectedSaclConfiguration')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
Initialize-WelaRegistryValueProbe;Initialize-WelaSelectedSaclNative
Add-Type -Path (Join-Path $PSScriptRoot 'RegistryValueProbeFixture.cs')
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-registry-value-probe-'+[guid]::NewGuid().ToString('N'))) $script:ScriptRoot
$engine=(Get-Process -Id $PID).Path;$count=0;$failure=$null;$cleanupErrors=@();$owner=$null;$policyTouched=$false
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){Get-WelaFileProbeKey $Value}
function Save($Name,$Value){[IO.File]::WriteAllText((Join-Path $root $Name),($Value|ConvertTo-Json -Depth 28),[Text.UTF8Encoding]::new($false))}
function Masks{$m=Get-WelaEffectiveAuditPolicy;@($m.Keys|Sort-Object|ForEach-Object{"$_=$($m[$_])"}) -join ';'}
function Channel{$c=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Security');try{[pscustomobject]@{Enabled=$c.IsEnabled;Size=$c.MaximumSizeInBytes;Mode=[string]$c.LogMode;Security=$c.SecurityDescriptor}}finally{$c.Dispose()}}
$token=[Wela.RegistryValueProbe.TokenReader]::Snapshot();$originalMasks=Get-WelaEffectiveAuditPolicy;$masks=Masks;$channel=Channel
$guid='0cce921e-69ae-11d9-bed3-505054503030';$p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$precedence=Get-WelaRegistryState $p SCENoApplyLegacyAuditPolicy
$hostState=Get-WelaChannelReadHost
Assert ($hostState.ProductType -eq 3 -and -not $hostState.DomainJoined) 'Actual disposable standalone Server required.'
Assert (-not $precedence.ValueExists -or ($precedence.Type -ceq 'DWord' -and $precedence.Value -in 0,1)) 'Unknown precedence is preserved.'
$softwareKey=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software')
try{$softwareBefore=@($softwareKey.GetSubKeyNames()|Sort-Object)}finally{$softwareKey.Dispose()}
Save 'original.json' @{Token=$token;Masks=$masks;Precedence=$precedence;Channel=$channel;Host=$hostState;Engine=$PSVersionTable.PSVersion.ToString();Commit=$env:GITHUB_SHA;Sources=Get-WelaRegistryValueProbeSources;SoftwareChildren=$softwareBefore}
try{
    $owner=[Wela.RegistryValueProbeFixture.Owner]::new([guid]::NewGuid().ToString('N'));$owner.Create()
    $path='HKEY_USERS\'+$token.Sid+'\Software\WELA\AuditProbe'
    $denied=Invoke-WelaRegistryValueProbe
    Assert ($denied.ExitCode -eq 1) 'Missing policy/SACL prerequisites refuse before mutation.'
    $privilege=[Wela.SelectedSacl.Privilege]::new();$target=$null
    try{$target=[Wela.SelectedSacl.Target]::new('Registry',$path);$before=$target.Read();$after=$target.Add($before.Identity,$before.DescriptorBase64,'S-1-1-0',2,64)}finally{if($target){$target.Dispose()};$privilege.Dispose()}
    Save 'prepared-key.json' $after
    $policyTouched=$true
    Set-ItemProperty -LiteralPath $p -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
    Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum
    $preparedMasks=Masks;$prepared=Get-WelaRegistryValueProbeState;Save 'prepared.json' $prepared
    $plan=Invoke-WelaRegistryValueProbe
    Assert ($plan.ExitCode -eq 0 -and $plan.Status -ceq 'PrerequisitesObserved' -and -not $plan.Operation) 'Plan reads existing prerequisites without value writes.'
    for($case=1;$case -le 2;$case++){
        $outputPath=Join-Path $root ('public-'+$case)
        $old=$ErrorActionPreference
        try{$ErrorActionPreference='Continue';$output=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $script:ScriptRoot 'WELA.ps1') registry-probe -RegistryProbeAction Run -RegistryProbeOutputPath $outputPath 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old;$global:LASTEXITCODE=0}
        Save ('public-'+$case+'-output.json') @($output|ForEach-Object{[string]$_})
        Assert ($code -eq 0) ('Public registry probe failed: '+($output -join ' '))
        $report=ConvertFrom-WelaArrivalJson ([IO.File]::ReadAllText((Join-Path $outputPath 'manifest.json')))
        Assert ($report.Status -ceq 'RegistryValueModificationObserved' -and $report.Matches -eq 1 -and $report.ConfigurationChanges -eq 0 -and $report.SigmaEvtxCredit -eq 0) 'Exactly one4657 is attributed without configuration/rule credit.'
        Assert-WelaRegistryValueProbeOperation $report.Operation $report.Before
        $xml=[IO.File]::ReadAllText((Join-Path $outputPath 'event.xml'))
        Assert (Test-WelaRegistryValueProbeEvent $xml $report.Operation $report.Before) 'Independent matcher verifies exact native4657 key/value/old/new/type/handle/PID/token/time.'
        foreach($artifact in $report.Artifacts){Assert ((Get-FileHash -LiteralPath (Join-Path $outputPath $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'Saved product artifact hash matches.'}
        $current=Get-WelaRegistryValueProbeState
        Assert ((Get-WelaRegistryValueProbeStateKey $current) -ceq (Get-WelaRegistryValueProbeStateKey $prepared)) 'Full stable host/token/descriptor/value/mask/channel/source state is preserved.'
        Assert ((Masks) -ceq $preparedMasks) 'All59 prepared masks unchanged.'
    }
    Save 'completed.json' @{Status='Passed';Assertions=$count;Exact4657=2;ProbeValuesRemoved=2;Scope='Only fixed owned current-user probe key on actual standalone Server; no arbitrary/production/remote/DC/CA or forwarding credit.'}
}catch{$failure=$_.ToString();Save 'failure.json' @{Error=$failure;Stack=$_.ScriptStackTrace}}
finally{
    if($policyTouched){try{Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $originalMasks[$guid] -Mode exact}catch{$cleanupErrors+=$_.ToString()};try{if($precedence.ValueExists){Set-ItemProperty -LiteralPath $p -Name SCENoApplyLegacyAuditPolicy -Value $precedence.Value -Type $precedence.Type}else{Remove-ItemProperty -LiteralPath $p -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop}}catch{$cleanupErrors+=$_.ToString()}}
    if($owner){try{$owner.Dispose()}catch{$cleanupErrors+=$_.ToString()}}
    $checks=[ordered]@{}
    foreach($pair in @(@('All59Masks',{(Masks) -ceq $masks}),@('Precedence',{(Key (Get-WelaRegistryState $p SCENoApplyLegacyAuditPolicy)) -ceq (Key $precedence)}),@('Token',{(Key ([Wela.RegistryValueProbe.TokenReader]::Snapshot())) -ceq (Key $token)}),@('Channel',{(Key (Channel)) -ceq (Key $channel)}),@('OwnedKeyRemoved',{-not(Test-Path 'HKCU:\Software\WELA')}))){try{$checks[$pair[0]]=& $pair[1]}catch{$checks[$pair[0]]=$false;$cleanupErrors+=$_.ToString()}}
    $complete=$cleanupErrors.Count -eq 0 -and @($checks.Values|Where-Object {-not $_}).Count -eq 0
    Save 'cleanup.json' @{Complete=$complete;Checks=$checks;Errors=$cleanupErrors;Failure=$failure;Assertions=$count}
    Save 'artifact-hashes.json' @(Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object Name -ne 'artifact-hashes.json'|Sort-Object FullName|ForEach-Object{[pscustomobject]@{Name=$_.FullName.Substring($root.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}})
    if(-not $complete){throw 'Registry probe native cleanup failed.'}
}
if($failure){throw $failure}
Write-Host "PASS: $count native public registry4657 assertions and exact cleanup."
