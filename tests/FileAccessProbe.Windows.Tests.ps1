param([switch]$AllowDisposablePolicyWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposablePolicyWrite -or $env:GITHUB_ACTIONS -ne 'true' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'Only an explicitly permitted disposable GitHub-hosted native Windows runner is supported.'}
$script:ScriptRoot=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:ScriptRoot 'modules/AuditProfiles.psm1') -ErrorAction Stop
foreach($name in @('Configuration','WefArrival','ChannelRead','WmiProbe','FileAccessProbe','SelectedSaclConfiguration')){. (Join-Path $script:ScriptRoot ('scripts/'+$name+'.ps1'))}
Initialize-WelaFileProbeNative;Initialize-WelaSelectedSaclNative
$engine=(Get-Process -Id $PID).Path;$script:checks=0
function Assert($Value,[string]$Message){if(-not $Value){throw "FAIL: $Message"};$script:checks++}
function Policy-Key($Policy){$ordered=[ordered]@{};foreach($key in @($Policy.Keys|Sort-Object)){$ordered[$key]=$Policy[$key]};Get-WelaFileProbeKey $ordered}
function Invoke-PublicFileProbe([string[]]$Arguments,[string]$Log,[bool]$Success=$true){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$lines=@(& $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $script:ScriptRoot 'WELA.ps1') @Arguments 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old;$global:LASTEXITCODE=0};$text=$lines -join "`n";[IO.File]::WriteAllText($Log,$text,[Text.UTF8Encoding]::new($false));if(($Success -and $code -ne 0) -or (-not $Success -and $code -eq 0)){throw "Unexpected public CLI result $code : $text"};$start=$text.IndexOf('{');if($start -lt 0){throw 'Public CLI returned no JSON report.'};ConvertFrom-WelaArrivalJson $text.Substring($start)}
function Add-OwnedReadSacl([string]$Path){$privilege=[Wela.SelectedSacl.Privilege]::new();$target=$null;try{$target=[Wela.SelectedSacl.Target]::new('FileSystem',$Path);$before=$target.Read();$null=$target.Add($before.Identity,$before.DescriptorBase64,'S-1-1-0',1,64)}finally{if($target){$target.Dispose()};$privilege.Dispose()}}
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-file-access-'+[guid]::NewGuid().ToString('N'))) $script:ScriptRoot
$targetRoot=Join-Path $root 'owned-targets';$null=New-Item -ItemType Directory $targetRoot
$file=Join-Path $targetRoot 'ReadCase.TxT';$plain=Join-Path $targetRoot 'WithoutAudit.txt'
[IO.File]::WriteAllText($file,'WELA owned harmless file probe fixture.',[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($plain,'WELA owned file without a matching audit ACE.',[Text.UTF8Encoding]::new($false))
$fileHash=(Get-FileHash $file).Hash;$beforePolicies=Get-WelaEffectiveAuditPolicy;$precedencePath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';$beforePrecedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
$originalToken=Get-WelaFileProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot());$changed=$false;$cleanupErrors=@()
[IO.File]::WriteAllText((Join-Path $root 'original-audit-policy.json'),(Policy-Key $beforePolicies),[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $root 'original-precedence.json'),(Get-WelaFileProbeKey $beforePrecedence),[Text.UTF8Encoding]::new($false))
try {
    $changed=$true;Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type DWord -Value 1
    Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask 1 -Mode exact
    Add-OwnedReadSacl $file
    $before=Get-WelaFileProbeSnapshot $file;$beforeKey=$before.StateKey
    $plan=Invoke-PublicFileProbe @('file-access-probe','-FileProbePath',$file.ToLowerInvariant()) (Join-Path $root 'plan.log')
    Assert ($plan.Status -ceq 'PrerequisitesObserved' -and $plan.Before.File.Path -ieq $file -and $plan.Before.File.StateKey -ceq $beforeKey) 'public Plan accepts Windows path casing and verifies the exact existing file SACL/policy'
    foreach($index in 1..2){
        $output=Join-Path $root ('run-'+$index)
        $report=Invoke-PublicFileProbe @('file-access-probe','-FileProbeAction','Run','-FileProbePath',$file.ToLowerInvariant(),'-FileProbeOutputPath',$output) (Join-Path $root ('run-'+$index+'.log'))
        Assert ($report.Status -ceq 'FileReadObserved' -and $report.Matches -eq 1) 'public one-byte read produced exactly one attributable actual4663'
        Assert ($report.Operation.Read.ReadCalls -eq 1 -and $report.Operation.Read.BytesRead -eq 1 -and $report.RetainedContentBytes -eq 0 -and $report.SigmaEvtxCredit -eq 0) 'one byte is read without retaining contents or granting Sigma credit'
        Assert ($report.Before.File.StateKey -ceq $beforeKey -and $report.After.File.StateKey -ceq $beforeKey -and (Get-FileHash $file).Hash -ceq $fileHash) 'existing file data, native identity and full descriptor remain unchanged'
        Assert (Test-WelaFileProbeEvent ([IO.File]::ReadAllText((Join-Path $output 'event.xml'))) $report.Operation $report.Before) 'retained native XML matches operation PID, handle, SID, logon, path, right and precise interval'
        foreach($artifact in $report.Artifacts){Assert ((Get-FileHash (Join-Path $output $artifact.Name)).Hash.ToLowerInvariant() -ceq $artifact.Sha256) 'retained artifact hash matches its public manifest'}
    }
    $missing=Invoke-PublicFileProbe @('file-access-probe','-FileProbePath',$plain) (Join-Path $root 'missing-sacl.log') $false
    Assert ($missing.Status -ceq 'Unverified' -and $missing.Diagnostic -match 'No existing ordinary success ReadData' -and $null -eq $missing.Operation) 'real missing SACL refuses access without adding an ACE'
    Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask 0 -Mode exact
    $disabled=Invoke-PublicFileProbe @('file-access-probe','-FileProbeAction','Run','-FileProbePath',$file,'-FileProbeOutputPath',(Join-Path $root 'disabled-policy')) (Join-Path $root 'disabled-policy.log') $false
    Assert ($disabled.Status -ceq 'Unverified' -and $disabled.Diagnostic -match 'File System success auditing' -and $null -eq $disabled.Operation) 'real disabled auditing refuses the byte read'
    Assert (-not(Test-Path (Join-Path $root 'disabled-policy/intent.json'))) 'failed prerequisites produce no pending read intent'
    Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask 1 -Mode exact
    $oldState=Get-WelaFileProbeState $file
    $replacement=Join-Path $targetRoot 'Replacement.txt';[IO.File]::WriteAllText($replacement,'WELA owned replacement.',[Text.UTF8Encoding]::new($false));Add-OwnedReadSacl $replacement
    Remove-Item -LiteralPath $file -Force;Move-Item -LiteralPath $replacement -Destination $file
    $message='';try{Start-WelaFileProbeRead $oldState (Join-Path $root 'not-used.json') ([guid]::NewGuid().ToString('N'))|Out-Null}catch{$message=$_.Exception.Message}
    Assert ($message -match 'drifted before worker launch') 'real replaced native file identity refuses a stale preflight before launching a worker'
    $held=[Wela.FileAccessProbe.FileHandle]::new($file,$false)
    try{$denied=$false;try{Remove-Item -LiteralPath $file -Force -ErrorAction Stop}catch{$denied=$true};Assert $denied 'held native observation handle prevents deletion of the selected file'}finally{$held.Dispose()}
} finally {
    if($changed){try{Set-WelaEffectiveAuditPolicy -Guid '0CCE921D-69AE-11D9-BED3-505054503030' -Mask $beforePolicies['0CCE921D-69AE-11D9-BED3-505054503030'] -Mode exact;if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type $beforePrecedence.Type -Value $beforePrecedence.Value}else{Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop}}catch{$cleanupErrors+=$_.Exception.Message}}
    $auditRestored=(Policy-Key (Get-WelaEffectiveAuditPolicy)) -ceq (Policy-Key $beforePolicies)
    $precedenceRestored=(Get-WelaFileProbeKey (Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy)) -ceq (Get-WelaFileProbeKey $beforePrecedence)
    $tokenRestored=(Get-WelaFileProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot())) -ceq $originalToken
    try{Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction Stop}catch{$cleanupErrors+=$_.Exception.Message}
    $cleanup=[pscustomobject]@{Complete=($auditRestored -and $precedenceRestored -and $tokenRestored -and -not(Test-Path $targetRoot) -and $cleanupErrors.Count -eq 0);AuditPoliciesRestored=$auditRestored;PrecedenceRestored=$precedenceRestored;TokenRestored=$tokenRestored;OwnedTargetsRemoved=(-not(Test-Path $targetRoot));Errors=$cleanupErrors;Checks=$script:checks;Engine=$PSVersionTable.PSVersion.ToString();AfterAuditPolicies=(Get-WelaEffectiveAuditPolicy);AfterPrecedence=(Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy)}
    [IO.File]::WriteAllText((Join-Path $root 'cleanup.json'),($cleanup|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    if(-not $cleanup.Complete){throw "Native file-probe cleanup incomplete: $($cleanup|ConvertTo-Json -Compress -Depth 10)"}
}
Write-Host "Passed $script:checks actual native file-access assertions; all59 audit masks, typed precedence, privileges and owned-target cleanup verified. Evidence: $root"
$global:LASTEXITCODE=0
