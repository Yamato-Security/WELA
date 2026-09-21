$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
. (Join-Path $root 'scripts/SelectedSaclConfiguration.ps1')
$script:count=0
function Assert($Condition,$Message){if(-not $Condition){throw $Message};$script:count++}
function Clone($Value){$Value|ConvertTo-Json -Depth 24|ConvertFrom-Json}
function Throws($Action,$Pattern){$message='';try{& $Action|Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern, got $message"}
function Snapshot($Path,[bool]$Directory=$false){
    [pscustomobject]@{SecurityInformation=511;DescriptorScope='WinSDK-defined sections 0x1ff; future sections unobserved';Path=$Path;Kind='FileSystem';Identity=$Path;IsDirectory=$Directory;DescriptorBase64=('before-'+$Path);Owner='S-1-5-18';Group='S-1-5-18';DaclBase64='dacl';ControlFlags=32788;Aces=@([pscustomobject]@{Binary='original';Type=17;Flags=0;Mask=0;Sid=$null;Ordinary=$false})}
}
$script:definition=[pscustomobject]@{Origin='fixture';Scope='files';UserSid=$null;Path='C:\owned';Kind='FileSystem';Resolution='Resolved';PrincipalSid='S-1-1-0';Propagation='None';Inheritance='ContainerInherit,ObjectInherit';Rights=@('ReadData');AuditFlags=@('Success');Policy='fixture';PolicyMode='minimum';PolicySelected=$true;RequiredPolicyMask=1}
$key=Get-WelaSelectedSaclDefinitionKey $script:definition;$script:id='sacl-'+$key.Substring(0,24)
function Get-WelaSelectedSaclContext {[pscustomobject]@{Computer='fixture';Role='MemberServer';Build=26100;Key='same-host'}}
function Get-WelaSelectedSaclCatalog {param($Profile,$IncludeOptional,$Context) [pscustomobject]@{Profile=$Profile;Rows=@([pscustomobject]@{Id=$script:id;DefinitionKey=(Get-WelaSelectedSaclDefinitionKey $script:definition);Definition=$script:definition});UserInventory=@()}}
function Assert-WelaSelectedSaclPrerequisites {}
$script:states=@{};$script:names=@{};$script:scenario='';$script:writes=0;$script:enumerations=0
function Reset {
    $script:states=@{};$script:names=@{};$script:scenario='';$script:writes=0;$script:enumerations=0
    $script:states['C:\owned']=Snapshot 'C:\owned' $true
    $script:states['C:\owned\open']=Snapshot 'C:\owned\open' $true
    $script:states['C:\owned\open\leaf']=Snapshot 'C:\owned\open\leaf'
    $script:states['C:\owned\protected']=Snapshot 'C:\owned\protected' $true
    $script:states['C:\owned\protected'].ControlFlags=32788 -bor 8192
    $script:states['C:\owned\protected\leaf']=Snapshot 'C:\owned\protected\leaf'
    $script:names['C:\owned']=@('open','protected');$script:names['C:\owned\open']=@('leaf');$script:names['C:\owned\protected']=@('leaf')
}
function Get-WelaSelectedSaclSnapshot {
    param($Definition)
    if($Definition.Path -eq 'C:\owned\open\leaf' -and $script:scenario -eq 'after-pending-drift' -and (Test-Path (Join-Path $script:backup ($script:id+'.pending.json')))){$script:states[$Definition.Path].DescriptorBase64='changed';$script:scenario=''}
    if($Definition.Path -eq 'C:\owned\open\leaf' -and $script:scenario -eq 'final-drift' -and (Test-Path (Join-Path $script:backup ($script:id+'.confirmed.json')))){$script:states[$Definition.Path].DescriptorBase64='changed';$script:scenario=''}
    if($script:scenario -eq 'denied' -and $Definition.Path -eq 'C:\owned\open\leaf'){throw 'Native descendant access denied'}
    if(-not $script:states.ContainsKey($Definition.Path)){throw 'Missing child'}
    Clone $script:states[$Definition.Path]
}
function Get-WelaSelectedSaclChildNames {
    param($Definition,$Snapshot,$Maximum)
    $script:enumerations++
    if($script:scenario -eq 'reparse'){throw 'Reparse-point target refused'}
    if($script:scenario -eq 'registry-link'){throw 'Registry symbolic-link component refused'}
    if($script:scenario -eq 'capture-drift' -and $script:enumerations -eq 4){$script:states['C:\owned\open\leaf'].DescriptorBase64='changed'}
    $children=@($script:names[$Definition.Path] | Where-Object {$null -ne $_})
    [pscustomobject]@{Names=@($children|Select-Object -First $Maximum);Truncated=($children.Count -gt $Maximum)}
}
function Add-Ace($Snapshot,$Ace,[bool]$Inherited){
    $flags=$Ace.Flags
    if($Inherited){$flags=($Ace.Flags -band 192) -bor 16;if($Snapshot.IsDirectory -or $Snapshot.Kind -eq 'Registry'){$flags=$flags -bor ($Ace.Flags -band 3)}}
    $Snapshot.Aces+=@([pscustomobject]@{Binary=('added-'+$flags);Type=2;Flags=$flags;Mask=$Ace.Mask;Sid=$Ace.Sid;Ordinary=$true})
    $Snapshot.DescriptorBase64='after-'+$Snapshot.DescriptorBase64
}
function Write-WelaSelectedSaclNative {
    param($Definition,$Before,$Ace)
    $script:writes++
    $pending=Get-Content -LiteralPath (Join-Path $script:backup ($script:id+'.pending.json')) -Raw|ConvertFrom-Json
    Assert ($pending.State -eq 'Pending' -and $pending.DescendantsBefore.Entries.Count -eq 4) 'Every reviewed child snapshot is durably recorded before root write.'
    if($script:scenario -eq 'native-failure'){throw 'Native root write failed'}
    Add-Ace $script:states['C:\owned'] $Ace $false
    if($script:scenario -ne 'missing-inheritance'){
        Add-Ace $script:states['C:\owned\open'] $Ace $true
        Add-Ace $script:states['C:\owned\open\leaf'] $Ace $true
    }
    switch($script:scenario){
        child-dacl {$script:states['C:\owned\open\leaf'].DaclBase64='changed'}
        child-identity {$script:states['C:\owned\open\leaf'].Identity='replacement'}
        child-ace-loss {$script:states['C:\owned\open\leaf'].Aces=@($script:states['C:\owned\open\leaf'].Aces|Where-Object Binary -ne 'original')}
        protected-drift {$script:states['C:\owned\protected\leaf'].DescriptorBase64='changed'}
        child-new {$script:names['C:\owned\open']+=@('new');$script:states['C:\owned\open\new']=Snapshot 'C:\owned\open\new'}
        child-disappeared {$script:names['C:\owned\open']=@()}
        after-denied {$script:scenario='denied'}
    }
    Clone $script:states['C:\owned']
}
function Read-Host {
    if($script:scenario -eq 'prompt-child-drift'){$script:states['C:\owned\open\leaf'].DescriptorBase64='changed'}
    'y'
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-descendants-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
function Review {
    Reset
    $script:planPath=Join-Path $temp ([guid]::NewGuid().ToString('N')+'.json');$script:backup=Join-Path $temp ([guid]::NewGuid().ToString('N'))
    Invoke-WelaSelectedSacl -Action Plan -Profile fixture -Ids $script:id -IncludeChildren -ResultsPath $script:planPath
}
function Apply([switch]$DryRun){Invoke-WelaSelectedSacl -Action Configure -PlanPath $script:planPath -Ids $script:id -IncludeChildren -BackupPath $script:backup -DryRun:$DryRun}
try {
    $plan=Review
    Assert ($plan.Rows[0].Status -eq 'ChangeRequired' -and $plan.Rows[0].DescendantsBefore.Entries.Count -eq 4 -and $script:writes -eq 0) 'Complete plan captures populated tree without native writes.'
    Assert (@($plan.Rows[0].DescendantsBefore.Entries|Where-Object ProtectedBarrier).Count -eq 2) 'Protection propagates as an observation barrier to the protected subtree.'
    $result=Apply -DryRun
    Assert ($result.Results[0].Status -eq 'Skipped' -and -not(Test-Path $script:backup)) 'Descendant review does not weaken DryRun.'
    $result=Apply
    Assert ($result.ExitCode -eq 0 -and $result.Results[0].Status -eq 'Applied') 'Root addition with observed inheritance and preserved protected children succeeds.'
    Assert (@($result.Results[0].DescendantVerification.Outcomes|Where-Object Status -eq 'InheritedAceObserved').Count -eq 2) 'Directory and leaf inheritance are separately observed.'
    Assert (@($result.Results[0].DescendantVerification.Outcomes|Where-Object Status -eq 'ProtectedUnchanged').Count -eq 2) 'Protected descendants remain unchanged and are never called inherited coverage.'
    $receipt=Get-Content (Join-Path $script:backup ($script:id+'.confirmed.json')) -Raw|ConvertFrom-Json
    Assert ($receipt.DescendantVerification.Status -eq 'Observed' -and $receipt.Ownership -match 'never descendant') 'Confirmed root receipt explicitly excludes child ownership.'
    $script:planPath=Join-Path $temp 'again.json';$script:backup=Join-Path $temp 'again-backup'
    $null=Invoke-WelaSelectedSacl -Action Plan -Profile fixture -Ids $script:id -IncludeChildren -ResultsPath $script:planPath
    $result=Apply
    Assert ($result.Results[0].Status -eq 'AlreadyCompliant' -and $script:writes -eq 1) 'Reviewed populated-tree rerun adds no duplicate root or child ACE.'
    foreach($case in @('denied','reparse','registry-link','capture-drift')){
        Reset;$script:scenario=$case
        $capture=Get-WelaSelectedSaclStableDescendants $script:definition (Get-WelaSelectedSaclSnapshot $script:definition)
        Assert ($capture.Status -eq 'Incomplete') "$case cannot be a complete descendant inventory."
    }
    Reset;$script:names['C:\owned']=@(1..129|ForEach-Object{"child$_"})
    $capture=Get-WelaSelectedSaclStableDescendants $script:definition (Get-WelaSelectedSaclSnapshot $script:definition)
    Assert ($capture.Status -eq 'Incomplete' -and ($capture.Diagnostics -join '') -match '128') 'Count cap blocks rather than silently truncating coverage.'
    Reset;$path='C:\owned';$script:names=@{}
    foreach($i in 1..17){$script:names[$path]=@('deep');$path+='\deep';$script:states[$path]=Snapshot $path $true}
    $capture=Get-WelaSelectedSaclStableDescendants $script:definition (Get-WelaSelectedSaclSnapshot $script:definition)
    Assert ($capture.Status -eq 'Incomplete' -and ($capture.Diagnostics -join '') -match 'depth') 'Depth cap is explicit and blocks writes.'
    Reset;$script:states['C:\owned\open\leaf'].Identity=$script:states['C:\owned\protected\leaf'].Identity
    $capture=Get-WelaSelectedSaclStableDescendants $script:definition (Get-WelaSelectedSaclSnapshot $script:definition)
    Assert ($capture.Status -eq 'Incomplete' -and ($capture.Diagnostics -join '') -match 'identity') 'Hard-link aliases cannot be called unique verified descendants.'
    Reset;$script:states['C:\owned\open\leaf'].DescriptorBase64='x'*2097153
    $capture=Get-WelaSelectedSaclStableDescendants $script:definition (Get-WelaSelectedSaclSnapshot $script:definition)
    Assert ($capture.Status -eq 'Incomplete' -and ($capture.Diagnostics -join '') -match '2 MiB') 'Snapshot evidence cap cannot truncate backups silently.'
    $child=New-WelaSelectedSaclChildDefinition Registry 'HKEY_USERS\S-1-5-21-1\owned\child'
    Assert ($child.Path -ceq 'Registry::HKEY_USERS\S-1-5-21-1\owned\child') 'Enumerated native registry paths keep an explicit provider boundary.'
    Throws {Resolve-WelaSelectedSaclNativePath (New-WelaSelectedSaclChildDefinition Registry 'HKEY_USERS')} 'canonical existing HKLM/HKU'
    Assert ((Resolve-WelaSelectedSaclNativePath $child) -ceq 'HKEY_USERS\S-1-5-21-1\owned\child') 'Native registry path validation does not perform a provider lookup that could follow a registry link.'
    foreach($case in @('child-dacl','child-identity','child-ace-loss','protected-drift','child-new','child-disappeared','missing-inheritance','after-denied','native-failure')){
        $null=Review;$script:scenario=$case;$result=Apply
        Assert ($result.ExitCode -eq 1 -and $result.Results[0].Status -eq 'Failed') "$case fails without claiming complete propagation."
        Assert ((Test-Path (Join-Path $script:backup ($script:id+'.pending.json'))) -and -not(Test-Path (Join-Path $script:backup ($script:id+'.confirmed.json')))) "$case retains Pending evidence without confirmed root/child ownership."
    }
    $null=Review;$script:scenario='prompt-child-drift';$result=Apply
    Assert ($result.ExitCode -eq 1 -and $script:writes -eq 0 -and -not(Test-Path (Join-Path $script:backup ($script:id+'.pending.json')))) 'Fresh child race after review/prompt refuses root mutation.'
    $null=Review;$script:scenario='after-pending-drift';$result=Apply
    Assert ($result.ExitCode -eq 1 -and $script:writes -eq 0 -and (Test-Path (Join-Path $script:backup ($script:id+'.pending.json'))) -and -not(Test-Path (Join-Path $script:backup ($script:id+'.confirmed.json')))) 'Race after Pending backup cannot authorize a native write or Confirmed ownership.'
    $null=Review;$script:scenario='final-drift';$result=Apply
    Assert ($result.ExitCode -eq 1 -and $result.Results[0].Diagnostic -match 'Final descendant' -and (Test-Path (Join-Path $script:backup ($script:id+'.confirmed.json')))) 'Final child drift fails the run despite an earlier confirmed observation.'
    $null=Review;$script:states['C:\owned\open\leaf'].Identity='replaced'
    Throws {Apply} 'preflight failed'
    Assert ($script:writes -eq 0 -and -not(Test-Path $script:backup)) 'Changed child identity blocks the whole preflight before journal creation.'
    $null=Review;$before=Get-WelaSelectedSaclSnapshot $script:definition;$ace=Get-WelaSelectedSaclAce $script:definition $before -IncludeChildren
    Add-Ace $script:states['C:\owned'] $ace $false
    $incomplete=Invoke-WelaSelectedSacl -Action Plan -Profile fixture -Ids $script:id -IncludeChildren
    Assert ($incomplete.Rows[0].Status -eq 'Blocked' -and $incomplete.Rows[0].Diagnostic -match 'already has') 'Compliant root with missing child inheritance never produces a false AlreadyCompliant claim or duplicate write.'
    Write-Host "PASS: $script:count descendant SACL fixture assertions; all native reads and writes mocked."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
