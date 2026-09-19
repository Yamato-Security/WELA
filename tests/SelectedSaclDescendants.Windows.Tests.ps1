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
    $null=New-Item -Path $regProvider
    Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
    foreach($guid in $policyGuids){Set-WelaEffectiveAuditPolicy -Guid $guid -Mask 1 -Mode minimum}
    $fileTree=Join-Path $temp 'tree';$null=New-Item -ItemType Directory $fileTree
    $regTree=Join-Path $regProvider 'Tree';$null=New-Item -Path $regTree
    foreach($tree in @($fileTree,$regTree)){
        if($tree -eq $fileTree){$null=New-Item -ItemType Directory (Join-Path $tree 'open');$null=New-Item -ItemType Directory (Join-Path $tree 'protected')}
        else{$null=New-Item -Path (Join-Path $tree 'open');$null=New-Item -Path (Join-Path $tree 'protected')}
        # Fixture setup changes protection only on an owned object. Production never changes it.
        Initialize-WelaSelectedSaclNative;$privilege=New-Object Wela.SelectedSacl.Privilege
        try {
            $protected=Join-Path $tree 'protected';$acl=Get-Acl -LiteralPath $protected -Audit
            $acl.SetAuditRuleProtection($true,$true)
            Set-Acl -LiteralPath $protected -AclObject $acl
        }finally{$privilege.Dispose()}
        foreach($branch in @('open','protected')){
            if($tree -eq $fileTree){[IO.File]::WriteAllText((Join-Path (Join-Path $tree $branch) 'leaf.txt'),'owned descendant fixture')}
            else{$null=New-Item -Path (Join-Path (Join-Path $tree $branch) 'Leaf')}
        }
    }
    $definitions=@(
        [pscustomobject]@{Path=$fileTree;Kind='FileSystem';Resolution='Resolved';PrincipalSid='S-1-1-0';Propagation='None';Inheritance='ContainerInherit,ObjectInherit';Rights=@('ReadData');AuditFlags=@('Success');PolicyMode='minimum';PolicySelected=$true;RequiredPolicyMask=1},
        [pscustomobject]@{Path=('Registry::HKEY_USERS\'+$sid+'\'+$regSub+'\Tree');Kind='Registry';Resolution='Resolved';PrincipalSid='S-1-1-0';Propagation='None';Inheritance='ContainerInherit';Rights=@('SetValue');AuditFlags=@('Success');PolicyMode='minimum';PolicySelected=$true;RequiredPolicyMask=1}
    )
    foreach($definition in $definitions){
        $before=Get-WelaSelectedSaclSnapshot $definition
        $ace=Get-WelaSelectedSaclAce $definition $before -IncludeChildren
        Assert-WelaSelectedSaclPrerequisites $definition $ace
        $children=Get-WelaSelectedSaclStableDescendants $definition $before
        Assert ($children.Status -eq 'Complete' -and $children.Entries.Count -eq 4) ('Native populated '+$definition.Kind+' enumeration captures all four existing children: '+($children.Diagnostics -join '; '))
        Assert (@($children.Entries|Where-Object ProtectedBarrier).Count -eq 2) 'Native SACL protection marks the protected object and its subtree.'
        $journal=Join-Path $temp ($definition.Kind+'.pending.json')
        Write-WelaSelectedSaclJson $journal ([pscustomobject]@{State='Pending';Before=$before;DescendantsBefore=$children;Ace=$ace})
        $saved=Get-Content -LiteralPath $journal -Raw|ConvertFrom-Json
        Assert ($saved.DescendantsBefore.Entries.Count -eq 4 -and $saved.Before.DescriptorBase64 -ceq $before.DescriptorBase64) 'Actual complete parent/child backup exists before native root mutation.'
        $fresh=Get-WelaSelectedSaclStableDescendants $definition (Get-WelaSelectedSaclSnapshot $definition)
        Assert ((Get-WelaSelectedSaclDescendantKey $fresh) -ceq (Get-WelaSelectedSaclDescendantKey $children)) 'Native child pre-write snapshots remain stable.'
        $after=Write-WelaSelectedSaclNative $definition $before $ace
        Assert-WelaSelectedSaclPreserved $before $after $ace
        $afterChildren=Get-WelaSelectedSaclStableDescendants $definition $after
        $outcomes=Test-WelaSelectedSaclDescendantOutcomes $children $afterChildren $ace
        if($outcomes.Status -ne 'Observed'){Write-Host ($outcomes|ConvertTo-Json -Depth 20)}
        Assert ($outcomes.Status -eq 'Observed') 'Real native inheritance preserves all reviewed child owner/group/DACL/original ACEs/protection.'
        Assert (@($outcomes.Outcomes|Where-Object Status -eq 'InheritedAceObserved').Count -eq 2) 'Actual inherited requested audit ACE appears on unprotected child container and leaf.'
        Assert (@($outcomes.Outcomes|Where-Object Status -eq 'ProtectedUnchanged').Count -eq 2) 'Protected child and its descendant retain exact descriptors without inherited coverage claims.'
        $again=Get-WelaSelectedSaclStableDescendants $definition (Get-WelaSelectedSaclSnapshot $definition)
        Assert ((Get-WelaSelectedSaclDescendantKey $again) -ceq (Get-WelaSelectedSaclDescendantKey $afterChildren)) 'Actual final descendant membership and descriptor state is stable.'
        Assert ((Test-WelaSelectedSaclAce $again.Root $ace) -and (Test-WelaSelectedSaclDescendantOutcomes $again $again $ace).Status -eq 'Observed') 'Native idempotence inputs verify root and all reviewed inheritance without another write.'
        if($definition.Kind -eq 'FileSystem'){[IO.File]::WriteAllText((Join-Path $fileTree 'appeared.txt'),'owned new child')}
        else{$null=New-Item -Path (Join-Path $regTree 'Appeared')}
        $appeared=Get-WelaSelectedSaclStableDescendants $definition (Get-WelaSelectedSaclSnapshot $definition)
        $changed=Test-WelaSelectedSaclDescendantOutcomes $again $appeared $ace
        Assert ($changed.Status -eq 'Unverified' -and @($changed.Outcomes|Where-Object Status -eq 'NewUnreviewedChild').Count -eq 1) 'New actual child is unreviewed even when Windows inherited a matching audit ACE.'
        Write-Host ('PASS: actual '+$definition.Kind+' populated-tree inheritance, protected-subtree preservation and final snapshots; no child ownership or future coverage claim.')
    }
    Assert ((Invoke-WelaNative whoami.exe @('/priv','/fo','csv')).Diagnostic -ceq $privilegeBefore) 'All native enumeration, snapshot, setup and writer operations restore process privilege state.'
    Write-Host "PASS: $script:count actual descendant SACL assertions on owned disposable populated trees."
} finally {
    foreach($guid in $policyGuids){Set-WelaEffectiveAuditPolicy -Guid $guid -Mask $beforePolicy[$guid] -Mode exact}
    if($beforePrecedence.ValueExists){Set-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -Type $beforePrecedence.Type -Value $beforePrecedence.Value}
    else{Remove-ItemProperty -LiteralPath $precedencePath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue}
    $afterPolicy=Get-WelaEffectiveAuditPolicy;$afterPrecedence=Get-WelaRegistryState $precedencePath SCENoApplyLegacyAuditPolicy
    if((Fingerprint $beforePolicy) -cne (Fingerprint $afterPolicy) -or ($beforePrecedence|ConvertTo-Json -Compress) -cne ($afterPrecedence|ConvertTo-Json -Compress)){throw "Fixture policy restoration failed; retain owned evidence at $temp and $regProvider."}
    if(Test-Path -LiteralPath $regProvider){Remove-Item -LiteralPath $regProvider -Recurse -Force}
    if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}
    if((Test-Path -LiteralPath $regProvider) -or (Test-Path -LiteralPath $temp)){throw 'Owned fixture objects remain after cleanup.'}
    $restored=$true
    Write-Host 'PASS: all59 native audit masks and typed precedence restored; only owned disposable targets removed.'
}
$global:LASTEXITCODE=0
