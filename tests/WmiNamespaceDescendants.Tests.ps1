$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
$script:assertions=0
function Assert($v,[string]$m){if(-not $v){throw $m};$script:assertions++}
function Throws([scriptblock]$f,[string]$m){$yes=$false;try{& $f|Out-Null}catch{$yes=$true};Assert $yes $m}
function Descriptor([uint32]$flags=32772){[pscustomobject]@{ControlFlags=$flags;Owner='owner';Group='group';DACL=@('a','b');SACL=@();Opaque='preserve'}}
function Snapshot([string]$ns,$d){[pscustomobject]@{Namespace=$ns;DescriptorJson=(ConvertTo-WelaWmiJson $d);DescriptorMof='native full descriptor';SaclReadPrivilege='test'}}
function Ace([uint32]$flags=82){[pscustomobject]@{AceType=2;AceFlags=$flags;AccessMask=262175;Trustee=[pscustomobject]@{SIDString='S-1-1-0'}}}
$script:tree=@{};$script:reads=0;$script:changeAt=0;$script:context='caller/host/source';$script:writes=0
function Reset {
 $script:tree=@{'root\default'=(Descriptor);'root\default\A'=(Descriptor);'root\default\A\B'=(Descriptor);'root\default\Protected'=(Descriptor 40964);'root\default\Protected\B'=(Descriptor)}
 $script:reads=0;$script:changeAt=0;$script:context='caller/host/source';$script:writes=0;$script:prompt=$null
}
function Get-WelaWmiChildNames {
 param($Namespace,$Maximum)
 @($script:tree.Keys|Where-Object {$_ -clike ($Namespace+'\*') -and $_.Substring($Namespace.Length+1) -notmatch '\\'}|ForEach-Object {$_.Substring($Namespace.Length+1)}|Sort-Object)
}
function Get-WelaWmiDescendantContext {$script:context}
function Get-WelaWmiNamespaceSnapshot {
 param($Namespace)
 $script:reads++
 if($script:changeAt -and $script:reads -eq $script:changeAt){$script:tree['root\default\A'].Owner='racing owner'}
 if(-not $script:tree.ContainsKey($Namespace)){throw 'Unknown namespace.'}
 Snapshot $Namespace $script:tree[$Namespace]
}
function Set-WelaWmiNamespaceDescriptor {
 param($Namespace,$ExpectedJson,$Definitions)
 if((ConvertTo-WelaWmiJson $script:tree[$Namespace]) -cne $ExpectedJson){throw 'Immediate parent drift'}
 $script:writes++
 foreach($d in $Definitions){$script:tree[$Namespace].SACL+=Ace $d.AceFlags}
 $script:tree[$Namespace].ControlFlags=$script:tree[$Namespace].ControlFlags -bor 16
 # Model the provider's potential inherited-only propagation exactly, leaving protected tree unchanged.
 foreach($ns in @('root\default\A','root\default\A\B')){$script:tree[$ns].SACL+=Ace;$script:tree[$ns].ControlFlags=$script:tree[$ns].ControlFlags -bor 16}
}
function Read-Host {param($Prompt)if($script:prompt){& $script:prompt};'Y'}
$defs=@(Get-WelaWmiAuditDefinitions -Namespace 'root\default' -IncludeChildren)
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-desc-test-'+[guid]::NewGuid().ToString('N'))
try{
 Reset
 $before=Get-WelaWmiStableDescendants 'root\default'
 Assert ($before.Entries.Count -eq 4) 'Complete multilevel inventory.'
 Assert (@($before.Entries|Where-Object ProtectedBarrier).Count -eq 2) 'Protected ancestor marks whole subtree.'
 Assert ((Get-WelaWmiDescendantKey $before) -ceq (Get-WelaWmiDescendantKey (Get-WelaWmiStableDescendants 'root\default'))) 'Stable tree key omits observation clock.'
 $script:changeAt=$script:reads+7
 Throws {Get-WelaWmiStableDescendants 'root\default'} 'Second-pass descriptor drift must fail.'
 Reset;$script:tree['root\default\A\bad-child']=Descriptor
 Assert ((Get-WelaWmiDescendants 'root\default').Status -eq 'Incomplete') 'Ambiguous child name rejected.'
 Reset;foreach($i in 1..65){$script:tree['root\default\N'+$i]=Descriptor}
 Assert ((Get-WelaWmiDescendants 'root\default').Status -eq 'Incomplete') 'Count overflow fails rather than truncates.'
 Reset;$n='root\default';foreach($i in 1..9){$n+='\Deep';$script:tree[$n]=Descriptor}
 Assert ((Get-WelaWmiDescendants 'root\default').Status -eq 'Incomplete') 'Depth overflow fails rather than truncates.'
 Reset;$script:tree['root\default\A'].Opaque='x'*2097153
 Assert ((Get-WelaWmiDescendants 'root\default').Status -eq 'Incomplete') 'Serialized descriptor budget enforced.'
 Reset;$script:tree['root\default'].Opaque='x'*2097153
 Assert ((Get-WelaWmiDescendants 'root\default').Status -eq 'Incomplete') 'The selected root also counts toward the descriptor budget.'
 Reset
 $p=@(Get-WelaWmiAuditPlan -Namespace 'root\default' -IncludeChildren)
 $c=New-WelaConfigurationContext -Auto -DryRun -BackupPath $temp
 Set-WelaWmiAuditControls $c $p
 Assert ($script:writes -eq 0 -and $c.Results[0].Status -eq 'Skipped' -and -not (Test-Path $temp)) 'DryRun no state or journal mutation.'
 $script:context='changed token';$c=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $temp token)
 Set-WelaWmiAuditControls $c $p
 Assert ($script:writes -eq 0 -and $c.Results[0].Status -eq 'Failed') 'Full context drift invalidates planned subtree.'
 $script:context='caller/host/source'
 $script:tree['root\default\New']=Descriptor
 $c=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $temp stale)
 Set-WelaWmiAuditControls $c $p
 Assert ($script:writes -eq 0 -and $c.Results[0].Status -eq 'Failed') 'Stale membership blocks before journal or setter.'
 Reset;$p=@(Get-WelaWmiAuditPlan -Namespace 'root\default' -IncludeChildren)
 $script:prompt={$script:tree['root\default\A'].DACL=@('changed')}
 $c=New-WelaConfigurationContext -BackupPath (Join-Path $temp prompt)
 Set-WelaWmiAuditControls $c $p
 Assert ($script:writes -eq 0 -and $c.Results[0].Status -eq 'Failed') 'Descendant drift during confirmation blocks parent setter.'
 Reset;$p=@(Get-WelaWmiAuditPlan -Namespace 'root\default' -IncludeChildren)
 $c=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $temp successful)
 Set-WelaWmiAuditControls $c $p
 $result=Complete-WelaConfiguration $c
 Assert ($script:writes -eq 1 -and $result.ExitCode -eq 0 -and $result.Results[0].Status -eq 'Applied') 'Exact inherited propagation and protected preservation pass.'
 $ob=$result.Results[0].DescendantVerification.Observation
 Assert (@($ob.Outcomes|Where-Object Status -eq InheritedAceObserved).Count -eq 2) 'Two inherited readbacks represented.'
 Assert (@($ob.Outcomes|Where-Object Status -eq ProtectedUnchanged).Count -eq 2) 'Two protected readbacks represented.'
 $journal=Get-Content (Join-Path $temp successful/before.jsonl)|ConvertFrom-Json
 Assert ($journal.Before.Descendants.Entries.Count -eq 4 -and $journal.Before.DescriptorMof -eq 'native full descriptor') 'Original journal fields and full subtree retained.'
 Assert ((Get-WelaWmiDescendantKey $journal.Before.Descendants) -ceq (Get-WelaWmiDescendantKey $p[0].Descendants)) 'Journal serialization does not truncate original child snapshots.'
 $script:tree['root\default\A'].Opaque='drift'
 Assert ((Complete-WelaConfiguration $c).ExitCode -eq 1) 'Final child drift propagates failure.'
 Reset;$script:tree['root\default'].SACL+=Ace 66;$script:tree['root\default'].ControlFlags=32788
 $unverified=@(Get-WelaWmiAuditPlan -Namespace 'root\default' -IncludeChildren)
 Assert ($unverified[0].Status -eq 'Unknown' -and $unverified[0].Diagnostic -match 'descendants are unverified') 'Already-compliant parent cannot imply descendant compliance.'
 $c=New-WelaConfigurationContext -Auto -BackupPath (Join-Path $temp unverified)
 Set-WelaWmiAuditControls $c $unverified
 Assert ($script:writes -eq 0 -and (Complete-WelaConfiguration $c).ExitCode -eq 1) 'Missing existing-child inheritance fails without an unnecessary parent rewrite.'
 # Each unrelated mutation invalidates observed propagation, even when required ACE still exists.
 foreach($kind in @('Owner','Dacl','Control','Unknown','NewProperty','Protected','Removed','Extra','Duplicate','Missing','New')){
  Reset;$a=Get-WelaWmiStableDescendants 'root\default';$null=Set-WelaWmiNamespaceDescriptor 'root\default' $a.Root.DescriptorJson $defs
  switch($kind){
   Owner {$script:tree['root\default\A'].Owner='other'}
   Dacl {$script:tree['root\default\A'].DACL=@('other')}
   Control {$script:tree['root\default\A'].ControlFlags=$script:tree['root\default\A'].ControlFlags -bor 256}
   Unknown {$script:tree['root\default\A'].Opaque='other'}
   NewProperty {$script:tree['root\default\A']|Add-Member NoteProperty NewOpaque 1}
   Protected {$script:tree['root\default\Protected\B'].SACL+=Ace}
   Removed {$script:tree.Remove('root\default\A\B')}
   Extra {$script:tree['root\default\A'].SACL+=Ace 64}
   Duplicate {$script:tree['root\default\A'].SACL+=Ace}
   Missing {$script:tree['root\default\A'].SACL=@()}
   New {$script:tree['root\default\Unreviewed']=Descriptor}
  }
  $b=Get-WelaWmiStableDescendants 'root\default'
  Assert ((Test-WelaWmiDescendantOutcomes $a $b $defs).Status -eq 'Unverified') "$kind child change must fail verification."
 }
 Write-Host "PASS: $script:assertions bounded WMI descendant assertions."
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force}}
