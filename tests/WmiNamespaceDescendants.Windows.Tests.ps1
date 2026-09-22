param([switch]$AllowDisposableNamespaceWrite,[string]$EvidencePath='wmi-descendants-native.json')
$ErrorActionPreference='Stop'
if(-not $AllowDisposableNamespaceWrite -or $env:OS -ne 'Windows_NT'){throw 'Requires disposable Windows and explicit namespace-write consent.'}
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'scripts/Configuration.ps1')
. (Join-Path $repo 'scripts/WmiNamespaceAuditing.ps1')
. (Join-Path $repo 'scripts/WmiProbe.ps1')
Initialize-WelaWmiInterop;Initialize-WelaWmiProbeNative
$script:assertions=0
function Assert($v,[string]$m){if(-not $v){throw $m};$script:assertions++}
function Safety {
 $masks=[ordered]@{};foreach($p in (Get-Content (Join-Path $repo 'config/audit_profiles.json') -Raw|ConvertFrom-Json).catalog){$masks[$p.guid]=Get-WelaAuditPolicyMask $p.guid}
 if($masks.Count -ne 59){throw 'Complete 59-subcategory inventory required.'}
 [pscustomobject]@{Token=(Get-WelaWmiProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot()));Masks=$masks;Precedence=(Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy);Services=@(Get-Service Winmgmt,EventLog|Sort-Object Name|Select-Object Name,@{n='Status';e={[string]$_.Status}})}
}
$owned=New-Object 'System.Collections.Generic.List[object]'
function New-OwnedNamespace([string]$Parent,[string]$Name){
 $factory=New-Object System.Management.ManagementClass -ArgumentList ('\\.\'+$Parent+':__Namespace');$instance=$null
 try{
  $instance=$factory.CreateInstance();$instance.Name=$Name;$o=New-Object System.Management.PutOptions;$o.Type=[System.Management.PutType]::CreateOnly
  $path=$instance.Put($o);$owned.Add([pscustomobject]@{Parent=$Parent;Name=$Name;Path=$Parent+'\'+$Name;Instance=$instance;Removed=$false});$instance=$null
  Assert ($path.RelativePath -ieq ('__NAMESPACE.Name="'+$Name+'"')) 'Created identity differs from owned request.'
  $Parent+'\'+$Name
 }finally{if($instance){$instance.Dispose()};$factory.Dispose()}
}
function Entry([string]$Namespace){
 $d=@(Get-WelaWmiAuditDefinitions -Namespace 'root\default' -IncludeChildren);$d[0].Namespace=$Namespace
 [pscustomobject]@{Namespace=$Namespace;Definitions=$d;Descendants=(Get-WelaWmiStableDescendants $Namespace)}
}
function Configure($Entry,[string]$Name,[switch]$DryRun){
 $c=New-WelaConfigurationContext -Auto -DryRun:$DryRun -BackupPath (Join-Path $backup $Name)
 Set-WelaWmiAuditControls -Context $c -Plan @($Entry)
 Complete-WelaConfiguration -Context $c -Scope wmi-namespace-sacl-only
}
function Observe-OwnedProtection([string]$Namespace){
 $before=Get-WelaWmiNamespaceSnapshot $Namespace
 $privilege=New-Object Wela.WmiSecurityPrivilege;$connection=$null;$response=$null
 try{
  $connection=New-WelaWmiConnection $Namespace;$descriptor=Get-WelaWmiNativeDescriptor $connection
  $request=$descriptor.Clone();$request.DACL=$null;$request.Owner=$null;$request.Group=$null
  $request.ControlFlags=([uint32]$descriptor.ControlFlags -band [uint32]4294967291) -bor [uint32]8208
  $parameters=$connection.GetMethodParameters('SetSecurityDescriptor');$parameters.Descriptor=$request
  $response=$connection.InvokeMethod('SetSecurityDescriptor',$parameters,$null)
 }finally{try{if($connection){$connection.Dispose()}}finally{$privilege.Dispose()}}
 $after=Get-WelaWmiNamespaceSnapshot $Namespace;$a=$before.DescriptorJson|ConvertFrom-Json;$b=$after.DescriptorJson|ConvertFrom-Json
 foreach($property in $a.PSObject.Properties){if($property.Name -ne 'ControlFlags'){Assert ((ConvertTo-WelaWmiJson $property.Value) -ceq (ConvertTo-WelaWmiJson $b.($property.Name))) 'Protection fixture changed an unrelated descriptor field.'}}
 Assert (([uint32]$a.ControlFlags -band (-bnot 8192)) -eq ([uint32]$b.ControlFlags -band (-bnot 8192))) 'Protection fixture changed unrelated controls.'
 [pscustomobject]@{Namespace=$Namespace;ReturnValue=$response.ReturnValue;Before=$before;After=$after;ProtectionObserved=(([uint32]$b.ControlFlags -band 8192) -ne 0)}
}
$backup=Join-Path ([IO.Path]::GetTempPath()) ('wela-wmi-tree-'+[guid]::NewGuid().ToString('N'))
$e=[ordered]@{SchemaVersion=1;Host=$env:COMPUTERNAME;Version=[Environment]::OSVersion.VersionString;PowerShell=$PSVersionTable.PSVersion.ToString();Head=$env:GITHUB_SHA;Cases=@();Before=$null;After=$null;Sources=@();Cleanup=@();Complete=$false;Failure=$null}
$failure=$null
try{
 $e.Before=Safety
 $root=New-OwnedNamespace root ('WelaInheritance_'+[guid]::NewGuid().ToString('N'))
 $child=New-OwnedNamespace $root Existing
 $grand=New-OwnedNamespace $child Grandchild
 $special=New-OwnedNamespace $root Explicit
 # Owned child with a distinct explicit failure ACE; access descriptors remain intact.
 $s=Get-WelaWmiNamespaceSnapshot $special
 $specialDef=[pscustomobject]@{Sid='S-1-5-18';AccessMask=[uint32]1;AceFlags=[uint32]128}
 $null=Set-WelaWmiNamespaceDescriptor $special $s.DescriptorJson @($specialDef)
 $protected=New-OwnedNamespace $root Protected
 $s=Get-WelaWmiNamespaceSnapshot $protected
 $null=Set-WelaWmiNamespaceDescriptor $protected $s.DescriptorJson @($specialDef)
 $protection=Observe-OwnedProtection $protected
 $protectedGrand=New-OwnedNamespace $protected Grandchild
 $e.Cases+=@{Name='NativeProtectionObservation';Observation=$protection}
 $p=Entry $root
 Assert ($p.Descendants.Entries.Count -eq 5) 'All existing children and grandchildren are captured.'
 $dry=Configure $p dry -DryRun
 Assert ($dry.ExitCode -eq 0 -and $dry.Results[0].Status -eq 'Skipped' -and -not (Test-Path $backup)) 'Tree dry-run wrote state or backup.'
 Assert ((Get-WelaWmiDescendantKey (Get-WelaWmiStableDescendants $root)) -ceq (Get-WelaWmiDescendantKey $p.Descendants)) 'Dry-run changed tree.'
 $extra=New-OwnedNamespace $root Stale
 $stale=Configure $p stale
 Assert ($stale.ExitCode -eq 1 -and $stale.Results[0].Diagnostic -match 'changed after planning') 'New child failed to invalidate plan.'
 Assert ((Get-WelaWmiNamespaceSnapshot $root).DescriptorJson -ceq $p.Descendants.Root.DescriptorJson) 'Stale topology allowed a parent setter.'
 $p=Entry $root
 $result=Configure $p apply
 $after=Get-WelaWmiStableDescendants $root
 $parentBefore=$p.Descendants.Root.DescriptorJson|ConvertFrom-Json;$parentAfter=$after.Root.DescriptorJson|ConvertFrom-Json
 Assert (Test-WelaWmiDescriptorPreserved $parentBefore $parentAfter) 'Parent access or existing ACE preservation failed.'
 Assert (@(Get-WelaWmiMissingAces $parentAfter $p.Definitions).Count -eq 0) 'Parent setter failed to apply requested inheritance ACE.'
 $outcome=Test-WelaWmiDescendantOutcomes $p.Descendants $after $p.Definitions
 Assert (($outcome.Status -eq 'Observed' -and $result.ExitCode -eq 0) -or ($outcome.Status -eq 'Unverified' -and $result.ExitCode -eq 1)) 'Configuration status misrepresents actual child observations.'
 $journal=@(Get-Content (Join-Path $backup 'apply/before.jsonl')|ConvertFrom-Json)
 Assert ($journal.Count -eq 1 -and $journal[0].Before.Descendants.Entries.Count -eq 6) 'Original complete subtree missing from journal.'
 Assert ((Get-WelaWmiDescendantKey $journal[0].Before.Descendants) -ceq (Get-WelaWmiDescendantKey $p.Descendants)) 'Journal tree differs from pre-write snapshots.'
 $e.Cases+=@{Name='ExistingTree';Plan=$p;Result=$result;After=$after;Outcomes=$outcome;Journal=$journal}
 # A genuinely newly created namespace independently demonstrates provider inheritance.
 $future=New-OwnedNamespace $root Future
 $futureSnapshot=Get-WelaWmiNamespaceSnapshot $future
 $futureDescriptor=$futureSnapshot.DescriptorJson|ConvertFrom-Json
 $expected=[pscustomobject]@{Sid=$p.Definitions[0].Sid;AccessMask=$p.Definitions[0].AccessMask;AceFlags=[uint32]82}
 Assert (@($futureDescriptor.SACL|Where-Object {Test-WelaWmiAceMatch $_ $expected}).Count -eq 1) 'New child did not expose the exact native inherited ACE.'
 $e.Cases+=@{Name='NewChildInheritance';Snapshot=$futureSnapshot;Expected=$expected}
 $repeat=Configure (Entry $root) repeat
 Assert ($repeat.ExitCode -eq $result.ExitCode) 'Repeat no longer reflects observed existing descendant outcomes.'
 Assert ((Get-WelaWmiNamespaceSnapshot $root).DescriptorJson -ceq $after.Root.DescriptorJson) 'Idempotent parent repeat changed descriptor.'
 $e.Cases+=@{Name='Repeat';Result=$repeat}
 # A reviewed empty descendant set can complete, and a later child observes inheritance.
 $empty=New-OwnedNamespace root ('WelaInheritance_'+[guid]::NewGuid().ToString('N'))
 $emptyResult=Configure (Entry $empty) empty
 Assert ($emptyResult.ExitCode -eq 0 -and $emptyResult.Results[0].Status -eq 'Applied') 'Reviewed empty tree did not apply.'
 $emptyRepeat=Configure (Entry $empty) emptyrepeat
 Assert ($emptyRepeat.ExitCode -eq 0 -and $emptyRepeat.Results[0].Status -eq 'AlreadyCompliant') 'Empty-tree repeat is not idempotent.'
 $e.Cases+=@{Name='EmptyTree';Result=$emptyResult;Repeat=$emptyRepeat}
 $e.Assertions=$script:assertions
}catch{$failure=$_;$e.Failure=$_.Exception.ToString()}
finally{
 $cleanupErrors=@()
 for($i=$owned.Count-1;$i -ge 0;$i--){$item=$owned[$i];try{$item.Instance.Delete();$names=@(Get-WelaWmiChildNames $item.Parent 64);if($item.Name -in $names){throw 'Owned namespace still exists after deletion.'};$item.Removed=$true}catch{$cleanupErrors+=$_.Exception.ToString()}finally{$item.Instance.Dispose()}}
 $e.Cleanup=@($owned|Select-Object Parent,Name,Path,Removed);$e.CleanupErrors=$cleanupErrors
 try{$e.After=Safety;Assert (($e.Before|ConvertTo-Json -Depth 12 -Compress) -ceq ($e.After|ConvertTo-Json -Depth 12 -Compress)) 'Full token/audit/precedence/services changed.'}catch{$cleanupErrors+=$_.Exception.ToString();$e.CleanupErrors=$cleanupErrors}
 foreach($f in @('scripts/WmiNamespaceAuditing.ps1','scripts/WmiNamespaceDescendants.ps1','scripts/WmiProbe.ps1','scripts/WmiProbeNative.cs','scripts/Configuration.ps1','tests/WmiNamespaceDescendants.Windows.Tests.ps1')){$e.Sources+=@{Path=$f;Sha256=(Get-FileHash (Join-Path $repo $f) -Algorithm SHA256).Hash.ToLowerInvariant()}}
 $e.Complete=($null -eq $failure -and $cleanupErrors.Count -eq 0)
 $e|ConvertTo-Json -Depth 25|Set-Content -LiteralPath $EvidencePath -Encoding UTF8
 if(Test-Path $backup){Copy-Item $backup -Destination ($EvidencePath+'.journals') -Recurse;Remove-Item $backup -Recurse -Force}
}
if($failure){throw $failure};if(-not $e.Complete){throw 'Native WMI descendant cleanup or safety verification failed.'}
Write-Host "PASS: $script:assertions native WMI descendant assertions, complete owned-tree cleanup."
