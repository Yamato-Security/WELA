# Read-only bounded observations. A descendant is never passed to a setter.
function Get-WelaWmiDescendantContext {
    if(-not (Get-Command Initialize-WelaWmiProbeNative -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'WmiProbe.ps1')}
    Initialize-WelaWmiProbeNative
    if((Get-Service Winmgmt -ErrorAction Stop).Status -ne 'Running'){throw 'Winmgmt must already be running before descendant observation.'}
    $sources=[ordered]@{}
    foreach($name in @('WmiNamespaceAuditing.ps1','WmiNamespaceDescendants.ps1','WmiProbeNative.cs','WmiProbe.ps1','Configuration.ps1')){$sources[$name]=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256 -ErrorAction Stop).Hash}
    [ordered]@{Computer=[Environment]::MachineName;Version=[Environment]::OSVersion.VersionString;Token=(Get-WelaWmiProbeTokenKey ([Wela.WmiProbe.Native]::Snapshot()));Sources=$sources}|ConvertTo-Json -Compress -Depth 5
}
function Get-WelaWmiChildNames {
    param([string]$Namespace,[int]$Maximum)
    Initialize-WelaWmiInterop
    $options=New-Object System.Management.ConnectionOptions
    $options.EnablePrivileges=$false;$options.Impersonation=[System.Management.ImpersonationLevel]::Impersonate
    $scope=New-Object System.Management.ManagementScope -ArgumentList "\\.\$Namespace",$options
    $query=New-Object System.Management.ObjectQuery -ArgumentList 'SELECT Name FROM __Namespace'
    $enumeration=New-Object System.Management.EnumerationOptions
    $enumeration.ReturnImmediately=$true;$enumeration.Rewindable=$false;$enumeration.BlockSize=1
    $enumeration.Timeout=[TimeSpan]::FromSeconds(10)
    $searcher=New-Object System.Management.ManagementObjectSearcher -ArgumentList $scope,$query,$enumeration
    $collection=$null;$names=New-Object 'System.Collections.Generic.List[string]'
    try {
        $collection=$searcher.Get()
        foreach($item in $collection){
            try {
                if($names.Count -ge $Maximum){throw 'WMI descendant count exceeds the reviewed maximum of 64.'}
                $name=$item.Name
                if($name -isnot [string] -or $name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$'){throw 'Unsupported or ambiguous native child namespace name.'}
                $names.Add($name)
            } finally {$item.Dispose()}
        }
        @($names.ToArray()|Sort-Object)
    } finally {if($collection){$collection.Dispose()};$searcher.Dispose()}
}
function Get-WelaWmiDescendantKey {
    param($Tree)
    if($null -eq $Tree -or $Tree.Status -cne 'Complete' -or $Tree.Maximum -ne 64 -or $Tree.MaximumDepth -ne 8 -or $Tree.Entries -isnot [array] -or $Tree.Entries.Count -gt 64){throw 'Complete bounded WMI descendant evidence is required.'}
    $parts=@($Tree.Context,$Tree.Root.Namespace,$Tree.Root.DescriptorJson)
    foreach($entry in $Tree.Entries){
        if($entry.Namespace -cne $entry.Snapshot.Namespace -or $entry.Depth -lt 1 -or $entry.Depth -gt 8 -or $entry.ProtectedBarrier -isnot [bool]){throw 'Malformed WMI descendant evidence.'}
        $parts+=@($entry.Namespace,$entry.Parent,[string]$entry.Depth,[string]$entry.ProtectedBarrier,$entry.Snapshot.DescriptorJson)
    }
    ConvertTo-Json -InputObject $parts -Compress -Depth 4
}
function Get-WelaWmiDescendants {
    param([string]$Namespace)
    $entries=New-Object 'System.Collections.Generic.List[object]'
    $diagnostics=New-Object 'System.Collections.Generic.List[string]'
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $root=$null;$started=[DateTime]::UtcNow;$bytes=0
    try {
        if($Namespace -cnotmatch '^root(\\[A-Za-z_][A-Za-z0-9_]{0,63}){1,8}$'){throw 'An exact local WMI namespace is required.'}
        $root=Get-WelaWmiNamespaceSnapshot $Namespace
        $queue.Enqueue([pscustomobject]@{Namespace=$Namespace;Depth=0;ProtectedBarrier=$false})
        $null=$seen.Add($Namespace)
        while($queue.Count){
            if(([DateTime]::UtcNow-$started).TotalSeconds -gt 30){throw 'WMI tree scan time budget exceeded; individual provider calls are not forcibly cancellable.'}
            $parent=$queue.Dequeue()
            $children=@(Get-WelaWmiChildNames $parent.Namespace (64-$entries.Count))
            if($entries.Count+$children.Count -gt 64){throw 'WMI descendant count exceeds 64.'}
            if($parent.Depth -ge 8 -and $children.Count){throw 'WMI descendant depth exceeds eight.'}
            foreach($name in $children){
                if($name -isnot [string] -or $name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$'){throw 'Unsupported native child namespace name.'}
                $path=$parent.Namespace+'\'+$name
                if(-not $seen.Add($path)){throw 'Duplicate or ambiguous WMI namespace during enumeration.'}
                $snapshot=Get-WelaWmiNamespaceSnapshot $path
                if($snapshot.Namespace -cne $path -or -not $snapshot.DescriptorMof){throw 'Incomplete or mismatched namespace descriptor.'}
                $bytes+=[Text.Encoding]::UTF8.GetByteCount($snapshot.DescriptorJson+$snapshot.DescriptorMof)
                if($bytes -gt 2097152){throw 'WMI descendant evidence exceeds two MiB.'}
                $descriptor=$snapshot.DescriptorJson|ConvertFrom-Json -ErrorAction Stop
                if($null -eq $descriptor.ControlFlags){throw 'Incomplete child descriptor controls.'}
                $barrier=$parent.ProtectedBarrier -or (([uint32]$descriptor.ControlFlags -band 8192) -ne 0)
                $entry=[pscustomobject]@{Namespace=$path;Parent=$parent.Namespace;Depth=$parent.Depth+1;ProtectedBarrier=[bool]$barrier;Snapshot=$snapshot}
                $entries.Add($entry);$queue.Enqueue($entry)
            }
        }
    } catch {$diagnostics.Add($_.Exception.Message)}
    [pscustomobject]@{Status=$(if($diagnostics.Count){'Incomplete'}else{'Complete'});Maximum=64;MaximumDepth=8;StartedUtc=$started.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');Root=$root;Entries=@($entries.ToArray());Diagnostics=@($diagnostics.ToArray())}
}
function Get-WelaWmiStableDescendants {
    param([string]$Namespace)
    $context=Get-WelaWmiDescendantContext
    try {
        $first=Get-WelaWmiDescendants $Namespace
        if($first.Status -cne 'Complete'){throw ('Incomplete WMI descendant inventory: '+($first.Diagnostics -join '; '))}
        $second=Get-WelaWmiDescendants $Namespace
        if((Get-WelaWmiDescendantKey $first) -cne (Get-WelaWmiDescendantKey $second)){throw 'WMI descendant topology or full descriptor changed between observations.'}
        $second|Add-Member NoteProperty Context $context
        $second
    } finally {
        if((Get-WelaWmiDescendantContext) -cne $context){throw 'Full caller token, host, source or Winmgmt state changed while observing WMI descendants.'}
    }
}
function Test-WelaWmiDescendantOutcomes {
    param($Before,$After,[array]$Definitions)
    $outcomes=New-Object 'System.Collections.Generic.List[object]'
    $diagnostics=New-Object 'System.Collections.Generic.List[string]'
    if($After.Status -cne 'Complete'){$diagnostics.Add('Post-write descendant inventory is incomplete: '+($After.Diagnostics -join '; '))}
    $map=@{};foreach($entry in $After.Entries){$map[$entry.Namespace]=$entry}
    foreach($entry in $Before.Entries){
        $status='Unverified';$actual=$null;$message=''
        try {
            if(-not $map.ContainsKey($entry.Namespace)){throw 'Reviewed namespace disappeared or could not be observed.'}
            $actual=$map[$entry.Namespace];$map.Remove($entry.Namespace)
            if($actual.Parent -cne $entry.Parent -or $actual.Depth -ne $entry.Depth -or $actual.ProtectedBarrier -ne $entry.ProtectedBarrier){throw 'Descendant topology or observed protection changed.'}
            $a=$entry.Snapshot.DescriptorJson|ConvertFrom-Json;$b=$actual.Snapshot.DescriptorJson|ConvertFrom-Json
            if($entry.ProtectedBarrier){
                if($entry.Snapshot.DescriptorJson -cne $actual.Snapshot.DescriptorJson){throw 'Protected namespace or its subtree changed.'}
                $status='ProtectedUnchanged'
            } else {
                # Allow only SACL_PRESENT to appear. Every other control and full
                # owner/group/DACL/unknown descriptor property remains identical.
                if((ConvertTo-WelaWmiJson @($a.PSObject.Properties.Name|Sort-Object)) -cne (ConvertTo-WelaWmiJson @($b.PSObject.Properties.Name|Sort-Object))){throw 'Child descriptor property inventory changed.'}
                foreach($property in $a.PSObject.Properties){
                    if($property.Name -eq 'SACL'){continue}
                    if($property.Name -eq 'ControlFlags'){
                        if(([uint32]$a.ControlFlags -band (-bnot 16)) -ne ([uint32]$b.ControlFlags -band (-bnot 16)) -or (([uint32]$a.ControlFlags -band 16) -ne 0 -and ([uint32]$b.ControlFlags -band 16) -eq 0)){throw 'Child descriptor controls changed.'}
                    } elseif((ConvertTo-WelaWmiJson $property.Value) -cne (ConvertTo-WelaWmiJson $b.($property.Name))){throw 'Child access or unknown descriptor field changed.'}
                }
                $remaining=New-Object 'System.Collections.Generic.List[object]'
                foreach($ace in @($b.SACL)){if($null -ne $ace){$remaining.Add($ace)}}
                foreach($ace in @($a.SACL)){
                    if($null -eq $ace){continue};$found=-1
                    for($i=0;$i -lt $remaining.Count;$i++){if((ConvertTo-WelaWmiJson $remaining[$i]) -ceq (ConvertTo-WelaWmiJson $ace)){$found=$i;break}}
                    if($found -lt 0){throw 'Original child audit/unknown ACE changed or disappeared.'};$remaining.RemoveAt($found)
                }
                $expected=@($Definitions|Where-Object {($_.AceFlags -band 2) -ne 0}|ForEach-Object {[pscustomobject]@{Sid=$_.Sid;AccessMask=$_.AccessMask;AceFlags=([uint32]$_.AceFlags -bor 16)}})
                foreach($ace in $remaining){if(-not @($expected|Where-Object {Test-WelaWmiAceMatch $ace $_}).Count){throw 'Unexplained child audit entry appeared.'}}
                foreach($definition in $expected){if(@($remaining|Where-Object {Test-WelaWmiAceMatch $_ $definition}).Count -gt 1){throw 'Unexplained duplicate inherited child entry appeared.'}}
                foreach($definition in $expected){if(-not @($b.SACL|Where-Object {Test-WelaWmiAceMatch $_ $definition}).Count){throw 'Requested inherited ACE was not observed; existing-child propagation is unverified.'}}
                $status='InheritedAceObserved'
            }
        } catch {$message=$_.Exception.Message;$diagnostics.Add($entry.Namespace+': '+$message)}
        $outcomes.Add([pscustomobject]@{Namespace=$entry.Namespace;Status=$status;Diagnostic=$message;Before=$entry.Snapshot;After=$(if($actual){$actual.Snapshot}else{$null})})
    }
    foreach($entry in $map.Values){$diagnostics.Add('New unreviewed descendant: '+$entry.Namespace);$outcomes.Add([pscustomobject]@{Namespace=$entry.Namespace;Status='NewUnreviewedNamespace';Diagnostic='No pre-write snapshot or ownership established.';Before=$null;After=$entry.Snapshot})}
    [pscustomobject]@{Status=$(if($diagnostics.Count){'Unverified'}else{'Observed'});Outcomes=@($outcomes.ToArray());Diagnostics=@($diagnostics.ToArray());Scope='Observed existing namespaces only. No atomic tree, namespace recreation identity, future-child, event, recovery ownership or Sigma claim.'}
}
