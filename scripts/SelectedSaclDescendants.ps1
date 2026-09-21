# Bounded observations only. Descendants are never supplied to the native writer.
function Get-WelaSelectedSaclChildNames {
    param($Definition,$Snapshot,[int]$Maximum)
    $path=Resolve-WelaSelectedSaclNativePath $Definition
    Initialize-WelaSelectedSaclNative
    $privilege=New-Object Wela.SelectedSacl.Privilege;$target=$null
    try {
        $target=New-Object Wela.SelectedSacl.Target($Definition.Kind,$path,$true)
        $before=$target.Read()
        if((Get-WelaSelectedSaclSnapshotKey $before) -cne (Get-WelaSelectedSaclSnapshotKey $Snapshot)){throw 'Container changed before enumeration.'}
        $children=$target.Enumerate($Maximum)
        if((Get-WelaSelectedSaclSnapshotKey ($target.Read())) -cne (Get-WelaSelectedSaclSnapshotKey $before)){throw 'Container changed during enumeration.'}
        $children
    } finally {if($target){$target.Dispose()};$privilege.Dispose()}
}
function New-WelaSelectedSaclChildDefinition {
    param([string]$Kind,[string]$Path)
    [pscustomobject]@{Kind=$Kind;Path=$(if($Kind -eq 'Registry'){'Registry::'+$Path}else{$Path});Resolution='Resolved'}
}
function Get-WelaSelectedSaclDescendantKey {
    param($Inventory)
    if($null -eq $Inventory -or $Inventory.Status -cne 'Complete' -or $Inventory.Maximum -ne 128 -or $Inventory.MaximumDepth -ne 16 -or $Inventory.Entries -isnot [array] -or $Inventory.Entries.Count -gt 128){throw 'Descendant capture is incomplete or has unknown limits; review a new plan.'}
    $fields=@('128','16',(Get-WelaSelectedSaclSnapshotKey $Inventory.Root))
    foreach($entry in $Inventory.Entries){
        if($entry.ProtectedBarrier -isnot [bool] -or $entry.Depth -lt 1 -or $entry.Depth -gt 16 -or $entry.Path -cne $entry.Snapshot.Path){throw 'Malformed descendant evidence.'}
        $fields+=@($entry.Path,$entry.ParentPath,[string]$entry.Depth,[string]$entry.ProtectedBarrier,(Get-WelaSelectedSaclSnapshotKey $entry.Snapshot))
    }
    Get-WelaSelectedSaclHash $fields
}
function Get-WelaSelectedSaclDescendants {
    param($Definition,$RootSnapshot)
    $entries=New-Object 'System.Collections.Generic.List[object]'
    $diagnostics=New-Object 'System.Collections.Generic.List[string]'
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    $queue.Enqueue([pscustomobject]@{Definition=$Definition;Snapshot=$RootSnapshot;Depth=0;ProtectedBarrier=$false})
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $null=$seen.Add($RootSnapshot.Path)
    $identities=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if($RootSnapshot.Kind -eq 'FileSystem'){$null=$identities.Add($RootSnapshot.Identity)}
    $started=[DateTime]::UtcNow;$bytes=0
    try {
        while($queue.Count){
            if(([DateTime]::UtcNow-$started).TotalSeconds -gt 30){throw 'Descendant scan time budget exceeded (individual native reads are not cancellable).'}
            $parent=$queue.Dequeue()
            if($parent.Snapshot.Kind -ne 'Registry' -and -not $parent.Snapshot.IsDirectory){continue}
            $remaining=128-$entries.Count
            $children=Get-WelaSelectedSaclChildNames $parent.Definition $parent.Snapshot ([Math]::Max(1,$remaining))
            if($children.Truncated -or @($children.Names).Count -gt $remaining){throw 'Descendant count exceeds the reviewed maximum of 128.'}
            if($parent.Depth -ge 16 -and @($children.Names).Count){throw 'Descendant depth exceeds the reviewed maximum of 16.'}
            foreach($name in $children.Names){
                if([string]::IsNullOrEmpty($name) -or $name -in @('.','..') -or $name -match '[\\/\x00-\x1f]' -or ($parent.Snapshot.Kind -eq 'FileSystem' -and $name -match '[:*?<>|]|[ .]$')){throw 'Ambiguous native descendant name.'}
                $path=$parent.Snapshot.Path.TrimEnd('\')+'\'+$name
                if(-not $seen.Add($path)){throw 'Duplicate descendant path during enumeration.'}
                $childDefinition=New-WelaSelectedSaclChildDefinition $Definition.Kind $path
                $snapshot=Get-WelaSelectedSaclSnapshot $childDefinition
                if($snapshot.Path -ine $path -or $snapshot.Kind -cne $Definition.Kind){throw 'Descendant snapshot does not identify the enumerated child.'}
                $null=Get-WelaSelectedSaclSnapshotKey $snapshot
                if($snapshot.Kind -eq 'FileSystem' -and -not $identities.Add($snapshot.Identity)){throw 'Repeated file identity (hard link/alias) prevents unique descendant attribution.'}
                $bytes+=[Text.Encoding]::UTF8.GetByteCount(($snapshot|ConvertTo-Json -Depth 12 -Compress))
                if($bytes -gt 2097152){throw 'Descendant snapshot evidence exceeds 2 MiB.'}
                $barrier=$parent.ProtectedBarrier -or (($snapshot.ControlFlags -band 8192) -ne 0)
                $entry=[pscustomobject]@{Path=$path;ParentPath=$parent.Snapshot.Path;Depth=$parent.Depth+1;ProtectedBarrier=[bool]$barrier;Snapshot=$snapshot}
                $entries.Add($entry)
                $queue.Enqueue([pscustomobject]@{Definition=$childDefinition;Snapshot=$snapshot;Depth=$entry.Depth;ProtectedBarrier=[bool]$barrier})
            }
        }
        # A second pass by the caller verifies membership and descriptor stability.
    }catch{$diagnostics.Add($_.Exception.Message)}
    [pscustomobject]@{Status=$(if($diagnostics.Count){'Incomplete'}else{'Complete'});Maximum=128;MaximumDepth=16;StartedUtc=$started.ToString('o');CompletedUtc=[DateTime]::UtcNow.ToString('o');Root=$RootSnapshot;Entries=@($entries.ToArray());Diagnostics=@($diagnostics.ToArray())}
}
function Get-WelaSelectedSaclStableDescendants {
    param($Definition,$Snapshot)
    $first=Get-WelaSelectedSaclDescendants $Definition $Snapshot
    if($first.Status -ne 'Complete'){return $first}
    $fresh=Get-WelaSelectedSaclSnapshot $Definition
    $second=Get-WelaSelectedSaclDescendants $Definition $fresh
    if($second.Status -eq 'Complete' -and (Get-WelaSelectedSaclDescendantKey $first) -cne (Get-WelaSelectedSaclDescendantKey $second)){
        $second.Status='Incomplete';$second.Diagnostics=@('Descendant membership, identity or descriptor changed between captures.')
    }
    $second
}
function Assert-WelaSelectedSaclDescendantPreservation {
    param($Before,$After,[bool]$Protected)
    if($Before.Kind -cne $After.Kind -or $Before.Path -cne $After.Path -or $Before.IsDirectory -ne $After.IsDirectory -or $Before.SecurityInformation -ne $After.SecurityInformation -or $Before.DescriptorScope -cne $After.DescriptorScope){throw 'Child identity/type or descriptor scope changed.'}
    # Registry identity incorporates last-write time and therefore can change as part of an ACL update.
    if($Before.Kind -eq 'FileSystem' -and $Before.Identity -cne $After.Identity){throw 'Child file identity changed.'}
    if($Before.Owner -cne $After.Owner -or $Before.Group -cne $After.Group -or $Before.DaclBase64 -cne $After.DaclBase64 -or ($Before.ControlFlags -band (-bnot 2576)) -ne ($After.ControlFlags -band (-bnot 2576))){throw 'Child owner/group/DACL/protection or non-SACL controls changed.'}
    if($Protected -and $Before.DescriptorBase64 -cne $After.DescriptorBase64){throw 'Protected child or protected subtree descriptor changed.'}
    $counts=New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    foreach($entry in $After.Aces){if(-not $counts.ContainsKey($entry.Binary)){$counts[$entry.Binary]=0};$counts[$entry.Binary]++}
    foreach($entry in $Before.Aces){if(-not $counts.ContainsKey($entry.Binary) -or $counts[$entry.Binary] -lt 1){throw 'Original child audit/unknown ACE changed or disappeared.'};$counts[$entry.Binary]--}
    # Arbitrary new explicit/unknown ACEs cannot be attributed to inheritance.
    foreach($entry in $After.Aces){if($counts[$entry.Binary] -gt 0 -and (-not $entry.Ordinary -or $entry.Type -ne 2 -or ($entry.Flags -band 16) -eq 0)){throw 'Unexplained explicit or unknown child ACE appeared.'}}
}
function Test-WelaSelectedSaclDescendantOutcomes {
    param($Before,$After,$Ace)
    $outcomes=New-Object 'System.Collections.Generic.List[object]'
    $diagnostics=New-Object 'System.Collections.Generic.List[string]'
    if($After.Status -ne 'Complete'){$diagnostics.Add('After-state inventory is incomplete: '+($After.Diagnostics -join '; '))}
    $map=@{};foreach($entry in $After.Entries){$map[$entry.Path]=$entry}
    foreach($entry in $Before.Entries){
        $status='Unverified';$message='';$actual=$null
        try {
            if(-not $map.ContainsKey($entry.Path)){throw 'Reviewed descendant disappeared or could not be observed.'}
            $actual=$map[$entry.Path];$map.Remove($entry.Path)
            if($actual.ParentPath -cne $entry.ParentPath -or $actual.Depth -ne $entry.Depth -or $actual.ProtectedBarrier -ne $entry.ProtectedBarrier){throw 'Child topology or inheritance protection changed.'}
            Assert-WelaSelectedSaclDescendantPreservation $entry.Snapshot $actual.Snapshot $entry.ProtectedBarrier
            if($entry.ProtectedBarrier){$status='ProtectedUnchanged'}
            elseif(($Ace.Flags -band 3) -eq 0){$status='PreservedWithoutRequestedInheritance'}
            else {
                $flags=($Ace.Flags -band 192) -bor 16
                if($actual.Snapshot.Kind -eq 'Registry' -or $actual.Snapshot.IsDirectory){$flags=$flags -bor ($Ace.Flags -band 3)}
                $expected=[pscustomobject]@{Sid=$Ace.Sid;Mask=$Ace.Mask;Flags=$flags}
                if(-not (Test-WelaSelectedSaclAce $actual.Snapshot $expected)){throw 'Requested inherited audit ACE was not observed; propagation may be incomplete or blocked.'}
                $status='InheritedAceObserved'
            }
        }catch{$message=$_.Exception.Message;$diagnostics.Add($entry.Path+': '+$message)}
        $outcomes.Add([pscustomobject]@{Path=$entry.Path;Status=$status;Diagnostic=$message;Before=$entry.Snapshot;After=$(if($actual){$actual.Snapshot}else{$null})})
    }
    foreach($entry in $map.Values){$outcomes.Add([pscustomobject]@{Path=$entry.Path;Status='NewUnreviewedChild';Diagnostic='Child appeared after the reviewed snapshot; no pre-write backup or ownership established.';Before=$null;After=$entry.Snapshot});$diagnostics.Add('New unreviewed descendant: '+$entry.Path)}
    [pscustomobject]@{Status=$(if($diagnostics.Count){'Unverified'}else{'Observed'});Scope='Reviewed existing descendants at the recorded observations only; propagation is non-atomic. Registry recreation between post-write observations cannot be excluded by last-write metadata.';Ownership='No descendant ACE ownership or automatic rollback authority.';Outcomes=@($outcomes.ToArray());Diagnostics=@($diagnostics.ToArray())}
}
