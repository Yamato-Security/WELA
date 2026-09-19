# Explicit selected, existing local targets. No audit-policy writes or hive loading.
. (Join-Path $PSScriptRoot 'SelectedSaclDescendants.ps1')
function Get-WelaSelectedSaclHash {
    param([string[]]$Values)
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    $text=(@($Values | ForEach-Object {[Convert]::ToBase64String($encoding.GetBytes([string]$_))}) -join '|')
    $sha=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($sha.ComputeHash($encoding.GetBytes($text)))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Get-WelaSelectedSaclSources {
    foreach($path in @('config/audit_sacl_targets.json','config/audit_profiles.json','modules/AuditProfiles.psm1','modules/AuditCatalog.psm1','scripts/TargetedSaclPlanning.ps1','scripts/SelectedSaclConfiguration.ps1','scripts/SelectedSaclNative.cs','scripts/SelectedSaclDescendants.ps1')) {
        [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "../$path") -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
}
function Get-WelaSelectedSaclContext {
    $role=Get-WelaHostContext; $detail=Get-WelaDefaultContext
    if(-not (Test-WelaDefaultContextComplete $detail) -or $role.Build -ne $detail.Build){throw 'Complete consistent actual Windows context is required.'}
    $matches=switch($role.Role){
        Client {$detail.ProductType -eq 1 -and $detail.DomainRole -in @(0,1)}
        MemberServer {$detail.ProductType -eq 3 -and $detail.DomainRole -in @(2,3)}
        DomainController {$detail.ProductType -eq 2 -and $detail.DomainRole -in @(4,5)}
        ADCS {$detail.ProductType -eq 3 -and $detail.DomainRole -in @(2,3) -and $detail.InstalledRoles -contains 'ADCS-Cert-Authority'}
        default {$false}
    }
    if(-not $matches){throw 'Role contradicts detailed host context.'}
    [pscustomobject]@{Computer=[Environment]::MachineName;Role=$role.Role;Build=$role.Build;Detail=$detail;Key=(Get-WelaSelectedSaclHash @([Environment]::MachineName,$role.Role,(Get-WelaDefaultContextKey $detail)))}
}
function Get-WelaSelectedSaclDefinitionKey {
    param($Row)
    Get-WelaSelectedSaclHash @($Row.Origin,$Row.Scope,$Row.UserSid,$Row.Path,$Row.Kind,$Row.PrincipalSid,($Row.AuditFlags -join ','),($Row.Rights -join ','),$Row.Inheritance,$Row.Propagation,$Row.Policy,$Row.PolicyMode,[string]$Row.PolicySelected,[string]$Row.RequiredPolicyMask)
}
function Get-WelaSelectedSaclSnapshotKey {
    param($Snapshot)
    if($null -eq $Snapshot -or $Snapshot.IsDirectory -isnot [bool] -or ($Snapshot.ControlFlags -isnot [int] -and $Snapshot.ControlFlags -isnot [long])){throw 'Malformed reviewed native snapshot.'}
    if(($Snapshot.SecurityInformation -isnot [int] -and $Snapshot.SecurityInformation -isnot [long]) -or $Snapshot.SecurityInformation -ne 511 -or $Snapshot.DescriptorScope -cne 'WinSDK-defined sections 0x1ff; future sections unobserved'){throw 'Incomplete or unknown native descriptor observation scope.'}
    $fields=@([string]$Snapshot.SecurityInformation,$Snapshot.DescriptorScope,$Snapshot.Path,$Snapshot.Kind,$Snapshot.Identity,[string]$Snapshot.IsDirectory,$Snapshot.DescriptorBase64,$Snapshot.Owner,$Snapshot.Group,$Snapshot.DaclBase64,[string]$Snapshot.ControlFlags)
    foreach($ace in $Snapshot.Aces){$fields+=@($ace.Binary,[string]$ace.Type,[string]$ace.Flags,[string]$ace.Mask,$ace.Sid,[string]$ace.Ordinary)}
    Get-WelaSelectedSaclHash $fields
}
function Get-WelaSelectedSaclCatalog {
    param([string]$Profile,[switch]$IncludeOptional,$Context)
    $current=Get-WelaEffectiveAuditPolicy
    $plan=Get-WelaAuditProfilePlan -Profile $Profile -Role $Context.Role -Build $Context.Build -Current $current -IncludeOptional:$IncludeOptional
    if($plan.referenceOnly){throw 'Reference-only defaults cannot select SACL configuration.'}
    # User inventory/known-folder resolution is shared, but unselected object ACLs are not read.
    $companion=Get-WelaTargetedSaclPlan -AuditPlan $plan -Live -SkipTargetObservation
    $seen=@{}
    $rows=@(foreach($row in $companion.Targets){
        $key=Get-WelaSelectedSaclDefinitionKey $row; $id='sacl-'+$key.Substring(0,24)
        if($seen.ContainsKey($id)){throw 'Duplicate selected SACL identity.'};$seen[$id]=$true
        [pscustomobject]@{Id=$id;DefinitionKey=$key;Definition=$row}
    })
    [pscustomobject]@{Profile=$plan;Rows=$rows;UserInventory=$companion.UserInventory}
}
function Initialize-WelaSelectedSaclNative {
    if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'Selected SACLs require native 64-bit Windows PowerShell.'}
    if(-not ('Wela.SelectedSacl.Target' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'SelectedSaclNative.cs') -ErrorAction Stop}
}
function Resolve-WelaSelectedSaclNativePath {
    param($Definition)
    if($Definition.Resolution -notin @('Resolved','Redirected')){throw "Target path is unresolved: $($Definition.Resolution). No hive is loaded."}
    if($Definition.Kind -eq 'FileSystem') {
        $observation=Get-WelaSaclTargetObservation -Path $Definition.Path -Kind $Definition.Kind -SkipSaclRead
        if($observation.PathState -ne 'Exists'){throw "Selected existing local target is unavailable: $($observation.PathState). $($observation.Diagnostic)"}
        if($Definition.Path -notmatch '^[A-Za-z]:\\'){throw 'Only absolute local filesystem targets are supported.'}
        if($Definition.Path.Substring(2).Contains(':') -or $Definition.Path -match '[*?<>|]|[ .](\\|$)'){throw 'Ambiguous filesystem target path.'}
        $full=[IO.Path]::GetFullPath($Definition.Path)
        if($full -ine $Definition.Path){throw 'Filesystem target path must be canonical.'}
        return $full
    }
    if($Definition.Kind -ne 'Registry'){throw 'Unsupported target kind.'}
    # Do not let a registry provider preflight follow a link before the native
    # component-by-component OPEN_LINK validation. Missing keys fail native open.
    $path=$Definition.Path -replace '^HKLM:\\','HKEY_LOCAL_MACHINE\' -replace '^Registry::',''
    if($path -notmatch '^HKEY_(LOCAL_MACHINE|USERS)\\[^\\]+' -or $path -match '\\\\|(^|\\)\.\.?($|\\)|[*?%/\x00-\x1f]'){throw 'Only canonical existing HKLM/HKU keys may be selected.'}
    return $path
}
function Get-WelaSelectedSaclSnapshot {
    param($Definition)
    $path=Resolve-WelaSelectedSaclNativePath $Definition
    Initialize-WelaSelectedSaclNative
    $privilege=New-Object Wela.SelectedSacl.Privilege; $target=$null
    try {$target=New-Object Wela.SelectedSacl.Target($Definition.Kind,$path);$target.Read()}
    finally {if($target){$target.Dispose()};$privilege.Dispose()}
}
function Get-WelaSelectedSaclAce {
    param($Definition,$Snapshot,[switch]$IncludeChildren)
    if($Definition.PrincipalSid -notin @('S-1-1-0','S-1-5-11') -or $Definition.Propagation -ne 'None'){throw 'Unsupported catalog principal or propagation.'}
    $maps=if($Definition.Kind -eq 'Registry') {@{QueryValues=1;SetValue=2;CreateSubKey=4;EnumerateSubKeys=8;Notify=16;Delete=65536;ReadPermissions=131072;ChangePermissions=262144;TakeOwnership=524288;ReadKey=131097;WriteKey=131078}} else {@{ReadData=1;WriteData=2;AppendData=4;ReadExtendedAttributes=8;WriteExtendedAttributes=16;ExecuteFile=32;DeleteSubdirectoriesAndFiles=64;ReadAttributes=128;WriteAttributes=256;Delete=65536;ReadPermissions=131072;ChangePermissions=262144;TakeOwnership=524288;Read=131209;Write=278;ReadAndExecute=131241;Modify=197055;FullControl=2032127;ListDirectory=1;CreateFiles=2;CreateDirectories=4;Traverse=32}}
    $mask=0;foreach($right in $Definition.Rights){if(-not $maps.ContainsKey($right)){throw "Unsupported catalog audit right: $right"};$mask=$mask -bor $maps[$right]}
    if(-not $mask){throw 'No audit rights selected.'}
    $flags=0;$policyMask=0
    foreach($flag in $Definition.AuditFlags){switch -Exact ($flag){Success {$flags=$flags -bor 64;$policyMask=$policyMask -bor 1} Failure {$flags=$flags -bor 128;$policyMask=$policyMask -bor 2} default {throw 'Unsupported audit outcome.'}}}
    $inherit=$Definition.Inheritance -ne 'None' -and ($Definition.Kind -eq 'Registry' -or $Snapshot.IsDirectory)
    $container=$Definition.Kind -eq 'Registry' -or $Snapshot.IsDirectory
    $existingInheritance=$container -and @($Snapshot.Aces | Where-Object {($_.Flags -band 3) -ne 0}).Count -gt 0
    if(($inherit -or $existingInheritance) -and -not $IncludeChildren){throw 'Source or existing SACL inheritance requires explicit -TargetSaclIncludeChildren consent; existing descendants can receive audit ACEs.'}
    if($inherit){$flags=$flags -bor $(if($Definition.Kind -eq 'Registry'){2}else{3})}
    [pscustomobject]@{Sid=$Definition.PrincipalSid;Mask=$mask;Flags=$flags;RequiredPolicyMask=$policyMask}
}
function Test-WelaSelectedSaclAce {
    param($Snapshot,$Ace)
    return @($Snapshot.Aces | Where-Object {$_.Ordinary -eq $true -and $_.Type -eq 2 -and $_.Sid -ceq $Ace.Sid -and $_.Flags -eq $Ace.Flags -and ($_.Mask -band $Ace.Mask) -eq $Ace.Mask}).Count -gt 0
}
function Assert-WelaSelectedSaclPreserved {
    param($Before,$After,$Ace)
    if($Before.SecurityInformation -ne $After.SecurityInformation -or $Before.DescriptorScope -cne $After.DescriptorScope){throw 'Native descriptor observation scope changed.'}
    if($Before.Owner -cne $After.Owner -or $Before.Group -cne $After.Group -or $Before.DaclBase64 -cne $After.DaclBase64 -or ($Before.ControlFlags -band (-bnot 16)) -ne ($After.ControlFlags -band (-bnot 16))){throw 'Non-SACL descriptor components or control flags changed.'}
    $counts=New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    foreach($entry in $After.Aces){if(-not $counts.ContainsKey($entry.Binary)){$counts[$entry.Binary]=0};$counts[$entry.Binary]++}
    foreach($entry in $Before.Aces){if(-not $counts.ContainsKey($entry.Binary) -or $counts[$entry.Binary] -lt 1){throw 'An original or unknown ACE changed or disappeared.'};$counts[$entry.Binary]--}
    if(-not (Test-WelaSelectedSaclAce $After $Ace)){throw 'Requested audit ACE is absent after write.'}
}
function Assert-WelaSelectedSaclPrerequisites {
    param($Definition,$Ace)
    $precedence=Get-WelaAuditPrecedenceState
    if(-not $precedence.Registry.ValueExists -or $precedence.Registry.Type -ne 'DWord' -or ($precedence.Registry.Value -isnot [int] -and $precedence.Registry.Value -isnot [long]) -or $precedence.Registry.Value -ne 1){throw 'Typed audit precedence DWORD=1 must already be effective; this command never enables it.'}
    if($Definition.PolicyMode -eq 'not-applicable' -or ($Definition.PolicyMode -eq 'optional' -and -not $Definition.PolicySelected) -or ($Definition.PolicyMode -eq 'exact' -and $Definition.RequiredPolicyMask -eq 0)){throw 'Selected profile does not select this optional/applicable object-audit requirement.'}
    $guid=if($Definition.Kind -eq 'Registry'){'0CCE921E-69AE-11D9-BED3-505054503030'}else{'0CCE921D-69AE-11D9-BED3-505054503030'}
    $policies=Get-WelaEffectiveAuditPolicy;$value=$policies[$guid]
    if(($value -isnot [int] -and $value -isnot [long]) -or $value -notin @(0,1,2,3) -or ($value -band $Ace.RequiredPolicyMask) -ne $Ace.RequiredPolicyMask){throw 'Required native object-audit outcomes are not already effective; no audit mask is changed.'}
}
function Write-WelaSelectedSaclNative {
    param($Definition,$Before,$Ace)
    $path=Resolve-WelaSelectedSaclNativePath $Definition
    Initialize-WelaSelectedSaclNative
    $privilege=New-Object Wela.SelectedSacl.Privilege;$target=$null
    try {
        $target=New-Object Wela.SelectedSacl.Target($Definition.Kind,$path)
        $after=$target.Add($Before.Identity,$Before.DescriptorBase64,$Ace.Sid,$Ace.Mask,$Ace.Flags)
        Assert-WelaSelectedSaclPreserved $Before $after $Ace
        $after
    } finally {if($target){$target.Dispose()};$privilege.Dispose()}
}
function Write-WelaSelectedSaclJson {
    param([string]$Path,$Value)
    $text=($Value | ConvertTo-Json -Depth 24 -Compress)+[Environment]::NewLine
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($text)
    if($Value.Kind -eq 'WelaSelectedSaclPlan' -and $bytes.Length -gt 4194304){throw 'Reviewed plan exceeds the 4 MiB import limit; select fewer roots.'}
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
}
function Resolve-WelaSelectedSaclFilePath {
    param([string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if($provider.Name -ne 'FileSystem'){throw 'A FileSystem path is required.'}
    [IO.Path]::GetFullPath($full)
}
function Read-WelaSelectedSaclPlan {
    param([string]$Path)
    $full=Resolve-WelaSelectedSaclFilePath $Path
    $file=Get-Item -LiteralPath $full -ErrorAction Stop
    if($file -isnot [IO.FileInfo] -or $file.Length -lt 1 -or $file.Length -gt 4194304 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Plan must be a regular JSON file of at most 4 MiB.'}
    $bytes=[IO.File]::ReadAllBytes($full);if($bytes.Length -gt 4194304){throw 'Plan size changed.'}
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    $text=$encoding.GetString($bytes).TrimStart([char]0xFEFF)
    $module=Get-Module AuditProfiles
    $plan=& $module {param($Text) ConvertFrom-WelaCustomProfileJson $Text} $text
    if($plan -isnot [pscustomobject] -or ($plan.SchemaVersion -isnot [int] -and $plan.SchemaVersion -isnot [long]) -or $plan.SchemaVersion -ne 1 -or $plan.Kind -cne 'WelaSelectedSaclPlan' -or $plan.IncludeChildren -isnot [bool] -or $plan.IncludeOptional -isnot [bool] -or $plan.Rows -isnot [array] -or -not $plan.Rows.Count -or $plan.Rows.Count -gt 100){throw 'Invalid selected SACL plan envelope.'}
    foreach($property in $plan.PSObject.Properties){if($property.Name -cnotin @('SchemaVersion','Kind','CapturedUtc','Profile','IncludeOptional','IncludeChildren','Context','Sources','Rows','GenerationReadiness','UsableRuleCredit','Catalog','UserInventory')){throw 'Unknown selected SACL plan property.'}}
    $seen=@{}
    foreach($row in $plan.Rows){
        if($row.Id -isnot [string] -or $row.Id -cnotmatch '^sacl-[0-9a-f]{24}$' -or $seen.ContainsKey($row.Id)){throw 'Invalid or duplicate reviewed target ID.'};$seen[$row.Id]=$true
        if((Get-WelaSelectedSaclDefinitionKey $row.Definition) -cne $row.DefinitionKey){throw 'Reviewed target definition was modified.'}
        $null=Get-WelaSelectedSaclSnapshotKey $row.Before
        if($plan.IncludeChildren -and ($row.Before.Kind -eq 'Registry' -or $row.Before.IsDirectory)){$null=Get-WelaSelectedSaclDescendantKey $row.DescendantsBefore}
    }
    [pscustomobject]@{Path=$full;Hash=(Get-WelaSelectedSaclHash @([Convert]::ToBase64String($bytes)));Plan=$plan}
}
function Assert-WelaSelectedSaclSources {
    param($Expected)
    $actual=@(Get-WelaSelectedSaclSources)
    if(@($Expected).Count -ne $actual.Count){throw 'Plan source inventory differs.'}
    for($i=0;$i -lt $actual.Count;$i++){if($Expected[$i].Path -cne $actual[$i].Path -or $Expected[$i].Sha256 -cne $actual[$i].Sha256){throw 'Plan/catalog source changed; generate a new plan.'}}
}
function Assert-WelaSelectedSaclRun {
    param($Plan,$Imported)
    Assert-WelaSelectedSaclSources $Plan.Sources
    if((Get-WelaSelectedSaclContext).Key -cne $Plan.Context.Key){throw 'Actual host context changed or differs from plan.'}
    if($Imported -and (Read-WelaSelectedSaclPlan $Imported.Path).Hash -cne $Imported.Hash){throw 'Selected plan file changed.'}
}
function Invoke-WelaSelectedSacl {
    param([ValidateSet('Audit','Plan','Configure')][string]$Action='Audit',[string]$Profile,[string[]]$Ids,[string]$PlanPath,[switch]$IncludeOptional,[switch]$IncludeChildren,[switch]$DryRun,[switch]$Auto,[string]$BackupPath,[string]$ResultsPath)
    if($DryRun -and $Action -ne 'Configure'){throw 'DryRun requires selected SACL Configure.'}
    if($Action -ne 'Configure' -and ($PlanPath -or $Auto -or $BackupPath)){throw 'Plan input, Auto and BackupPath require Configure.'}
    if($Action -in @('Plan','Configure') -and -not $Ids){throw 'Explicit nonempty target IDs are required.'}
    $selected=@{};foreach($id in $Ids){if($id -cnotmatch '^sacl-[0-9a-f]{24}$' -or $selected.ContainsKey($id)){throw 'Invalid or duplicate selected target ID.'};$selected[$id]=$true}
    $output=$null;if($ResultsPath){$output=Resolve-WelaSelectedSaclFilePath $ResultsPath;if(Test-Path -LiteralPath $output){throw 'Results must use a new file.'};if(-not (Test-Path -LiteralPath (Split-Path $output -Parent) -PathType Container)){throw 'Results parent must exist.'}}
    $imported=$null
    if($Action -eq 'Configure') {
        if(-not $PlanPath){throw 'Configure requires a previously reviewed -TargetSaclPlanPath.'}
        $imported=Read-WelaSelectedSaclPlan $PlanPath;$prior=$imported.Plan
        Assert-WelaSelectedSaclSources $prior.Sources
        if($Profile -and $Profile -cne $prior.Profile){throw 'Profile differs from the reviewed plan.'};$Profile=$prior.Profile
        if([bool]$IncludeOptional -ne $prior.IncludeOptional -or [bool]$IncludeChildren -ne $prior.IncludeChildren){throw 'Optional/inheritance consent must match the plan explicitly.'}
        if(@($prior.Rows).Count -ne $selected.Count -or @($prior.Rows | Where-Object {-not $selected.ContainsKey($_.Id)}).Count){throw 'Configure IDs must match exactly the reviewed plan selection.'}
    }
    if(-not $Profile){throw 'An explicit built-in -TargetSaclProfile is required for Audit/Plan.'}
    $sources=@(Get-WelaSelectedSaclSources);$context=Get-WelaSelectedSaclContext
    if($imported -and $context.Key -cne $prior.Context.Key){throw 'Plan belongs to a different actual host context.'}
    $catalog=Get-WelaSelectedSaclCatalog -Profile $Profile -IncludeOptional:$IncludeOptional -Context $context
    Assert-WelaSelectedSaclSources $sources
    foreach($id in $Ids){if(@($catalog.Rows | Where-Object Id -ceq $id).Count -ne 1){throw "Unknown/stale target ID: $id"}}
    $rows=@(foreach($item in $catalog.Rows){if(-not $selected.ContainsKey($item.Id)){continue}
        $row=[pscustomobject]@{Id=$item.Id;DefinitionKey=$item.DefinitionKey;Definition=$item.Definition;Before=$null;Ace=$null;Status='Blocked';Diagnostic='';After=$null;DescendantsBefore=$null;DescendantsAfter=$null;DescendantVerification=$null}
        try {
            $row.Before=Get-WelaSelectedSaclSnapshot $item.Definition
            $row.Ace=Get-WelaSelectedSaclAce $item.Definition $row.Before -IncludeChildren:$IncludeChildren
            Assert-WelaSelectedSaclPrerequisites $item.Definition $row.Ace
            if($IncludeChildren -and ($row.Before.Kind -eq 'Registry' -or $row.Before.IsDirectory)){
                $row.DescendantsBefore=Get-WelaSelectedSaclStableDescendants $item.Definition $row.Before
                if($row.DescendantsBefore.Status -ne 'Complete'){throw ('Descendant capture incomplete: '+($row.DescendantsBefore.Diagnostics -join '; '))}
            }
            if($imported){
                $old=@($prior.Rows | Where-Object Id -ceq $item.Id)[0]
                if($row.DescendantsBefore -and (Get-WelaSelectedSaclDescendantKey $old.DescendantsBefore) -cne (Get-WelaSelectedSaclDescendantKey $row.DescendantsBefore)){throw 'Reviewed descendants changed; review a new plan.'}
                if($old.DefinitionKey -cne $item.DefinitionKey -or (Get-WelaSelectedSaclSnapshotKey $old.Before) -cne (Get-WelaSelectedSaclSnapshotKey $row.Before) -or
                    $old.Ace.Sid -cne $row.Ace.Sid -or $old.Ace.Mask -ne $row.Ace.Mask -or $old.Ace.Flags -ne $row.Ace.Flags -or $old.Ace.RequiredPolicyMask -ne $row.Ace.RequiredPolicyMask){throw 'Reviewed target definition/identity/descriptor changed; review a new plan.'}
            }
            $row.Status=if(Test-WelaSelectedSaclAce $row.Before $row.Ace){'AlreadyCompliant'}else{'ChangeRequired'}
            if($row.DescendantsBefore -and $row.Status -eq 'AlreadyCompliant'){
                $row.DescendantVerification=Test-WelaSelectedSaclDescendantOutcomes $row.DescendantsBefore $row.DescendantsBefore $row.Ace
                if($row.DescendantVerification.Status -ne 'Observed'){$row.Status='Blocked';throw 'Selected root already has its ACE, but reviewed descendant inheritance is unverified. No duplicate root ACE is added.'}
            }
        } catch {$row.Diagnostic=$_.Exception.Message}
        $row
    })
    # Different source entries may identify the same physical key/file. Refuse a
    # predictable partial apply: each must be reviewed again after the other write.
    $physical=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $rows){
        if($null -eq $row.Before){continue}
        $key=$row.Before.Kind+'|'+$row.Before.Path
        if($physical.ContainsKey($key)){
            $row.Status='Blocked';$row.Diagnostic='Multiple selected entries resolve to the same target. Configure one entry, then generate a fresh plan for the other.'
            $physical[$key].Status='Blocked';$physical[$key].Diagnostic=$row.Diagnostic
        }else{$physical[$key]=$row}
    }
    foreach($ancestor in $rows){
        if(-not $ancestor.DescendantsBefore){continue}
        foreach($child in $rows){
            if($child -eq $ancestor -or -not $child.Before -or $child.Before.Kind -cne $ancestor.Before.Kind){continue}
            if($child.Before.Path.StartsWith($ancestor.Before.Path.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
                $ancestor.Status='Blocked';$child.Status='Blocked'
                $ancestor.Diagnostic='Selected ancestor and descendant overlap. Configure one root and review a fresh plan before selecting another.';$child.Diagnostic=$ancestor.Diagnostic
            }
        }
    }
    $plan=[pscustomobject]@{SchemaVersion=1;Kind='WelaSelectedSaclPlan';CapturedUtc=[DateTime]::UtcNow.ToString('o');Profile=$Profile;IncludeOptional=[bool]$IncludeOptional;IncludeChildren=[bool]$IncludeChildren;Context=$context;Sources=$sources;Rows=$rows;GenerationReadiness='Conditional';UsableRuleCredit=0;Catalog=$(if(-not $Ids){$catalog.Rows}else{@()});UserInventory=$catalog.UserInventory}
    Assert-WelaSelectedSaclRun $plan $imported
    if($Action -ne 'Configure'){if($output){Write-WelaSelectedSaclJson $output $plan};return $plan}
    # Preflight the whole selected set before creating a journal or writing any target.
    if(@($rows | Where-Object Status -eq 'Blocked').Count){throw ('Selected SACL preflight failed: '+(@($rows | Where-Object Status -eq 'Blocked' | ForEach-Object Diagnostic) -join '; '))}
    $backup=$null
    if(-not $DryRun){
        if(-not $BackupPath){throw 'Configure requires an explicit new -BackupPath.'}
        $backup=Resolve-WelaSelectedSaclFilePath $BackupPath
        if(Test-Path -LiteralPath $backup){throw 'Backup directory must be new.'}
        if(-not (Test-Path -LiteralPath (Split-Path $backup -Parent) -PathType Container)){throw 'Backup parent must exist.'}
        $null=New-Item -ItemType Directory -Path $backup -ErrorAction Stop
    }
    foreach($row in $rows){
        if($row.Status -eq 'AlreadyCompliant'){$row.After=$row.Before;$row.DescendantsAfter=$row.DescendantsBefore;continue}
        if($DryRun){$row.Status='Skipped';$row.Diagnostic='Dry run; no SACL or recovery file written.';continue}
        if(-not $Auto -and (Read-Host "Add the selected audit ACE to $($row.Definition.Path)? (y/N)") -cnotin @('y','Y')){$row.Status='Skipped';$row.Diagnostic='Declined.';continue}
        try {
            Assert-WelaSelectedSaclRun $plan $imported
            Assert-WelaSelectedSaclPrerequisites $row.Definition $row.Ace
            $fresh=Get-WelaSelectedSaclSnapshot $row.Definition
            if($fresh.Identity -cne $row.Before.Identity -or $fresh.DescriptorBase64 -cne $row.Before.DescriptorBase64){throw 'Target changed before journal/write.'}
            if($row.DescendantsBefore){
                $freshChildren=Get-WelaSelectedSaclStableDescendants $row.Definition $fresh
                if((Get-WelaSelectedSaclDescendantKey $freshChildren) -cne (Get-WelaSelectedSaclDescendantKey $row.DescendantsBefore)){throw 'Descendants changed before journal/write.'}
            }
            $receipt=[pscustomobject]@{SchemaVersion=1;Kind='WelaSelectedSaclReceipt';State='Pending';RecordedUtc=[DateTime]::UtcNow.ToString('o');Computer=$context.Computer;ContextKey=$context.Key;Id=$row.Id;Sources=$sources;Definition=$row.Definition;Before=$fresh;Ace=$row.Ace;After=$null;DescendantsBefore=$row.DescendantsBefore;DescendantsAfter=$null;DescendantVerification=$null;Ownership='Only the verified explicit selected-root addition; never descendant ACE ownership or bulk rollback authority.'}
            Write-WelaSelectedSaclJson (Join-Path $backup ($row.Id+'.pending.json')) $receipt
            Assert-WelaSelectedSaclRun $plan $imported
            Assert-WelaSelectedSaclPrerequisites $row.Definition $row.Ace
            if($row.DescendantsBefore){
                $lastChildren=Get-WelaSelectedSaclStableDescendants $row.Definition (Get-WelaSelectedSaclSnapshot $row.Definition)
                if((Get-WelaSelectedSaclDescendantKey $lastChildren) -cne (Get-WelaSelectedSaclDescendantKey $row.DescendantsBefore)){throw 'Descendants changed after pending receipt; native write refused.'}
            }
            try {
                $row.After=Write-WelaSelectedSaclNative $row.Definition $fresh $row.Ace
                Assert-WelaSelectedSaclPreserved $fresh $row.After $row.Ace
            } finally {
                if($row.DescendantsBefore){
                    try {
                        $row.DescendantsAfter=Get-WelaSelectedSaclStableDescendants $row.Definition (Get-WelaSelectedSaclSnapshot $row.Definition)
                        $row.DescendantVerification=Test-WelaSelectedSaclDescendantOutcomes $row.DescendantsBefore $row.DescendantsAfter $row.Ace
                    }catch{$row.DescendantVerification=[pscustomobject]@{Status='Unverified';Diagnostics=@($_.Exception.Message);Ownership='No descendant ownership or automatic rollback authority.'}}
                    Write-WelaSelectedSaclJson (Join-Path $backup ($row.Id+'.descendants-observed.json')) ([pscustomobject]@{Kind='WelaSelectedSaclDescendantObservation';RecordedUtc=[DateTime]::UtcNow.ToString('o');Id=$row.Id;After=$row.DescendantsAfter;Verification=$row.DescendantVerification})
                }
            }
            if($row.DescendantVerification -and $row.DescendantVerification.Status -ne 'Observed'){throw ('Descendant preservation/propagation unverified: '+($row.DescendantVerification.Diagnostics -join '; '))}
            $receipt.State='Confirmed';$receipt.After=$row.After;$receipt.DescendantsAfter=$row.DescendantsAfter;$receipt.DescendantVerification=$row.DescendantVerification
            Write-WelaSelectedSaclJson (Join-Path $backup ($row.Id+'.confirmed.json')) $receipt
            $row.Status='Applied'
        }catch{$row.Status='Failed';$row.Diagnostic=$_.Exception.Message}
    }
    foreach($row in $rows | Where-Object Status -in @('Applied','AlreadyCompliant')){
        try {
            Assert-WelaSelectedSaclRun $plan $imported;Assert-WelaSelectedSaclPrerequisites $row.Definition $row.Ace
            $fresh=Get-WelaSelectedSaclSnapshot $row.Definition
            if($fresh.Identity -cne $row.After.Identity -or $fresh.DescriptorBase64 -cne $row.After.DescriptorBase64){throw 'Final selected target state drifted.'}
            if($row.DescendantsAfter){
                $finalChildren=Get-WelaSelectedSaclStableDescendants $row.Definition $fresh
                if((Get-WelaSelectedSaclDescendantKey $finalChildren) -cne (Get-WelaSelectedSaclDescendantKey $row.DescendantsAfter)){throw 'Final descendant membership, identity or descriptor drifted; earlier receipts describe an earlier moment only.'}
            }
        }catch{$row.Status='Failed';$row.Diagnostic=$_.Exception.Message}
    }
    $report=[pscustomobject]@{SchemaVersion=1;Kind='WelaSelectedSaclResult';ExitCode=$(if(@($rows | Where-Object Status -eq 'Failed').Count){1}else{0});DryRun=[bool]$DryRun;BackupPath=$backup;Plan=$plan;Results=$rows;GenerationReadiness='Conditional';UsableRuleCredit=0}
    if($output){Write-WelaSelectedSaclJson $output $report};$report
}
