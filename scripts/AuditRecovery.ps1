# Conservative, explicitly selected recovery of completed audit-policy writes.
. (Join-Path $PSScriptRoot 'NamedRegistryRecovery.ps1')
function ConvertFrom-WelaRecoveryJson {
    param([string]$Text)
    # ConvertFrom-Json accepts some JavaScript extensions (including single-quoted
    # and bare property names). Validate the entire JSON token stream first, so
    # those forms cannot bypass duplicate-property tracking below.
    $lexical=[regex]'\G(?:[ \t\r\n]+|"(?:\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4}|[^"\\\x00-\x1f])*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?(?![A-Za-z0-9_.+-])|(?:true|false|null)(?![A-Za-z0-9_])|[{}\[\]:,])'
    $position=0
    while ($position -lt $Text.Length) {
        $match=$lexical.Match($Text,$position)
        if (-not $match.Success -or $match.Index -ne $position) { throw 'Recovery evidence require strict JSON tokens; JavaScript extensions and invalid escapes are not supported.' }
        $position+=$match.Length
    }
    # Match JSON strings first; braces/property-looking text inside strings is inert.
    $withoutStrings=[regex]::Replace($Text,'"(?:\\.|[^"\\])*"','""')
    if ($withoutStrings -match '//|/\*|,\s*[}\]]') { throw 'Recovery evidence require strict JSON without comments or trailing commas.' }
    $tokens=[regex]::Matches($Text,'"(?:\\.|[^"\\])*"|[{}\[\]:,]')
    $stack=New-Object 'System.Collections.Generic.Stack[object]'
    for ($i=0;$i -lt $tokens.Count;$i++) {
        $token=$tokens[$i].Value
        if ($token -eq '{') { $stack.Push(@{}) }
        elseif ($token -eq '[') { $stack.Push($null) }
        elseif ($token -in @('}',']')) { if (-not $stack.Count) { throw 'Unbalanced recovery JSON.' }; $null=$stack.Pop() }
        elseif ($token.StartsWith('"') -and $i+1 -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
            if (-not $stack.Count -or $null -eq $stack.Peek()) { throw 'JSON property outside object.' }
            $holder=ConvertFrom-Json -InputObject ('{'+$token+':null}') -ErrorAction Stop
            $name=@($holder.PSObject.Properties.Name)[0]
            if ($stack.Peek().ContainsKey($name)) { throw "Duplicate or case-colliding recovery property: $name" }
            $stack.Peek()[$name]=$true
        }
        if ($stack.Count -gt 20) { throw 'Recovery nesting exceeds 20 levels.' }
    }
    $args=@{InputObject=$Text;ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {$args.DateKind='String'}
    ConvertFrom-Json @args
}
function Get-WelaRecoveryHash {
    param([byte[]]$Bytes)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $algorithm.Dispose() }
}
function Get-WelaRecoveryFile {
    param([string]$Path)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file -isnot [IO.FileInfo] -or $file.Length -lt 1 -or $file.Length -gt 4194304) {throw 'Recovery input must be a nonempty file of at most 4 MiB.'}
    for ($node=$file;$null -ne $node;$node=$node.Parent) {
        if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Recovery paths must not contain reparse points.'}
        if ($node -is [IO.FileInfo]) {$node=$node.Directory; if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Recovery paths must not contain reparse points.'}}
    }
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -gt 4194304) {throw 'Recovery input grew beyond the byte limit.'}
    [pscustomobject]@{Path=$file.FullName;Sha256=(Get-WelaRecoveryHash $bytes);Text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes).TrimStart([char]0xfeff)}
}
function Get-WelaRecoveryHost {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {throw 'Recovery requires native 64-bit Windows.'}
    $context=Get-WelaDefaultContext
    if (-not (Test-WelaDefaultContextComplete $context)) {throw 'Actual host context is incomplete.'}
    $machine=Get-WelaRegistryState 'HKLM:\SOFTWARE\Microsoft\Cryptography' MachineGuid
    $parsed=[guid]::Empty
    if (-not $machine.ValueExists -or $machine.Type -ne 'String' -or -not [guid]::TryParse([string]$machine.Value,[ref]$parsed) -or $parsed -eq [guid]::Empty -or -not [Environment]::MachineName) {throw 'Actual machine identity is unavailable.'}
    [pscustomobject][ordered]@{Computer=[Environment]::MachineName;MachineGuid=$parsed.ToString();ContextKey=(Get-WelaDefaultContextKey $context)}
}
function Get-WelaRecoveryKey {param($Value) ConvertTo-Json -InputObject $Value -Depth 20 -Compress}
function Assert-WelaRecoveryMask {param($Value) if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -notin @(0,1,2,3)) {throw 'Audit mask must be an integer 0..3.'}}
function Get-WelaRecoveryMaskTarget {
    param($Before,$Desired,$After)
    Assert-WelaRecoveryMask $Before; Assert-WelaRecoveryMask $Desired.Mask; Assert-WelaRecoveryMask $After
    if ($Desired.Mode -ceq 'exact') {if ($After -ne $Desired.Mask) {throw 'Exact write lacks matching final state.'};return [int]$Before}
    if ($Desired.Mode -cne 'minimum' -or ($After -band $Before) -ne $Before -or ($After -band $Desired.Mask) -ne $Desired.Mask) {throw 'Minimum write has inconsistent final state.'}
    # Undo only requested bits absent before WELA. Preserve independent additions.
    $added=$Desired.Mask -band (3 -bxor $Before)
    return [int]($After -band (3 -bxor $added))
}
function Assert-WelaRecoveryPrecedenceValue {
    param($Value)
    if ($Value.KeyExists -isnot [bool] -or -not $Value.KeyExists -or $Value.ValueExists -isnot [bool]) {throw 'Precedence requires an existing LSA key and typed value state.'}
    if ($Value.ValueExists) {
        if ($Value.Type -cne 'DWord' -or ($Value.Value -isnot [int] -and $Value.Value -isnot [long]) -or $Value.Value -notin @(0,1)) {throw 'Unknown prior precedence type/value requires manual recovery.'}
    } elseif ($null -ne $Value.Value -or $null -ne $Value.Type) {throw 'Absent precedence value has inconsistent state.'}
}
function New-WelaRecoveryPlan {
    param([string]$JournalPath,[string]$OriginalResultsPath,[string[]]$ControlId)
    $ErrorActionPreference='Stop'
    if (-not $ControlId -or $ControlId.Count -gt 60 -or @($ControlId | Select-Object -Unique).Count -ne $ControlId.Count) {throw 'Select 1..60 unique recovery control IDs explicitly.'}
    $hostState=Get-WelaRecoveryHost
    $journal=Get-WelaRecoveryFile $JournalPath; $resultFile=Get-WelaRecoveryFile $OriginalResultsPath
    $entries=@($journal.Text -split '\r?\n' | Where-Object {$_ -match '\S'} | ForEach-Object {ConvertFrom-WelaRecoveryJson $_})
    if ($entries.Count -lt 1 -or $entries.Count -gt 1024) {throw 'Journal must contain 1..1024 entries.'}
    $results=ConvertFrom-WelaRecoveryJson $resultFile.Text
    if ($results.DryRun -isnot [bool] -or $results.DryRun -or $results.Results -isnot [array] -or $results.Results.Count -gt 2048) {throw 'Original results must describe a completed non-dry-run configuration.'}
    $byId=@{}; $final=@{}
    foreach ($row in $results.Results) {
        if ($row.Id -isnot [string] -or -not $row.Id -or $final.ContainsKey($row.Id)) {throw 'Duplicate or invalid final result ID.'};$final[$row.Id]=$row
    }
    foreach ($entry in $entries) {
        if ($entry.Version -isnot [ValueType] -or $entry.Version -is [bool] -or $entry.Version -ne 1 -or $entry.ComputerName -isnot [string] -or $entry.ComputerName -ine $hostState.Computer -or
            $entry.Id -isnot [string] -or -not $entry.Id -or $byId.ContainsKey($entry.Id)) {throw 'Duplicate, wrong-host or invalid journal entry.'}
        $time=[datetimeoffset]::MinValue
        if ($entry.RecordedUtc -isnot [string] -or $entry.RecordedUtc -notmatch '(Z|\+00:00)$' -or -not [datetimeoffset]::TryParse($entry.RecordedUtc,[ref]$time) -or $time -gt [datetimeoffset]::UtcNow.AddMinutes(1)) {throw 'Journal timestamp must be valid UTC.'}
        $byId[$entry.Id]=$entry
    }
    $catalog=@{}; foreach ($item in (Import-WelaAuditProfiles).catalog) {$catalog['AuditPolicy/'+$item.id]=$item}
    $precedenceId='Registry/HKLM:\SYSTEM\CurrentControlSet\Control\Lsa/SCENoApplyLegacyAuditPolicy'
    $rows=New-Object 'System.Collections.Generic.List[object]'
    $targets=@{}
    $named=@{}; foreach ($item in Get-WelaNamedRecoveryCatalog) {$named[$item.Id]=$item}
    foreach ($id in ($ControlId | Sort-Object)) {
        if (-not $byId.ContainsKey($id) -or -not $final.ContainsKey($id)) {throw "Missing journal/final evidence for $id"}
        $entry=$byId[$id]; $last=$final[$id];$namedControl=$false
        if ($last.Status -cne 'Applied' -or $last.Id -cne $entry.Id -or $last.Kind -cne $entry.Kind) {throw "Only completed Applied writes can be recovered: $id"}
        foreach ($field in @('Before','Desired','Target')) {if ((Get-WelaRecoveryKey $entry.$field) -cne (Get-WelaRecoveryKey $last.$field)) {throw "Journal/final $field mismatch: $id"}}
        if ($entry.Kind -ceq 'AuditPolicy' -and $catalog.ContainsKey($id)) {
            if ($catalog[$id].id -cne $id.Substring(12) -or $entry.Target.Guid -isnot [string] -or $entry.Target.Guid -ine $catalog[$id].guid -or $targets.ContainsKey($entry.Target.Guid)) {throw 'Canonical audit name/GUID mismatch or duplicate target.'}
            $targets[$entry.Target.Guid]=$true
            $target=Get-WelaRecoveryMaskTarget $entry.Before $entry.Desired $last.After
        } elseif ($entry.Kind -ceq 'Registry' -and $id -ceq $precedenceId) {
            if ($entry.Target.Path -cne 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -or $entry.Target.Name -cne 'SCENoApplyLegacyAuditPolicy' -or $entry.Desired.Type -cne 'DWord' -or $entry.Desired.Value -ne 1) {throw 'Unsupported registry recovery target.'}
            Assert-WelaRecoveryPrecedenceValue $entry.Before; Assert-WelaRecoveryPrecedenceValue $last.After
            if (-not $last.After.ValueExists -or $last.After.Value -ne 1) {throw 'Final precedence is not enabled.'}
            # Never disable precedence while leaving another journaled subcategory unrestored.
            foreach ($other in $entries) {if ($other.Kind -eq 'AuditPolicy' -and $other.Id -notin $ControlId) {throw 'Precedence recovery requires every journaled audit subcategory to be selected.'}}
            $target=$entry.Before
        } elseif ($entry.Kind -ceq 'Registry' -and $named.ContainsKey($id)) {
            $definition=$named[$id]
            if ($id -cne $definition.Id -or $entry.Target.Path -cne $definition.Path -or $entry.Target.Name -cne $definition.Name -or $entry.Desired.Type -cne 'DWord' -or ($entry.Desired.Value -isnot [int] -and $entry.Desired.Value -isnot [long]) -or $entry.Desired.Value -ne 1) {throw 'Unsupported named logging registry recovery target.'}
            Assert-WelaNamedRecoveryValue $entry.Before; Assert-WelaNamedRecoveryValue $last.After
            if (-not $last.After.ValueExists -or $last.After.Value -ne 1) {throw 'Final logging switch is not enabled.'}
            $target=[pscustomobject]@{KeyExists=$true;ValueExists=$entry.Before.ValueExists;Value=$entry.Before.Value;Type=$entry.Before.Type}
            $namedControl=$true
        } else {throw "Unsupported control requires manual recovery: $id"}
        $row=[pscustomobject][ordered]@{Id=$id;Kind=$entry.Kind;Target=$entry.Target;Expected=$last.After;RecoverTo=$target}
        if ($namedControl) {
            $row.Kind='NamedLoggingRegistry'
            $row | Add-Member NoteProperty OriginalKeyExisted $entry.Before.KeyExists
            $row | Add-Member NoteProperty RegistryGuard (Get-WelaNamedRecoveryGuard (Get-WelaNamedRecoveryObservation $entry.Target))
        }
        $rows.Add($row)
    }
    $plan=[pscustomobject][ordered]@{
        Kind='WelaAuditRecoveryPlan';SchemaVersion=1
        Host=$hostState;Journal=[pscustomobject]@{Path=$journal.Path;Sha256=$journal.Sha256}
        OriginalResults=[pscustomobject]@{Path=$resultFile.Path;Sha256=$resultFile.Sha256}
        CatalogSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '../config/audit_profiles.json')).Hash.ToLowerInvariant()
        ControlIds=@($ControlId | Sort-Object);Controls=@($rows.ToArray() | Sort-Object Kind,Id)
        HistoricalIdentity='Version-1 journals record only ComputerName. MachineGuid/context bind this reviewed recovery plan, not the historical configuration. Hashes establish consistency, not authenticity.'
        UnsupportedJournalControls=@($entries | Where-Object {$_.Id -notin $ControlId} | Select-Object Id,Kind)
        ReadyRuleCredit=0
    }
    if (@($rows | Where-Object Kind -eq 'NamedLoggingRegistry').Count) {$plan | Add-Member NoteProperty NamedSources @(Get-WelaNamedRecoverySources)}
    return $plan
}
function Get-WelaRecoveryOutputDriveType {
    param([string]$Root)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {return ([IO.DriveInfo]::new($Root)).DriveType}
    # Offline fixture execution has no Windows drive classifications.
    return [IO.DriveType]::Fixed
}
function New-WelaRecoveryOutput {
    param([string]$Path)
    if (-not $Path) {throw 'A new output directory is required.'}
    $provider=$null;$drive=$null
    $resolved=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $resolved -match '^[\\/]{2}' -or $resolved.Substring([IO.Path]::GetPathRoot($resolved).Length).Contains(':')) {throw 'Output must be an ordinary local filesystem path without remote/device paths or alternate data streams.'}
    # Check the drive before probing the destination or its parent: a mapped
    # network drive can have an ordinary drive-letter path without a UNC prefix.
    if ((Get-WelaRecoveryOutputDriveType ([IO.Path]::GetPathRoot($resolved))) -ne [IO.DriveType]::Fixed) {throw 'Recovery output requires a local fixed drive.'}
    if (Test-Path -LiteralPath $resolved) {throw 'Output must be a new local filesystem directory.'}
    $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($resolved)) -ErrorAction Stop
    for ($node=$parent;$null -ne $node;$node=$node.Parent) {if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Output ancestors must not be reparse points.'}}
    $null=New-Item -ItemType Directory -Path $resolved -ErrorAction Stop
    if ($env:OS -eq 'Windows_NT') {
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
            $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $resolved -AclObject $acl -ErrorAction Stop
    }
    return $resolved
}
function Write-WelaRecoveryArtifact {
    param([string]$Path,$Value)
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $Value -Depth 24))
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
}
function Get-WelaRecoveryCurrent {
    param($Control)
    if ($Control.Kind -eq 'AuditPolicy') {return Get-WelaAuditPolicyMask $Control.Target.Guid}
    if ($Control.Kind -eq 'NamedLoggingRegistry') {
        $observation=Get-WelaNamedRecoveryObservation $Control.Target
        Assert-WelaNamedRecoveryGuard $Control $observation
        return Get-WelaNamedRecoveryState $observation
    }
    Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
}
function Set-WelaRecoveryCurrent {
    param($Control)
    if ($Control.Kind -eq 'AuditPolicy') {Set-WelaEffectiveAuditPolicy -Guid $Control.Target.Guid -Mask $Control.RecoverTo -Mode exact;return}
    if ($Control.Kind -eq 'NamedLoggingRegistry') {Set-WelaNamedRecoveryValue $Control;return}
    $path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($Control.RecoverTo.ValueExists) {Set-ItemProperty -LiteralPath $path -Name SCENoApplyLegacyAuditPolicy -Value $Control.RecoverTo.Value -Type DWord -ErrorAction Stop}
    else {Remove-ItemProperty -LiteralPath $path -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop}
}
function Assert-WelaRecoverySources {
    param($Plan)
    if ($Plan.PSObject.Properties.Name -contains 'NamedSources' -and (Get-WelaRecoveryKey @(Get-WelaNamedRecoverySources)) -cne (Get-WelaRecoveryKey $Plan.NamedSources)) {throw 'Named registry recovery implementation changed.'}
    foreach ($source in @($Plan.Journal,$Plan.OriginalResults)) {if ((Get-WelaRecoveryFile $source.Path).Sha256 -cne $source.Sha256) {throw 'Original recovery evidence changed.'}}
    if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '../config/audit_profiles.json')).Hash.ToLowerInvariant() -cne $Plan.CatalogSha256) {throw 'Canonical catalog changed.'}
    if ((Get-WelaRecoveryKey (Get-WelaRecoveryHost)) -cne (Get-WelaRecoveryKey $Plan.Host)) {throw 'Actual host changed since recovery planning.'}
}
function Invoke-WelaAuditRecovery {
    param([ValidateSet('Plan','Restore')][string]$Action='Plan',[string]$JournalPath,[string]$OriginalResultsPath,[string[]]$ControlId,[string]$PlanPath,[string]$OutputPath,[switch]$Auto,[switch]$DryRun)
    $ErrorActionPreference='Stop'
    if ($Action -eq 'Plan') {
        if ($PlanPath -or $Auto -or $DryRun) {throw 'Plan uses original journal/results and selected IDs; Auto/DryRun are Restore-only.'}
        $plan=New-WelaRecoveryPlan $JournalPath $OriginalResultsPath $ControlId
        $observed=@(foreach ($row in $plan.Controls) {[pscustomobject]@{Id=$row.Id;Current=(Get-WelaRecoveryCurrent $row);Expected=$row.Expected;RecoverTo=$row.RecoverTo}})
        Assert-WelaRecoverySources $plan
        $output=New-WelaRecoveryOutput $OutputPath
        Write-WelaRecoveryArtifact (Join-Path $output 'plan.json') $plan
        Write-WelaRecoveryArtifact (Join-Path $output 'observed.json') $observed
        return [pscustomobject]@{Status='Planned';ExitCode=0;OutputPath=$output;Controls=$observed;ReadyRuleCredit=0}
    }
    if ($JournalPath -or $OriginalResultsPath -or $ControlId -or -not $PlanPath) {throw 'Restore consumes only a reviewed PlanPath and a new OutputPath.'}
    $source=Get-WelaRecoveryFile $PlanPath; $plan=ConvertFrom-WelaRecoveryJson $source.Text
    if ($plan.Kind -cne 'WelaAuditRecoveryPlan' -or $plan.SchemaVersion -ne 1) {throw 'Unsupported recovery plan.'}
    Assert-WelaRecoverySources $plan
    $rebuilt=New-WelaRecoveryPlan $plan.Journal.Path $plan.OriginalResults.Path $plan.ControlIds
    if ((Get-WelaRecoveryKey $rebuilt) -cne (Get-WelaRecoveryKey $plan)) {throw 'Recovery plan differs from independently rebuilt source evidence.'}
    $output=if (-not $DryRun) {New-WelaRecoveryOutput $OutputPath} elseif ($OutputPath) {throw 'DryRun produces no directory; omit OutputPath.'} else {$null}
    $results=New-Object 'System.Collections.Generic.List[object]';$blocked=$false;$sequence=0
    foreach ($control in $plan.Controls) {
        $sequence++
        $row=[pscustomobject]@{Id=$control.Id;Status='Failed';Before=$null;After=$null;RecoverTo=$control.RecoverTo;Diagnostic=''}
        try {
            Assert-WelaRecoverySources $plan
            if ((Get-WelaRecoveryFile $source.Path).Sha256 -cne $source.Sha256) {throw 'Reviewed recovery plan changed.'}
            $row.Before=Get-WelaRecoveryCurrent $control
            if ((Get-WelaRecoveryKey $row.Before) -ceq (Get-WelaRecoveryKey $control.RecoverTo)) {$row.Status='AlreadyRecovered';$row.After=$row.Before}
            else {
                if ($blocked -and $control.Kind -eq 'Registry') {throw 'Precedence recovery blocked by incomplete audit recovery.'}
                if ((Get-WelaRecoveryKey $row.Before) -cne (Get-WelaRecoveryKey $control.Expected)) {throw 'Current state drifted from recorded post-configuration state.'}
                if ($control.Kind -eq 'AuditPolicy') {
                    $precedence=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
                    if (-not $precedence.ValueExists -or $precedence.Type -ne 'DWord' -or $precedence.Value -ne 1) {throw 'Enabled DWORD audit precedence is required before subcategory recovery.'}
                }
                if ($DryRun) {$row.Status='WouldRestore'}
                elseif (-not $Auto -and (Read-Host "Restore $($control.Id) to reviewed state? (y/N)") -cnotin @('y','Y')) {$row.Status='Declined';$blocked=$true}
                else {
                    Write-WelaRecoveryArtifact (Join-Path $output (('{0:d3}-before.json' -f $sequence))) ([pscustomobject]@{Host=$plan.Host;RecordedUtc=[datetime]::UtcNow.ToString('o');PlanSha256=$source.Sha256;Control=$control;Before=$row.Before})
                    Assert-WelaRecoverySources $plan
                    if ((Get-WelaRecoveryFile $source.Path).Sha256 -cne $source.Sha256 -or (Get-WelaRecoveryKey (Get-WelaRecoveryCurrent $control)) -cne (Get-WelaRecoveryKey $row.Before)) {throw 'State or reviewed plan changed before recovery write.'}
                    if ($control.Kind -eq 'AuditPolicy') {
                        $p=Get-WelaRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy
                        if (-not $p.ValueExists -or $p.Type -ne 'DWord' -or $p.Value -ne 1) {throw 'Audit precedence changed before recovery write.'}
                    } elseif ($control.Kind -eq 'Registry') {
                        foreach ($prior in $plan.Controls | Where-Object Kind -eq 'AuditPolicy') {if ((Get-WelaRecoveryKey (Get-WelaRecoveryCurrent $prior)) -cne (Get-WelaRecoveryKey $prior.RecoverTo)) {throw 'An audit mask changed before precedence recovery.'}}
                    }
                    Set-WelaRecoveryCurrent $control
                    $row.After=Get-WelaRecoveryCurrent $control
                    if ((Get-WelaRecoveryKey $row.After) -cne (Get-WelaRecoveryKey $control.RecoverTo)) {throw 'Recovery readback did not match.'}
                    $row.Status='Restored'
                }
            }
        } catch {$row.Status='Failed';$row.Diagnostic=$_.Exception.Message;$blocked=$true}
        $results.Add($row)
    }
    foreach ($row in $results | Where-Object {$_.Status -in @('Restored','AlreadyRecovered')}) {
        try {
            Assert-WelaRecoverySources $plan
            $control=$plan.Controls | Where-Object Id -eq $row.Id
            $row.After=Get-WelaRecoveryCurrent $control
            if ((Get-WelaRecoveryKey $row.After) -cne (Get-WelaRecoveryKey $control.RecoverTo)) {throw 'State changed during final recovery verification.'}
        } catch {$row.Status='Failed';$row.Diagnostic=$_.Exception.Message;$blocked=$true}
    }
    $report=[pscustomobject]@{Status=$(if ($blocked) {'Incomplete'} elseif ($DryRun) {'DryRun'} else {'Recovered'});ExitCode=[int]$blocked;DryRun=[bool]$DryRun;OutputPath=$output;Results=@($results.ToArray());ReadyRuleCredit=0;Scope='Selected audit masks, typed audit precedence and three named logging DWORDs only; value-only registry recovery retains keys. No persistence or event-generation proof.'}
    if (-not $DryRun) {Write-WelaRecoveryArtifact (Join-Path $output 'results.json') $report}
    return $report
}
