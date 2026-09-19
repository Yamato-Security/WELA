# Offline deployment components only. This script never calls GPMC, LGPO or Windows policy writers.
function ConvertTo-WelaGpoPackagePlan {
    param($ProfilePlan,[ValidateSet('Reject','PromoteToBoth')][string]$MinimumMode='Reject')
    $rows=@();$blockers=@()
    if ($ProfilePlan.referenceOnly) { $blockers+='Reference-only Windows defaults cannot be exported as a deployment policy.' }
    foreach ($policy in $ProfilePlan.policies) {
        $mask=$null;$disposition='Omitted';$reason=$policy.mode
        if ($policy.mode -eq 'optional' -and -not $ProfilePlan.includeOptional) { $reason='Optional control not selected.' }
        elseif ($policy.mode -in @('exact','minimum','optional')) {
            if ($policy.mode -eq 'minimum' -and $policy.requiredMask -eq 0) { $reason='Minimum zero imposes no requirement; preserve by omission.' }
            elseif ($policy.mode -eq 'minimum' -and $policy.requiredMask -in @(1,2) -and $MinimumMode -eq 'Reject') {
                $disposition='Blocked';$reason='GPO stores an exact mask. Explicit PromoteToBoth is required to avoid turning off an existing opposite audit bit.'
            } elseif ($policy.requiredMask -eq 0) {
                $disposition='Blocked';$reason='Exact No Auditing export is unsupported: normative MS-GPAC uses value 4 for None, but a Microsoft example uses 0. Native deployment semantics remain unvalidated.'
            } else {
                $disposition='Exported'
                $mask=if ($policy.mode -eq 'minimum') {3} else {[int]$policy.requiredMask}
                $reason=if ($policy.mode -eq 'minimum' -and $policy.requiredMask -ne 3) {'Explicit expansion: minimum Success or Failure becomes exact Success and Failure; additional event volume is possible.'}
                    elseif ($policy.mode -eq 'minimum') {'Minimum Both is equivalent to exact Both.'}
                    else {'Exact source mask; an opposite audit bit may be disabled when deployed. Target effective state is not assessed.'}
            }
        }
        if ($disposition -eq 'Blocked') { $blockers+="$($policy.id): $reason" }
        $rows+=[pscustomobject][ordered]@{
            Name=$policy.id;Guid=$policy.guid.ToUpperInvariant();Category=$policy.category;SourceMode=$policy.mode;RequiredMask=$policy.requiredMask
            Disposition=$disposition;ExportMask=$mask;Reason=$reason;SourceIds=@($policy.sourceIds);Prerequisites=@($policy.prerequisites);SourceNote=$policy.note
        }
    }
    if (-not @($rows|Where-Object Disposition -eq 'Exported').Count) { $blockers+='No applicable system audit subcategories were selected for export.' }
    [pscustomobject][ordered]@{
        SchemaVersion=1;Kind='WelaGpoAuditDeploymentComponents';Scope='advanced-audit-policy-and-precedence-components-only'
        Profile=$ProfilePlan.profile;ProfileVersion=$ProfilePlan.version;Role=$ProfilePlan.role;Build=$ProfilePlan.build
        ContextBasis='Operator-declared target role/build; no host or domain observations.'
        IncludeOptional=[bool]$ProfilePlan.includeOptional;MinimumMode=$MinimumMode;ProfileSchemaSha256=$ProfilePlan.schemaSha256.ToLowerInvariant()
        Sources=@($ProfilePlan.provenance);Controls=$rows;Blockers=$blockers
        Precedence=[pscustomobject][ordered]@{Path='MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy';Type='REG_DWORD';Value=1;Source='https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/e8edc8e2-4b91-433f-b1a2-672d4647e12f'}
        ImportableGpoBackup=$false;DeploymentVerified=$false;SigmaEvtxCredit=0
        UnsupportedControls=@('Event channel enablement, size, retention, permissions and WEF/collector configuration','Object, directory, registry, AD and WMI SACLs; AD CS AuditFilter','PowerShell module/script-block/transcription and process-command-line policies','Audit privileges, CrashOnAuditFail, notifications and diagnostic controls','Firewall text logs, SMB auditing, AppLocker and other provider-specific settings','Domain GPO creation, import, linking, filtering, delegation and client refresh')
    }
}
function Get-WelaGpoPackagePlan {
    param([Parameter(Mandatory)][string]$Profile,[Parameter(Mandatory)][ValidateSet('Client','MemberServer','DomainController','ADCS')][string]$Role,
        [Parameter(Mandatory)][ValidateRange(1,999999)][int]$Build,[ValidateSet('Reject','PromoteToBoth')][string]$MinimumMode='Reject',[switch]$IncludeOptional)
    $path=Join-Path $PSScriptRoot '../config/audit_profiles.json'
    $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    $profilePlan=Get-WelaAuditProfilePlan -Profile $Profile -Role $Role -Build $Build -IncludeOptional:$IncludeOptional
    $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($before -ne $after -or $after -ne $profilePlan.schemaSha256) { throw 'Shared audit profile source changed during planning; retry with a consistent source.' }
    ConvertTo-WelaGpoPackagePlan -ProfilePlan $profilePlan -MinimumMode $MinimumMode
}
function Get-WelaGpoComponentContent {
    param($Plan)
    if ($Plan.Blockers.Count) { throw ('Package export blocked: '+($Plan.Blockers -join ' ')) }
    $csv=@('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($row in $Plan.Controls) {
        if ($row.Disposition -ne 'Exported') { continue }
        # Built-in catalog labels are non-executable readable names; GUID/value govern policy.
        $name=$row.Name
        if ($name -match '[,"\r\n]' -or $row.ExportMask -notin @(1,2,3)) { throw 'Unsupported audit CSV label or exact mask.' }
        $csv+=",System,$name,{$($row.Guid)},$(Format-WelaAuditMask $row.ExportMask),,$($row.ExportMask)"
    }
    $template=@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Registry Values]',($Plan.Precedence.Path+'=4,1'))
    $review=@('# WELA GPO audit-policy deployment components','',
        '**This component folder is not a GPO backup and cannot be passed to Import-GPO. No host or domain policy has been changed.**','',
        "Profile: $($Plan.Profile) ($($Plan.ProfileVersion)); declared target: $($Plan.Role), build $($Plan.Build).",
        "Minimum policy: $($Plan.MinimumMode); optional controls selected: $($Plan.IncludeOptional).",
        "Shared profile SHA-256: $($Plan.ProfileSchemaSha256)",'',
        'The security template specifies only SCENoApplyLegacyAuditPolicy=1 (DWORD). Review precedence and effective policy separately after deployment.',
        'Omitted rows are absent from audit.csv. They do not clear settings supplied by another GPO, and they do not mean No Auditing.','',
        '| Subcategory / GUID | Source mode / mask | Export disposition / mask | Reason and prerequisites |','| --- | --- | --- | --- |')
    foreach ($row in $Plan.Controls) {
        $reason=($row.Reason+' '+($row.Prerequisites -join '; ')+' '+$row.SourceNote).Replace('|','\|').Replace("`r",' ').Replace("`n",' ')
        $review+="| $($row.Name) / $($row.Guid) | $($row.SourceMode) / $($row.RequiredMask) | $($row.Disposition) / $($row.ExportMask) | $reason |"
    }
    $review+=@('','## Unsupported scope','')+@($Plan.UnsupportedControls|ForEach-Object {'- '+$_})
    $review+=@('','## Profile source provenance','')
    foreach ($source in $Plan.Sources) { $review+="- $($source.id): $($source.source.title); $($source.source.version). $($source.source.url)" }
    $review+=@('',
        'Component validation does not prove GPO import, replication, client application, event generation or ingestion. Sigma EVTX credit remains zero. See deployment.md for preparation, staged review and recovery.')
    [ordered]@{
        'audit.csv'=[pscustomobject]@{Text=($csv -join "`r`n")+"`r`n";Encoding='utf-8'}
        'GptTmpl.inf'=[pscustomobject]@{Text=($template -join "`r`n")+"`r`n";Encoding='utf-16le-bom'}
        'review.md'=[pscustomobject]@{Text=($review -join "`r`n")+"`r`n";Encoding='utf-8'}
        'deployment.md'=[pscustomobject]@{Text=(Get-Content -LiteralPath (Join-Path $PSScriptRoot '../docs/gpo-package-deployment.md') -Raw -Encoding UTF8 -ErrorAction Stop).Replace("`r`n","`n").Replace("`n","`r`n");Encoding='utf-8'}
    }
}
function Get-WelaGpoContentBytes {
    param($Component)
    if ($Component.Encoding -eq 'utf-8') { $encoding=New-Object Text.UTF8Encoding($false) }
    elseif ($Component.Encoding -eq 'utf-16le-bom') { $encoding=New-Object Text.UnicodeEncoding($false,$true) }
    else { throw 'Unknown component encoding.' }
    return ,([byte[]](@($encoding.GetPreamble())+@($encoding.GetBytes($Component.Text))))
}
function Get-WelaGpoBytesHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
}
function Resolve-WelaGpoPackagePath {
    param([Parameter(Mandatory)][string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Package paths must use the filesystem.' }
    $full=[IO.Path]::GetFullPath($full)
    if ($full.StartsWith('\\?\') -or $full.StartsWith('\\.\')) {throw 'Device paths are unsupported.'}
    # Reject observed symbolic links/junctions, including ancestors. No traversal through them.
    $check=$full
    while ($check) {
        if (Test-Path -LiteralPath $check) {
            $item=Get-Item -LiteralPath $check -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Reparse-point package paths are unsupported.'}
        }
        $parent=[IO.Directory]::GetParent($check)
        if (-not $parent) {break};$check=$parent.FullName
    }
    return $full
}
function Test-WelaGpoPackage {
    param([Parameter(Mandatory)][string]$Path)
    $full=Resolve-WelaGpoPackagePath $Path
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {throw 'Package directory does not exist.'}
    $names=@('audit.csv','GptTmpl.inf','review.md','deployment.md','manifest.json')
    $files=@(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop)
    if ($files.Count -ne $names.Count -or @($files|Where-Object {$_.PSIsContainer -or $_.Name -cnotin $names -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count) {throw 'Package must contain exactly the five expected regular files, with no reparse points.'}
    foreach ($file in $files) {if ($file.Length -gt 4194304) {throw 'Component exceeds the supported size limit.'}}
    $manifest=Get-Content -LiteralPath (Join-Path $full 'manifest.json') -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    if (@($manifest.PSObject.Properties.Name).Count -ne 5 -or @($manifest.PSObject.Properties.Name|Where-Object {$_ -cnotin @('SchemaVersion','Kind','CreatedUtc','Plan','Files')}).Count) {throw 'Unexpected manifest metadata.'}
    $created=[DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$manifest.CreatedUtc,[ref]$created)) {throw 'Invalid manifest creation timestamp.'}
    if ($manifest.SchemaVersion -ne 1 -or $manifest.Kind -cne 'WelaGpoAuditDeploymentComponents' -or $manifest.Plan.IncludeOptional -isnot [bool] -or $manifest.Files.Count -ne 4) {throw 'Invalid deployment component manifest.'}
    $expected=Get-WelaGpoPackagePlan -Profile $manifest.Plan.Profile -Role $manifest.Plan.Role -Build $manifest.Plan.Build -MinimumMode $manifest.Plan.MinimumMode -IncludeOptional:$manifest.Plan.IncludeOptional
    if ((ConvertTo-Json -InputObject $manifest.Plan -Depth 18 -Compress) -cne (ConvertTo-Json -InputObject $expected -Depth 18 -Compress)) {throw 'Manifest intent/provenance does not match the installed shared profile. Regenerate and review the package.'}
    $content=Get-WelaGpoComponentContent $expected
    $seen=@{}
    foreach ($entry in $manifest.Files) {
        if (@($entry.PSObject.Properties.Name).Count -ne 4 -or @($entry.PSObject.Properties.Name|Where-Object {$_ -cnotin @('Name','Encoding','Length','Sha256')}).Count) {throw 'Unexpected component metadata.'}
        if ($entry.Name -cnotin @($content.Keys) -or $seen.ContainsKey($entry.Name)) {throw 'Unexpected or duplicate manifest component.'}
        $seen[$entry.Name]=$true
        $bytes=[IO.File]::ReadAllBytes((Join-Path $full $entry.Name))
        $hash=Get-WelaGpoBytesHash $bytes
        $expectedHash=Get-WelaGpoBytesHash (Get-WelaGpoContentBytes $content[$entry.Name])
        if ($entry.Encoding -cne $content[$entry.Name].Encoding -or $entry.Sha256 -cne $hash -or $entry.Length -ne $bytes.Length -or $hash -cne $expectedHash) {throw "Component content/hash differs from the reviewed installed profile: $($entry.Name)"}
    }
    [pscustomobject]@{Scope=$expected.Scope;Action='Verify';ExitCode=0;Path=$full;ComponentValidation='Matches installed shared profile and component generator';ImportableGpoBackup=$false;DeploymentVerified=$false;SigmaEvtxCredit=0;Plan=$expected}
}
function Export-WelaGpoPackage {
    param($Plan,[Parameter(Mandatory)][string]$Path,[switch]$DryRun)
    if ($Plan.Blockers.Count) {throw ('Package export blocked: '+($Plan.Blockers -join ' '))}
    $full=Resolve-WelaGpoPackagePath $Path
    if (Test-Path -LiteralPath $full) {throw 'Export requires a fresh output directory; existing files and directories are never reused.'}
    $parent=[IO.Directory]::GetParent($full)
    if (-not $parent -or -not (Test-Path -LiteralPath $parent.FullName -PathType Container)) {throw 'The output parent directory must already exist.'}
    $content=Get-WelaGpoComponentContent $Plan
    if ($DryRun) {return [pscustomobject]@{Scope=$Plan.Scope;Action='Export';ExitCode=0;DryRun=$true;Path=$full;ComponentValidation='Not exported';ImportableGpoBackup=$false;DeploymentVerified=$false;SigmaEvtxCredit=0;Plan=$Plan}}
    $stage=Join-Path $parent.FullName ('.wela-gpo-stage-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $stage -ErrorAction Stop
    try {
        $entries=@()
        foreach ($name in $content.Keys) {
            $bytes=Get-WelaGpoContentBytes $content[$name]
            $stream=[IO.File]::Open((Join-Path $stage $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush()} finally {$stream.Dispose()}
            $entries+=[pscustomobject][ordered]@{Name=$name;Encoding=$content[$name].Encoding;Length=$bytes.Length;Sha256=(Get-WelaGpoBytesHash $bytes)}
        }
        $manifest=[pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaGpoAuditDeploymentComponents';CreatedUtc=[DateTime]::UtcNow.ToString('o');Plan=$Plan;Files=$entries}
        [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'),(ConvertTo-Json -InputObject $manifest -Depth 18),(New-Object Text.UTF8Encoding($false)))
        $null=Test-WelaGpoPackage $stage
        $null=Resolve-WelaGpoPackagePath $full
        # Directory.Move refuses a raced destination; no overwrite or recursive merge.
        [IO.Directory]::Move($stage,$full)
        $result=Test-WelaGpoPackage $full
        $result.Action='Export';$result|Add-Member NoteProperty DryRun $false
        return $result
    } catch {throw "Component export did not complete: $($_.Exception.Message) Review any retained staging directory '$stage' or output '$full'; no Windows policy was changed."}
}
function Invoke-WelaGpoPackageCommand {
    param([ValidateSet('Plan','Export','Verify')][string]$Action='Plan',[string]$Profile,[string]$Role,[int]$Build,
        [ValidateSet('Reject','PromoteToBoth')][string]$MinimumMode='Reject',[switch]$IncludeOptional,[string]$Path,[switch]$DryRun)
    if ($DryRun -and $Action -ne 'Export') {throw '-DryRun requires GpoAction Export; Plan and Verify are read-only.'}
    if ($Action -eq 'Verify') {
        if ($Profile -or $Role -or $Build -or $IncludeOptional -or $MinimumMode -ne 'Reject') {throw 'Verify reads the package context; profile, role, build and expansion overrides are unsupported.'}
        if (-not $Path) {throw 'Verify requires -GpoOutputPath.'}
        return Test-WelaGpoPackage $Path
    }
    if (-not $Profile -or -not $Role -or -not $Build) {throw 'Plan and Export require explicit -GpoProfile, -Role and -Build for the declared deployment target.'}
    $plan=Get-WelaGpoPackagePlan -Profile $Profile -Role $Role -Build $Build -MinimumMode $MinimumMode -IncludeOptional:$IncludeOptional
    if ($Action -eq 'Export') {
        if (-not $Path) {throw 'Export requires -GpoOutputPath.'}
        return Export-WelaGpoPackage -Plan $plan -Path $Path -DryRun:$DryRun
    }
    if ($Path) {throw 'GpoOutputPath is supported only with Export or Verify.'}
    [pscustomobject]@{Scope=$plan.Scope;Action='Plan';ExitCode=$(if ($plan.Blockers.Count){1}else{0});ImportableGpoBackup=$false;DeploymentVerified=$false;SigmaEvtxCredit=0;Plan=$plan}
}
