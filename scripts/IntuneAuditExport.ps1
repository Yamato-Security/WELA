# Offline artifacts only: no Windows policy reads/writes, Graph requests or assignment.
function Import-WelaIntuneAuditMappings {
    param([string]$Path=(Join-Path $PSScriptRoot '../config/intune_audit_csp.json'),$Catalog)
    $data=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($data.schemaVersion -ne 1 -or -not $data.version -or @($data.mappings).Count -ne 59 -or @($Catalog).Count -ne 59) { throw 'Unknown Intune mapping schema/catalog; the reviewed 59 mappings are required.' }
    foreach ($hash in @($data.provenance.packageSha256,$data.provenance.auditSha256,$data.provenance.precedenceSha256)) {
        if ($hash -notmatch '^[a-f0-9]{64}$') { throw 'Missing Intune DDF provenance fingerprint.' }
    }
    $definition=$data.auditDefinition
    if ($definition.dataType -cne 'Integer' -or $definition.cspFormat -cne 'int' -or $definition.scope -cne 'Device' -or
        ($definition.allowedValues -join ',') -cne '0,1,2,3' -or ($definition.operations -join ',') -cne 'Add,Delete,Get,Replace' -or $definition.conflictResolution -cne 'LastWrite') { throw 'Unexpected Audit CSP format, masks, operations or conflict semantics.' }
    $seenGuids=@{};$seenUris=@{}
    foreach ($mapping in $data.mappings) {
        $match=@($Catalog | Where-Object { $_.guid -ieq $mapping.guid -and $_.id -ceq $mapping.id })
        if ($match.Count -ne 1 -or $seenGuids.ContainsKey($mapping.guid) -or $seenUris.ContainsKey($mapping.omaUri) -or
            $mapping.omaUri -cnotmatch '^\./Device/Vendor/MSFT/Policy/Config/Audit/[A-Za-z]+_Audit[A-Za-z]+$' -or $mapping.omaUri -match 'Sysmon|EMET' -or
            $mapping.cspDocumentedDefault -notin @(0,1,2,3) -or -not $mapping.gpEnglishName -or
            $mapping.sourceUrl -cne ('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-audit#'+($mapping.omaUri.Split('/')[-1]).ToLowerInvariant())) { throw "Unknown, duplicate or inconsistent Intune GUID/URI mapping: $($mapping.id)" }
        $seenGuids[$mapping.guid]=$true;$seenUris[$mapping.omaUri]=$true
    }
    $precedence=$data.precedenceDefinition
    if ($precedence.omaUri -cne './Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Audit_ForceAuditPolicySubcategorySettingsToOverrideAuditPolicyCategorySettings' -or
        $precedence.dataType -cne 'Integer' -or $precedence.cspFormat -cne 'int' -or $precedence.value -isnot [ValueType] -or $precedence.value -is [bool] -or $precedence.value -ne 1 -or
        $precedence.scope -cne 'Device' -or $precedence.conflictResolution -cne 'LastWrite' -or ($precedence.operations -join ',') -cne 'Add,Delete,Get,Replace' -or
        ($precedence.sourceMinimumVersions -join ',') -cne '10.0.26100,10.0.22621.5126') { throw 'Unexpected advanced audit precedence CSP definition.' }
    return $data
}

function Get-WelaIntuneAuditExportPlan {
    param([Parameter(Mandatory)][string]$Profile,[Parameter(Mandatory)][int]$Build,[Parameter(Mandatory)][string]$Edition,
        [ValidateSet('Reject','PromoteToBoth')][string]$MinimumMode='Reject',[switch]$IncludeOptional,
        [string]$ProfilePath=(Join-Path $PSScriptRoot '../config/audit_profiles.json'),[string]$MappingPath=(Join-Path $PSScriptRoot '../config/intune_audit_csp.json'))
    if ($Build -notin @(26100,26200)) { throw 'Intune export supports reviewed Windows 11 client builds 26100 and 26200 only, including the precedence CSP prerequisite.' }
    if ($Edition -cnotin @('Pro','Enterprise','Education','IoTEnterprise')) { throw 'Intune export requires a reviewed client edition: Pro, Enterprise, Education or IoTEnterprise.' }
    $profileHash=(Get-FileHash -LiteralPath $ProfilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    $mappingHash=(Get-FileHash -LiteralPath $MappingPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $catalog=Import-WelaAuditProfiles -Path $ProfilePath
    $mapping=Import-WelaIntuneAuditMappings -Path $MappingPath -Catalog $catalog.catalog
    $plan=Get-WelaAuditProfilePlan -Profile $Profile -Role Client -Build $Build -IncludeOptional:$IncludeOptional -Path $ProfilePath
    if ($profileHash -cne (Get-FileHash -LiteralPath $ProfilePath -Algorithm SHA256).Hash -or $profileHash -cne $plan.schemaSha256 -or
        $mappingHash -cne (Get-FileHash -LiteralPath $MappingPath -Algorithm SHA256).Hash) { throw 'Export source changed while being read; retry from consistent input files.' }
    $blockers=@();$rows=@();$settings=@()
    if ($plan.referenceOnly) { $blockers+='The selected profile is documentary reference only; it cannot be deployed as Windows defaults.' }
    foreach ($policy in $plan.policies) {
        $mapped=@($mapping.mappings | Where-Object guid -eq $policy.guid)[0]
        $value=$null;$disposition='Preserve';$expansion=$false
        switch ($policy.mode) {
            'not-applicable' { $disposition='NotApplicable' }
            'not-configured' { $disposition='NotConfiguredPreserved' }
            'unchanged' { $disposition='Preserve' }
            'optional' { if ($IncludeOptional) { $value=[int]$policy.requiredMask;$disposition='SelectedOptionalExact' } else { $disposition='OptionalNotSelected' } }
            'exact' { $value=[int]$policy.requiredMask;$disposition='ExactReplacement' }
            'minimum' {
                if ($policy.requiredMask -eq 0) { $disposition='MinimumZeroPreserved' }
                elseif ($policy.requiredMask -eq 3) { $value=3;$disposition='MinimumEquivalentToBoth' }
                elseif ($MinimumMode -eq 'PromoteToBoth') { $value=3;$disposition='PromotedToBoth';$expansion=$true }
                else { $disposition='BlockedMinimum';$blockers+="$($policy.id): minimum mask $($policy.requiredMask) cannot preserve unknown existing bits in a static LastWrite CSP value. Use explicit PromoteToBoth only after reviewing the expansion." }
            }
            default { throw "Unknown audit profile mode: $($policy.mode)" }
        }
        $row=[pscustomobject][ordered]@{Id=$policy.id;Guid=$policy.guid;Category=$policy.category;SourceMode=$policy.mode;RequiredMask=$policy.requiredMask;Disposition=$disposition;CandidateValue=$value;ExpandedBeyondMinimum=$expansion;OmaUri=$mapped.omaUri;DataType='Integer';CspFormat='int';ConflictResolution='LastWrite';CspDocumentedDefault=$mapped.cspDocumentedDefault;CurrentValue='Not observed';MappingSource=$mapped.sourceUrl;SourceIds=$policy.sourceIds;Prerequisites=$policy.prerequisites;SourceNote=$policy.note;SourceEvidence=$policy.evidence}
        $rows+=$row
        if ($null -ne $value) { $settings+=[pscustomobject][ordered]@{Name=$policy.id;Description="WELA $Profile; $($policy.mode) required=$($policy.requiredMask); $disposition. Current state and generated events are unverified.";OmaUri=$mapped.omaUri;DataType='Integer';Value=[int]$value} }
    }
    if ($settings.Count) {
        $precedence=[pscustomobject][ordered]@{Name='Advanced audit subcategory precedence';Description='Required companion setting: SCENoApplyLegacyAuditPolicy=1. This is separate from MDM/GPO ownership and is not a source-profile subcategory.';OmaUri=$mapping.precedenceDefinition.omaUri;DataType='Integer';Value=1}
        $settings=@($precedence)+$settings
    }
    if (-not $settings.Count -and -not $blockers.Count) { $blockers+='The selected profile requests no representable client settings; no precedence-only policy is emitted.' }
    [pscustomobject][ordered]@{SchemaVersion=1;Scope='offline-intune-native-audit-export';RecordedUtc=[datetime]::UtcNow.ToString('o');Status=$(if ($blockers.Count) {'BlockedReviewOnly'} else {'PreparedOffline'});ExitCode=$(if ($blockers.Count) {1} else {0});Target=[pscustomobject]@{Role='Client';Build=$Build;Edition=$Edition;Observation='Operator declaration; no endpoint was queried';Support='Reviewed CSP applicability only, not full source-baseline certification'};Profile=$plan.profile;ProfileVersion=$plan.version;ProfileSha256=$profileHash;MappingVersion=$mapping.version;MappingSha256=$mappingHash;DdfProvenance=$mapping.provenance;AuditCspDefinition=$mapping.auditDefinition;PrecedenceDefinition=$mapping.precedenceDefinition;SourceProvenance=$plan.provenance;IncludeOptional=[bool]$IncludeOptional;MinimumMode=$MinimumMode;Rows=$rows;CandidateSettings=$settings;Blockers=$blockers;PayloadEmitted=$false;TenantContacted=$false;Assigned=$false;WindowsConfigurationChanged=$false;SigmaCredit=0;Limitations=@('Integer masks replace values; exact 0/1/2 can disable existing audit bits. Minimum promotion enables both bits and can increase volume.','Omitted, not-configured and unselected optional rows emit no setting and no Delete; they do not remove previous MDM/GPO policy.','No MDMWinsOverGP setting is emitted. Review overlapping GPO, Settings Catalog, baseline, custom profiles and local scripts. LastWrite is not a guarantee against those conflicts.','The target edition/build is declared, not enforced by this artifact. Assign only to a validated matching pilot group.','SACLs, command-line payloads, provider/channel readiness, log size, retention, forwarding and events require separate validation. Sysmon and EMET are excluded.','Successful file export establishes no Intune acceptance, policy application, resultant audit masks, persistence, event generation or Sigma eligibility.')}
}

function Get-WelaIntuneOutputDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1f*?\[\]]' -or $Path -match '(^|[\\/])\.\.([\\/]|$)' -or $Path -match '^[\\/]{2}' -or $Path -match '^[A-Za-z]:[^\\/]') { throw 'Intune output requires an exact local new directory, without remote, wildcard, device, drive-relative or parent-traversal paths.' }
    $provider=$null;$drive=$null
    try { $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive) }
    catch { throw "Intune output must resolve to a local filesystem path: $($_.Exception.Message)" }
    if ($provider.Name -ne 'FileSystem' -or $full -match '^[\\/]{2}') { throw 'Intune output must use the local filesystem.' }
    if ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full)) { throw 'Intune output directory already exists; prior artifacts are never overwritten.' }
    $parent=[IO.DirectoryInfo]([IO.Path]::GetDirectoryName($full))
    if (-not $parent.Exists) { throw 'Intune output parent directory must already exist.' }
    $ancestor=$parent
    while ($ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Intune output cannot traverse a symlink or reparse point.' }
        $ancestor=$ancestor.Parent
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))).DriveType -ne [IO.DriveType]::Fixed) { throw 'Intune output requires a local fixed drive.' }
    return $full
}

function Write-WelaIntuneArtifact {
    param([string]$Directory,[string]$Name,[string]$Text)
    if ((Get-Item -LiteralPath $Directory -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Intune output directory changed to a reparse point.' }
    $path=Join-Path $Directory $Name
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { $expected=([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','') } finally { $algorithm.Dispose() }
    if ($hash -cne $expected) { throw "Intune artifact readback failed: $Name" }
    [pscustomobject]@{Name=$Name;Bytes=$bytes.Length;Sha256=$hash}
}

function Invoke-WelaIntuneAuditExport {
    param([Parameter(Mandatory)][string]$Profile,[Parameter(Mandatory)][int]$Build,[Parameter(Mandatory)][string]$Edition,[Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Reject','PromoteToBoth')][string]$MinimumMode='Reject',[switch]$IncludeOptional)
    $plan=Get-WelaIntuneAuditExportPlan -Profile $Profile -Build $Build -Edition $Edition -MinimumMode $MinimumMode -IncludeOptional:$IncludeOptional
    $directory=Get-WelaIntuneOutputDirectory $OutputPath
    $text=@{};$plan.PayloadEmitted=-not [bool]$plan.Blockers.Count
    if ($plan.PayloadEmitted) {
        $omaSettings=@($plan.CandidateSettings | ForEach-Object { [ordered]@{'@odata.type'='#microsoft.graph.omaSettingInteger';displayName=$_.Name;description=$_.Description;omaUri=$_.OmaUri;value=[int]$_.Value} })
        $graph=[ordered]@{'@odata.type'='#microsoft.graph.windows10CustomConfiguration';displayName="WELA $Profile - Windows 11 $Build $Edition";description="Offline reviewed WELA audit export. Profile $($plan.ProfileVersion); minimum mode $MinimumMode. Target $Edition build $Build must be scoped separately. No assignments included.";version=1;omaSettings=$omaSettings}
        $text['graph-body.json']=$graph | ConvertTo-Json -Depth 8
        $csv=@($plan.CandidateSettings | Select-Object Name,Description,@{n='OMA-URI';e={$_.OmaUri}},DataType,Value | ConvertTo-Csv -NoTypeInformation)
        $text['oma-settings.csv']=$csv -join [Environment]::NewLine
    }
    $text['manifest.json']=$plan | ConvertTo-Json -Depth 18
    $text['README.txt']=@"
WELA offline Intune native audit export
Status: $($plan.Status). Profile: $Profile. Declared client: $Edition build $Build.
Review every manifest row, omission, expansion, prerequisite and source fingerprint.
BlockedReviewOnly bundles contain no deployable Graph body or settings CSV; resolve
the blockers and export to another new directory. Never deploy candidate rows from
a blocked manifest as though they were a complete policy.

For PreparedOffline bundles, oma-settings.csv is a manual-entry/review list, NOT a
portal-importable profile. Add its case-sensitive OMA-URI rows as Integer settings
in a Windows custom configuration, or have an authorized operator review the
offline graph-body.json representation of windows10CustomConfiguration.
Graph reference: https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-windows10customconfiguration-create?view=graph-rest-1.0
This bundle sends no request and contains no assignment, device ID, tenant ID,
credential or token. It is not a Settings Catalog import file or provisioning XML.

Validate scope on a matching enrolled pilot client. Check existing GPO, Settings
Catalog, baseline, custom policy and script ownership before deployment. No
MDMWinsOverGP, deletion or rollback request is generated. Omissions do not remove
previously deployed settings. Review exact masks that can remove existing bits;
PromoteToBoth is an explicit expansion, not preservation of unknown current state.
After authorized deployment, verify Intune status, MDM diagnostic evidence,
SCENoApplyLegacyAuditPolicy=1 and native audit masks with WELA; then verify benign
event generation/collection and persistence after normal policy sync. Keep prior
authoritative policy evidence for operator-reviewed recovery. No complete logging,
source-baseline compliance or Sigma eligibility is established by file generation.
Native Windows only; Sysmon/EMET, SACLs and provider configuration are outside scope.

SHA256SUMS.json is written last after artifact readback. Without that receipt, the
directory is incomplete. Preserve incomplete files for review; export to a fresh
directory after fixing the error. Fingerprints detect changes, not source trust.
"@
    # All semantic validation/serialization happens before the first output write.
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $files=@()
    foreach ($name in @($text.Keys | Sort-Object)) { $files+=Write-WelaIntuneArtifact -Directory $directory -Name $name -Text $text[$name] }
    $receipt=[ordered]@{SchemaVersion=1;BundleComplete=$true;Status=$plan.Status;Files=$files}
    $null=Write-WelaIntuneArtifact -Directory $directory -Name 'SHA256SUMS.json' -Text ($receipt | ConvertTo-Json -Depth 5)
    Write-Host "Intune export $($plan.Status): $directory. No tenant or Windows policy was changed."
    foreach ($blocker in $plan.Blockers) { Write-Host "Blocked: $blocker" -ForegroundColor Yellow }
    [pscustomobject]@{ExitCode=$plan.ExitCode;Status=$plan.Status;OutputPath=$directory;PayloadEmitted=$plan.PayloadEmitted;Files=$files;Plan=$plan}
}
