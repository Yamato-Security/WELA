# Read-only historical control applicability and provenance-bound default evidence.
function Get-WelaDefaultContext {
    $result=[ordered]@{Status='Unknown';Build=$null;UBR=$null;Edition=$null;ProductType=$null;DomainRole=$null;DomainJoined=$null;Domain=$null;Architecture=$null;InstalledRoles=@();RolesStatus='Unknown';Diagnostic=''}
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows is required for a native default snapshot.' }
        if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell for exact native registry and role observations.' }
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ([string]$os.BuildNumber -notmatch '^\d+$' -or $null -eq $version.UBR -or -not $version.EditionID -or
            $os.ProductType -notin @(1,2,3) -or $computer.PartOfDomain -isnot [bool]) { throw 'Incomplete host build, patch, edition or join evidence.' }
        if (($os.ProductType -eq 1 -and $computer.DomainRole -notin @(0,1)) -or
            ($os.ProductType -eq 2 -and $computer.DomainRole -notin @(4,5)) -or
            ($os.ProductType -eq 3 -and $computer.DomainRole -notin @(2,3))) { throw 'Conflicting host role observations.' }
        $result.Build=[int]$os.BuildNumber; $result.UBR=[int]$version.UBR; $result.Edition=[string]$version.EditionID
        $result.ProductType=[int]$os.ProductType; $result.DomainRole=[int]$computer.DomainRole
        $result.DomainJoined=[bool]$computer.PartOfDomain; $result.Domain=[string]$computer.Domain; $result.Architecture=[string]$os.OSArchitecture
        if ($os.ProductType -eq 1) {
            $result.InstalledRoles=@(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object State -eq 'Enabled' | ForEach-Object { [string]$_.FeatureName } | Sort-Object -Unique)
        } else {
            $result.InstalledRoles=@(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed -eq $true | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        }
        $result.RolesStatus='Observed'; $result.Status='Observed'
    } catch { $result.Diagnostic=$_.Exception.Message }
    [pscustomobject]$result
}

function Get-WelaControlCatalog {
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/control_applicability.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($catalog.schemaVersion -ne 1) { throw 'Unsupported control applicability catalog.' }
    return $catalog
}

function Resolve-WelaControlApplicability {
    param($Definition,$Context,[string]$FeatureState='Unknown')
    $status='Unknown'; $reason='Host build/product type could not be established.'
    if ($Context.ProductType -in @(1,2,3) -and $Context.Build -is [ValueType] -and $Context.Build -gt 0) {
        if ($Context.ProductType -notin $Definition.productTypes) { $status='NotApplicable'; $reason='Historical source requirement applies to Windows 11 clients only.' }
        elseif ($Context.Build -ge $Definition.removal.firstBuild) { $status='NotApplicable'; $reason="Removed starting $($Definition.removal.release); no remediation is proposed." }
        elseif ($Context.Build -lt $Definition.minBuild) { $status='NotApplicable'; $reason='Outside the Windows 11 source scope.' }
        elseif ($Context.Build -gt $Definition.maxBuild -or $Context.Build -notin $Definition.reviewedBuilds) { $reason='Build not reviewed; no inferred support.' }
        elseif ($Context.Edition -notin $Definition.editions) { $reason='Edition is not in the reviewed historical support set.' }
        elseif ($FeatureState -in @('Disabled','DisabledWithPayloadRemoved','NotPresent')) { $status='NotApplicable'; $reason='Optional feature is unavailable or disabled; retained source requirement is conditional on its presence.' }
        elseif ($FeatureState -eq 'Enabled') { $status='Applicable'; $reason='Historical build and enabled feature observed; application/runtime event generation remains unverified.' }
        else { $reason='Optional feature state is unknown or pending; no remediation is proposed.' }
    }
    [pscustomobject]@{Status=$status;Reason=$reason;FeatureState=$FeatureState;Remediation=$null;SourceRequirement=$Definition.source;MinBuild=$Definition.minBuild;MaxBuild=$Definition.maxBuild;Removal=$Definition.removal}
}

function Get-WelaHistoricalControls {
    param($Context=(Get-WelaDefaultContext))
    foreach ($definition in (Get-WelaControlCatalog).controls) {
        $feature='Unknown'; $featureError=$null; $policy=$null; $policyState='Not assessed'
        $gate=Resolve-WelaControlApplicability $definition $Context
        # Never query DISM or propose reinstalling a feature on removed/server builds.
        if ($gate.Status -eq 'Unknown' -and $Context.Build -in $definition.reviewedBuilds -and $Context.ProductType -in $definition.productTypes -and $Context.Edition -in $definition.editions) {
            try {
                $observed=@(Get-WindowsOptionalFeature -Online -FeatureName $definition.feature -ErrorAction Stop)
                if ($observed.Count -ne 1 -or $observed[0].FeatureName -ne $definition.feature) { throw 'Exact optional feature result missing or ambiguous.' }
                $feature=[string]$observed[0].State
            } catch { $featureError=$_.Exception.Message }
        }
        $gate=Resolve-WelaControlApplicability $definition $Context $feature
        if ($gate.Status -eq 'Applicable') {
            try {
                $policy=Get-WelaRegistryState -Path $definition.registryPath -Name $definition.valueName
                $policyState=if (-not $policy.ValueExists) {'Not configured'} elseif ($policy.Type -ne $definition.requiredType) {'Unknown'} elseif ($policy.Value -eq $definition.requiredValue) {'Policy matches'} else {'Policy differs'}
            } catch { $policyState='Unknown'; $featureError=$_.Exception.Message }
        }
        [pscustomobject]@{Id=$definition.id;Title=$definition.title;Applicability=$gate;FeatureDiagnostic=$featureError;Policy=$policy;PolicyState=$policyState;AutomaticConfiguration='Unavailable: read-only historical assessment';EventGeneration='Unverified';DefaultSetting='Unknown'}
    }
}

function Get-WelaDefaultSourceFingerprints {
    foreach ($path in @('config/baselines.json','config/audit_profiles.json','config/control_applicability.json','scripts/ControlApplicability.ps1')) {
        [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "../$path") -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    }
}

function Get-WelaDefaultControlDefinitions {
    $config=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/baselines.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    $seen=@{}
    foreach ($item in $config.catalog) {
        if ($item.currentSetting.type -eq 'auditpol') { continue }
        $seen[$item.id]=$true
        [pscustomobject]@{Id=$item.id;Kind=$item.currentSetting.type;Definition=$item.currentSetting}
    }
    $profiles=Import-WelaAuditProfiles
    foreach ($item in $profiles.catalog) {
        $id='audit:'+([string]$item.guid).ToLowerInvariant()
        if ($seen.ContainsKey($id)) { throw 'Duplicate default evidence audit GUID.' }; $seen[$id]=$true
        [pscustomobject]@{Id=$id;Kind='auditpol';Definition=$item}
    }
}

function Get-WelaDefaultObservation {
    param($Control)
    $state='Unknown'; $value=$null; $raw=@(); $diagnostic=''
    try {
        switch ($Control.Kind) {
            'auditpol' {
                $mask=Get-WelaAuditPolicyMask -Guid $Control.Definition.guid
                $value=Format-WelaAuditMask $mask; $raw=@([pscustomobject]@{Guid=$Control.Definition.guid;Mask=$mask}); $state='Observed'
            }
            'native-channel' {
                $raw=@(foreach ($channel in $Control.Definition.channels) { Get-WelaNativeChannel -Name $channel })
                if (-not $raw.Count -or @($raw | Where-Object State -notin @('Enabled','Disabled','Not installed')).Count) { throw 'One or more channel observations are unknown.' }
                $value=(@($raw | ForEach-Object { "$($_.Name)=$($_.State)" }) -join '; '); $state='Observed'
            }
            'registry' {
                $raw=@(foreach ($path in $Control.Definition.paths) { [pscustomobject]@{Path=$path;Name=$Control.Definition.name;State=(Get-WelaRegistryState -Path $path -Name $Control.Definition.name)} })
                if (-not $raw.Count) { throw 'Registry definition has no paths.' }
                $value=(@($raw | ForEach-Object { if (-not $_.State.ValueExists) {"$($_.Path)=Not configured"} else {"$($_.Path)=$($_.State.Type):$($_.State.Value)"} }) -join '; '); $state='Observed'
            }
            default { throw 'Default observation kind is not supported.' }
        }
    } catch { $state='Unknown'; $value=$null; $diagnostic=$_.Exception.Message }
    [pscustomobject]@{Id=$Control.Id;Kind=$Control.Kind;Status=$state;Value=$value;Raw=$raw;Diagnostic=$diagnostic}
}

function New-WelaDefaultSnapshot {
    [pscustomobject][ordered]@{
        SchemaVersion=1;EvidenceKind='ObservedState';CapturedUtc=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME
        Context=(Get-WelaDefaultContext);Sources=@(Get-WelaDefaultSourceFingerprints)
        SourceVersions=(Import-WelaAuditProfiles).sources
        Review=[pscustomobject]@{Reviewer=$null;ReviewedUtc=$null;ImageSha256=$null;SnapshotId=$null;PolicyEvidenceSha256=$null;ProvisioningNotes=$null}
        Observations=@(Get-WelaDefaultControlDefinitions | ForEach-Object { Get-WelaDefaultObservation $_ })
        Warning='Observed settings are not Windows defaults. Only independently reviewed clean-install provenance can qualify a reference; domain join, promotion and CA installation define distinct scenarios.'
    }
}

function Test-WelaDefaultContextComplete {
    param($Context)
    $consistent=($Context.ProductType -eq 1 -and $Context.DomainRole -in @(0,1)) -or
        ($Context.ProductType -eq 2 -and $Context.DomainRole -in @(4,5)) -or ($Context.ProductType -eq 3 -and $Context.DomainRole -in @(2,3))
    $joined=$Context.DomainRole -in @(1,3,4,5)
    return $consistent -and $Context.DomainJoined -eq $joined -and $Context.Status -eq 'Observed' -and $Context.RolesStatus -eq 'Observed' -and
        ($Context.Build -is [int] -or $Context.Build -is [long]) -and $Context.Build -gt 0 -and
        ($Context.UBR -is [int] -or $Context.UBR -is [long]) -and $Context.UBR -ge 0 -and
        -not [string]::IsNullOrWhiteSpace($Context.Edition) -and $Context.ProductType -in @(1,2,3) -and
        $Context.DomainRole -in @(0,1,2,3,4,5) -and $Context.DomainJoined -is [bool] -and
        -not [string]::IsNullOrWhiteSpace($Context.Domain) -and -not [string]::IsNullOrWhiteSpace($Context.Architecture) -and
        $null -ne $Context.InstalledRoles
}

function Get-WelaDefaultContextKey {
    param($Context)
    # Fixed property order; host name intentionally excluded so matching lab peers can compare.
    [ordered]@{Build=$Context.Build;UBR=$Context.UBR;Edition=$Context.Edition;ProductType=$Context.ProductType;DomainRole=$Context.DomainRole;DomainJoined=$Context.DomainJoined;Domain=$Context.Domain;Architecture=$Context.Architecture;InstalledRoles=@($Context.InstalledRoles | Sort-Object -Unique)} | ConvertTo-Json -Depth 5 -Compress
}

function Test-WelaReviewedDefaultEvidence {
    param($Evidence,$Context,$Sources)
    $reason=''
    if (-not $Evidence -or $Evidence.SchemaVersion -ne 1 -or $Evidence.EvidenceKind -ne 'ReviewedCleanInstall') { $reason='Reference is not a reviewed clean-install scenario.' }
    elseif (-not (Test-WelaDefaultContextComplete $Context) -or -not (Test-WelaDefaultContextComplete $Evidence.Context)) { $reason='Exact host/role/patch evidence is incomplete.' }
    elseif ((Get-WelaDefaultContextKey $Context) -cne (Get-WelaDefaultContextKey $Evidence.Context)) { $reason='Build, patch, edition, architecture, domain/join or installed-role context differs.' }
    else {
        $review=$Evidence.Review
        $captured=[DateTimeOffset]::MinValue; $reviewed=[DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$Evidence.CapturedUtc,[ref]$captured) -or
            -not [DateTimeOffset]::TryParse([string]$review.ReviewedUtc,[ref]$reviewed) -or $reviewed -lt $captured -or
            [string]::IsNullOrWhiteSpace($review.Reviewer) -or [string]::IsNullOrWhiteSpace($review.SnapshotId) -or
            [string]::IsNullOrWhiteSpace($review.ProvisioningNotes) -or $review.ImageSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
            $review.PolicyEvidenceSha256 -notmatch '^[a-fA-F0-9]{64}$') { $reason='Clean-install review/image/snapshot/policy provenance is incomplete.' }
        elseif (@($Sources).Count -ne @($Evidence.Sources).Count) { $reason='Source fingerprint set differs.' }
        else {
            foreach ($source in $Sources) {
                $matches=@($Evidence.Sources | Where-Object Path -eq $source.Path)
                if ($matches.Count -ne 1 -or $matches[0].Sha256 -cne $source.Sha256) { $reason='Source or collector version fingerprint differs.'; break }
            }
            $ids=@{}
            foreach ($observation in $Evidence.Observations) {
                if (-not $observation.Id -or $ids.ContainsKey($observation.Id)) { $reason='Missing or duplicated observation ID.'; break }
                $ids[$observation.Id]=$true
            }
        }
    }
    [pscustomobject]@{Accepted=($reason -eq '');Reason=$(if ($reason) {$reason} else {'Operator-reviewed scenario reference; provenance is declared, not independently authenticated by WELA.'})}
}

function Get-WelaDefaultComparison {
    param($Snapshot,$Reference)
    $review=Test-WelaReviewedDefaultEvidence -Evidence $Reference -Context $Snapshot.Context -Sources $Snapshot.Sources
    $rows=foreach ($current in $Snapshot.Observations) {
        $match=@($Reference.Observations | Where-Object Id -eq $current.Id)
        $default='Unknown'; $reason=$review.Reason; $comparison='Unknown'
        if ($review.Accepted -and $match.Count -eq 1 -and $match[0].Status -eq 'Observed' -and
            $match[0].Value -is [string] -and $match[0].Value.Length -gt 0 -and $match[0].Kind -eq $current.Kind) {
            $default=$match[0].Value
            if ($current.Status -eq 'Observed') { $comparison=if ($current.Value -ceq $default) {'Matches reference'} else {'Differs from reference'} }
        } elseif ($review.Accepted) { $reason='Reference control is missing, unknown or malformed.' }
        [pscustomobject]@{Id=$current.Id;Current=$current;DefaultSetting=$default;DefaultEvidence=$reason;Comparison=$comparison}
    }
    [pscustomobject]@{ReferenceReview=$review;Results=@($rows);Scope='Scenario-specific native settings only; no event generation or Sigma eligibility claim.'}
}

function Invoke-WelaDefaultEvidenceCommand {
    param([ValidateSet('Capture','Compare')][string]$Action='Capture',[string]$ReferencePath,[string]$ResultsPath)
    if ($Action -eq 'Compare' -and -not $ReferencePath) { throw 'Compare requires DefaultEvidencePath.' }
    if ($Action -eq 'Capture' -and $ReferencePath) { throw 'DefaultEvidencePath requires Compare.' }
    $snapshot=New-WelaDefaultSnapshot
    $report=if ($Action -eq 'Compare') {
        $reference=Get-Content -LiteralPath $ReferencePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $comparison=Get-WelaDefaultComparison -Snapshot $snapshot -Reference $reference
        [pscustomobject]@{Action=$Action;Snapshot=$snapshot;Comparison=$comparison;ExitCode=$(if ($comparison.ReferenceReview.Accepted -and @($snapshot.Observations | Where-Object Status -eq 'Unknown').Count -eq 0) {0} else {1})}
    } else { [pscustomobject]@{Action=$Action;Snapshot=$snapshot;ExitCode=$(if ((Test-WelaDefaultContextComplete $snapshot.Context) -and @($snapshot.Observations | Where-Object Status -eq 'Unknown').Count -eq 0) {0} else {1})} }
    # Capture exports the snapshot directly so its exact artifact can be reviewed.
    if ($ResultsPath) { $(if ($Action -eq 'Capture') {$snapshot} else {$report}) | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    return $report
}
