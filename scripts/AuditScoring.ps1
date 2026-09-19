# Read-only, versioned and separable configuration / evidence-qualified readiness measures.
function Get-WelaScoreDefinition {
    $path=Join-Path $PSScriptRoot '../config/audit_scoring.json'
    $sourceData=Read-WelaScoreJsonBytes $path
    $definition=$sourceData.Value
    if ($definition.schemaVersion -ne 1 -or $definition.id -cne 'native-audit-score-v1' -or $definition.version -cne '1.0.0' -or $definition.configurationWeight -ne 1) { throw 'Unsupported score definition.' }
    $expected=@{critical=20;high=15;medium=10;low=5;informational=1;unknown=1}
    if (@($definition.ruleWeights.PSObject.Properties).Count -ne $expected.Count) { throw 'Unexpected severity weights.' }
    foreach ($key in $expected.Keys) { if (($definition.ruleWeights.$key -isnot [int] -and $definition.ruleWeights.$key -isnot [long]) -or $definition.ruleWeights.$key -ne $expected[$key]) { throw 'Score weights changed without a reviewed definition version.' } }
    $definition | Add-Member NoteProperty Sha256 $sourceData.Sha256
    return $definition
}
function Read-WelaScoreJsonBytes {
    param([string]$Path)
    $bytes=[IO.File]::ReadAllBytes($Path)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { $hash=([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $algorithm.Dispose() }
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    # Bind the parsed metadata to these exact bytes, including any BOM/newlines.
    $parsed=ConvertFrom-Json -InputObject ($encoding.GetString($bytes).TrimStart([char]0xFEFF)) -ErrorAction Stop
    [pscustomobject]@{Sha256=$hash;Value=$parsed}
}
function Get-WelaScorePercent {
    param([long]$Numerator,[long]$Denominator)
    if ($Denominator -eq 0) { return $null }
    return [Math]::Round(100.0*$Numerator/$Denominator,2)
}
function Get-WelaConfigurationScore {
    param($Plan,$Precedence)
    if ($Plan.referenceOnly) { throw 'Reference-only documentary defaults are not a recommended compliance target.' }
    $rows=@(foreach ($policy in $Plan.policies) {
        $included=$policy.mode -in @('exact','minimum') -or ($policy.mode -eq 'optional' -and $Plan.includeOptional)
        $reason='Selected advanced audit-policy requirement.'
        if ($included -and (($policy.requiredMask -isnot [int] -and $policy.requiredMask -isnot [long]) -or $policy.requiredMask -notin @(0,1,2,3))) { throw 'Invalid selected requirement mask.' }
        if (-not $included) { $reason="Omitted from denominator: $($policy.mode)." }
        elseif ($policy.mode -eq 'minimum' -and $policy.requiredMask -eq 0) { $included=$false; $reason='Minimum zero imposes no constraint; omitted from denominator.' }
        $state='Excluded'; $earned=0
        if ($included) {
            $current=$policy.currentMask; $required=$policy.requiredMask
            if (($required -isnot [int] -and $required -isnot [long]) -or $required -notin @(0,1,2,3)) { throw 'Invalid selected requirement mask.' }
            if (($current -isnot [int] -and $current -isnot [long]) -or $current -notin @(0,1,2,3)) { $state='Unknown'; $reason='Effective policy is unknown; included without credit.' }
            else {
                $matches=if ($policy.mode -eq 'minimum') { ($current -band $required) -eq $required } else { $current -eq $required }
                if ($matches) { $state='Compliant'; $earned=1 } else { $state='Drift' }
            }
        }
        [pscustomobject]@{Id=$policy.id;Guid=$policy.guid;Mode=$policy.mode;Current=$policy.currentMask;Required=$policy.requiredMask;Included=$included;State=$state;Weight=([int]$included);Earned=$earned;Reason=$reason;Prerequisites=$policy.prerequisites;Sources=$policy.sourceIds}
    })
    $requiresPrecedence=@($rows | Where-Object Included).Count -gt 0
    $state='Unknown'; $reason='Typed audit precedence is unknown; included without credit.'; $earned=0
    $registry=$Precedence.Registry
    if ($registry) {
        if (-not $registry.ValueExists) { $state='Drift'; $reason='Audit precedence is not configured.' }
        elseif ($registry.Type -eq 'DWord' -and ($registry.Value -is [int] -or $registry.Value -is [long]) -and $registry.Value -in @(0,1)) {
            if ($registry.Value -eq 1) { $state='Compliant'; $earned=1; $reason='Observed typed audit precedence matches.' } else { $state='Drift'; $reason='Audit precedence is disabled.' }
        }
    }
    if (-not $requiresPrecedence) { $state='Excluded'; $earned=0; $reason='No selected substantive audit constraint requires precedence; omitted from denominator.' }
    $rows+=[pscustomobject]@{Id='SCENoApplyLegacyAuditPolicy';Guid=$null;Mode='exact';Current=$registry;Required='DWORD=1';Included=$requiresPrecedence;State=$state;Weight=([int]$requiresPrecedence);Earned=$earned;Reason=$reason;Prerequisites='Later GPO/MDM refresh can change policy.';Sources=@('Advanced audit policy precedence prerequisite')}
    $included=@($rows | Where-Object Included)
    $numerator=[long](@($rows | Measure-Object Earned -Sum)[0].Sum)
    $denominator=[long]$included.Count
    [pscustomobject]@{Label='Advanced audit profile configuration compliance';Numerator=$numerator;Denominator=$denominator;Percent=(Get-WelaScorePercent $numerator $denominator);Compliant=@($included | Where-Object State -eq 'Compliant').Count;Drift=@($included | Where-Object State -eq 'Drift').Count;Unknown=@($included | Where-Object State -eq 'Unknown').Count;Excluded=@($rows | Where-Object { -not $_.Included }).Count;Scope='Advanced audit subcategories plus precedence. Channels, SACLs, provider activation, retention, forwarding and event generation are not scored.';Rows=$rows}
}
function Get-WelaReadinessScore {
    param($Eligibility,[hashtable]$Levels,$Definition)
    $seen=@{}
    $rows=@(foreach ($rule in $Eligibility.Results) {
        if ($rule.Id -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.Id)) { throw 'Eligibility rule ID is missing.' }
        if ($seen.ContainsKey([string]$rule.Id)) { throw 'Duplicate rule in eligibility output.' }; $seen[[string]$rule.Id]=$true
        $level=[string]$Levels[[string]$rule.Id]; $weightLevel=$level.ToLowerInvariant()
        if ($weightLevel -notin @('critical','high','medium','low','informational')) { $weightLevel='unknown' }
        $weight=[long]$Definition.ruleWeights.$weightLevel
        $included=$rule.State -notin @('Excluded','NotApplicable')
        $earned=if ($included -and $rule.State -eq 'Ready') { $weight } else { 0 }
        [pscustomobject]@{Id=$rule.Id;Title=$rule.Title;Level=$level;WeightLevel=$weightLevel;Weight=$weight;Included=$included;Earned=$earned;State=$rule.State;Reasons=$rule.Reasons;ScopeExclusion=$rule.ScopeExclusion;EvidenceAsOfUtc=$rule.EvidenceAsOfUtc;EvidenceContext=$rule.EvidenceContext;EvidenceArtifacts=$rule.EvidenceArtifacts;MetadataSha256=$rule.MetadataSha256}
    })
    $included=@($rows | Where-Object Included)
    $numerator=[long](@($included | Measure-Object Earned -Sum)[0].Sum)
    $denominator=[long](@($included | Measure-Object Weight -Sum)[0].Sum)
    [pscustomobject]@{Label='Evidence-qualified native rule readiness (severity weighted)';Numerator=$numerator;Denominator=$denominator;Percent=(Get-WelaScorePercent $numerator $denominator);ApplicableUniqueRules=$included.Count;Ready=@($included | Where-Object State -eq 'Ready').Count;UnknownSeverity=@($included | Where-Object WeightLevel -eq 'unknown').Count;Excluded=@($rows | Where-Object { -not $_.Included }).Count;Scope='Ready applies only to the original recorded evidence context and time. No evidence yields zero credit, not proof that logging is ineffective.';Rows=$rows}
}
function Invoke-WelaAuditScore {
    param([Parameter(Mandatory)][string]$Profile,[string]$EvidencePath,[string]$Role,[int]$Build,[switch]$IncludeOptional)
    if (($Role -and -not $Build) -or ($Build -and -not $Role)) { throw 'Supply both Role and Build for an offline scenario, or neither for the actual Windows host.' }
    $definition=Get-WelaScoreDefinition
    $current=@{}; $precedence=Get-WelaAuditPrecedenceState -Offline
    $observation=[pscustomobject]@{Basis='Offline scenario; no native settings observed';ComputerName=$null;Context=$null;Diagnostic='';CapturedUtc=[DateTime]::UtcNow.ToString('o')}
    if (-not $Role) {
        $hostContext=Get-WelaHostContext; $Role=$hostContext.Role; $Build=$hostContext.Build
        $observation.Context=Get-WelaDefaultContext
        $observation.Basis='Actual native Windows observation'
        $observation.ComputerName=[Environment]::MachineName
        if (-not (Test-WelaDefaultContextComplete $observation.Context) -or $observation.Context.Build -ne $Build) { throw 'Complete consistent actual host context is required; use explicit Role/Build for an offline scenario.' }
        $detailed=$observation.Context
        $roleMatches=switch ($Role) {
            'Client' { $detailed.ProductType -eq 1 -and $detailed.DomainRole -in @(0,1) }
            'DomainController' { $detailed.ProductType -eq 2 -and $detailed.DomainRole -in @(4,5) }
            'MemberServer' { $detailed.ProductType -eq 3 -and $detailed.DomainRole -in @(2,3) }
            'ADCS' { $detailed.ProductType -eq 3 -and $detailed.DomainRole -in @(2,3) -and $detailed.InstalledRoles -contains 'ADCS-Cert-Authority' }
            default { $false }
        }
        if (-not $roleMatches) { throw 'Observed score role contradicts detailed native host context.' }
        try { $current=Get-WelaEffectiveAuditPolicy } catch { $observation.Diagnostic=$_.Exception.Message }
        $precedence=Get-WelaAuditPrecedenceState
    }
    $profilePath=Join-Path $PSScriptRoot '../config/audit_profiles.json'
    $profileHash=(Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $plan=Get-WelaAuditProfilePlan -Profile $Profile -Role $Role -Build $Build -Current $current -IncludeOptional:$IncludeOptional
    if ($profileHash -cne $plan.schemaSha256.ToLowerInvariant() -or $profileHash -cne (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Profile source changed during scoring; its plan provenance is not stable.' }
    $configuration=Get-WelaConfigurationScore -Plan $plan -Precedence $precedence
    $corpusPath=Join-Path $PSScriptRoot '../config/security_rules.json'
    $mappingPath=Join-Path $PSScriptRoot '../config/eid_subcategory_mapping.csv'
    $manifestPath=Join-Path $PSScriptRoot '../config/rule_eligibility_manifest.json'
    $sourceData=Read-WelaScoreJsonBytes $corpusPath
    $beforeHash=$sourceData.Sha256; $metadata=$sourceData.Value
    $mappingHash=(Get-FileHash -LiteralPath $mappingPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $arguments=@{Role=$Role;Build=$Build}
    if ($EvidencePath) { $arguments.EvidencePath=$EvidencePath }
    $eligibility=Get-WelaRuleEligibility @arguments
    $afterHash=(Get-FileHash -LiteralPath $corpusPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeHash -cne $afterHash -or $beforeHash -cne $eligibility.Corpus.Sha256 -or
        $eligibility.Corpus.Pinned -isnot [bool] -or -not $eligibility.Corpus.Pinned -or
        $mappingHash -cne $eligibility.Corpus.MappingSha256 -or
        $mappingHash -cne (Get-FileHash -LiteralPath $mappingPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $manifestHash -cne (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Rule corpus/mapping/manifest changed or is unpinned; severity metadata is not bound to this eligibility report.'
    }
    $levels=@{}
    foreach ($entry in $metadata) {
        if ($levels.ContainsKey([string]$entry.id) -and $levels[[string]$entry.id] -cne [string]$entry.level) { throw 'Conflicting duplicate severity metadata.' }
        $levels[[string]$entry.id]=[string]$entry.level
    }
    $readiness=Get-WelaReadinessScore -Eligibility $eligibility -Levels $levels -Definition $definition
    [pscustomobject][ordered]@{SchemaVersion=1;Kind='WelaNativeAuditScores';GeneratedUtc=[DateTime]::UtcNow.ToString('o');Definition=$definition;Observation=$observation;ProfilePlan=$plan;Precedence=$precedence;Configuration=$configuration;Readiness=$readiness;Eligibility=$eligibility;OverallGrade=$null;Note=$definition.note}
}
function Export-WelaAuditScore {
    param($Report,[string]$ResultsPath,[string]$HtmlPath)
    $paths=@($ResultsPath,$HtmlPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [IO.Path]::GetFullPath($_) })
    if (@($paths | Select-Object -Unique).Count -ne $paths.Count) { throw 'JSON and HTML destinations must differ.' }
    foreach ($path in $paths) { if (Test-Path -LiteralPath $path) { throw 'Score output must use new files.' }; if (-not (Test-Path -LiteralPath (Split-Path $path -Parent) -PathType Container)) { throw 'Score output parent must exist.' } }
    $outputs=@()
    if ($ResultsPath) { $outputs+=@{Path=$ResultsPath;Text=($Report | ConvertTo-Json -Depth 28)} }
    if ($HtmlPath) {
        $e={param($value) [Net.WebUtility]::HtmlEncode([string]$value)}
        $cards=foreach ($measure in @($Report.Configuration,$Report.Readiness)) {
            $percent=if ($null -eq $measure.Percent) { 'N/A' } else { [string]::Format([Globalization.CultureInfo]::InvariantCulture,'{0:0.##}%',$measure.Percent) }
            $bar=if ($null -eq $measure.Percent) { 0 } else { $measure.Percent }
            '<article><h2>'+(& $e $measure.Label)+'</h2><p class="value">'+$percent+'</p><progress max="100" value="'+[string]::Format([Globalization.CultureInfo]::InvariantCulture,'{0:0.##}',$bar)+'"></progress><p>'+(& $e "$($measure.Numerator) / $($measure.Denominator) weighted points")+'</p><p>'+(& $e $measure.Scope)+'</p></article>'
        }
        $configRows=foreach ($row in $Report.Configuration.Rows) { '<tr><td>'+(& $e $row.Id)+'</td><td>'+(& $e $row.Mode)+'</td><td>'+(& $e $row.State)+'</td><td>'+(& $e "$($row.Earned)/$($row.Weight)")+'</td><td>'+(& $e $row.Reason)+'</td><td>'+(& $e $row.Prerequisites)+'</td></tr>' }
        $ruleRows=foreach ($row in $Report.Readiness.Rows) { '<tr><td>'+(& $e $row.Id)+'</td><td>'+(& $e $row.Title)+'</td><td>'+(& $e $row.WeightLevel)+'</td><td>'+(& $e $row.State)+'</td><td>'+(& $e "$($row.Earned)/$($row.Weight); included=$($row.Included)")+'</td><td>'+(& $e ($row.Reasons -join '; '))+'</td><td>'+(& $e $row.EvidenceAsOfUtc)+'</td><td>'+(& $e ($row.EvidenceContext | ConvertTo-Json -Depth 8 -Compress))+'</td></tr>' }
        $observation='<p>Observed computer: '+(& $e $Report.Observation.ComputerName)+'</p><p>Observation UTC: '+(& $e $Report.Observation.CapturedUtc)+'</p><p>Observation diagnostic: '+(& $e $Report.Observation.Diagnostic)+'</p><details><summary>Detailed observed context</summary><pre>'+(& $e ($Report.Observation.Context | ConvertTo-Json -Depth 8))+'</pre></details>'
        $html='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>WELA native audit scores</title><style>body{font:16px system-ui;margin:2rem;color:#182738;background:#f5f7fb}.cards{display:flex;gap:1rem;flex-wrap:wrap}article{background:white;border:1px solid #ccd5e0;border-radius:8px;padding:1rem;flex:1;min-width:260px}.value{font-size:2.5rem;margin:.3rem 0}progress{width:100%;height:1.2rem}table{border-collapse:collapse;background:white;width:100%;font-size:.85rem}td,th{border:1px solid #ccd5e0;padding:.5rem;text-align:left;overflow-wrap:anywhere}th{background:#e2eaf3}.scroll{overflow:auto}code{overflow-wrap:anywhere}</style><h1>WELA native audit scores</h1><p>'+(& $e $Report.Note)+'</p><p>'+(& $e "$($Report.Observation.Basis). Profile $($Report.ProfilePlan.profile); $($Report.ProfilePlan.role), build $($Report.ProfilePlan.build).")+'</p>'+$observation+'<div class="cards">'+($cards -join '')+'</div><p>'+(& $e "Configuration: $($Report.Configuration.Unknown) unknown, $($Report.Configuration.Excluded) excluded. Rules: $($Report.Readiness.Ready) Ready of $($Report.Readiness.ApplicableUniqueRules) applicable unique candidates; $($Report.Readiness.Excluded) excluded, $($Report.Readiness.UnknownSeverity) unknown severity. Evidence is tied to its recorded context/time, not automatically this host.")+'</p><p>Version '+(& $e $Report.Definition.version)+'; definition SHA-256 <code>'+(& $e $Report.Definition.Sha256)+'</code>; corpus SHA-256 <code>'+(& $e $Report.Eligibility.Corpus.Sha256)+'</code>.</p><h2>Configuration controls</h2><div class="scroll"><table><tr><th>Control</th><th>Mode</th><th>State</th><th>Points</th><th>Reason</th><th>Unscored prerequisite</th></tr>'+($configRows -join '')+'</table></div><h2>Native rules and exclusions</h2><p>Severity weights: critical 20, high 15, medium 10, low 5, informational 1, unknown 1. Only Ready earns points. Excluded rows never enter the denominator.</p><div class="scroll"><table><tr><th>Rule ID</th><th>Title</th><th>Severity</th><th>State</th><th>Points</th><th>Reasons</th><th>Evidence time</th><th>Evidence context</th></tr>'+($ruleRows -join '')+'</table></div></html>'
        $outputs+=@{Path=$HtmlPath;Text=$html}
    }
    foreach ($output in $outputs) {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes([string]$output.Text)
        $stream=[IO.File]::Open([IO.Path]::GetFullPath($output.Path),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    }
}
