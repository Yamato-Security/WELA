$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/AuditScoring.ps1')
. (Join-Path $root 'scripts/ControlApplicability.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1') -Force
$script:count=0
function Assert($Condition,$Message) { if (-not $Condition) {throw $Message};$script:count++ }
function Throws($Action,$Pattern) { $message='';try {& $Action | Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected $Pattern; got $message" }
function Policy($Mode,$Required,$Current) {[pscustomobject]@{id='fixture';guid='fixture';mode=$Mode;requiredMask=$Required;currentMask=$Current;prerequisites='SACL unscored';sourceIds=@('fixture')}}
function Plan($Rows,[switch]$Optional) {[pscustomobject]@{referenceOnly=$false;includeOptional=[bool]$Optional;policies=@($Rows)}}
$precedence=[pscustomobject]@{Registry=[pscustomobject]@{ValueExists=$true;Type='DWord';Value=1}}
$definition=Get-WelaScoreDefinition
Assert ($definition.Sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $root 'config/audit_scoring.json')).Hash.ToLowerInvariant()) 'Definition fingerprint covers the exact bytes parsed.'
foreach ($required in 0..3) {foreach ($current in 0..3) {
    $score=Get-WelaConfigurationScore (Plan @(Policy exact $required $current)) $precedence
    $matches=@('0/0','1/1','2/2','3/3') -contains "$required/$current"
    Assert ($score.Denominator -eq 2 -and $score.Rows[0].Earned -eq [int]$matches -and $score.Numerator -eq (1+[int]$matches)) "Exact $required/$current truth table including precedence."
}}
foreach ($required in 0..3) {foreach ($current in 0..3) {
    $score=Get-WelaConfigurationScore (Plan @(Policy minimum $required $current)) $precedence
    if ($required -eq 0) {Assert ($score.Denominator -eq 0 -and $null -eq $score.Percent) 'Minimum zero and unnecessary precedence impose no scored constraint.'}
    else {
        $matches=@('1/1','1/3','2/2','2/3','3/3') -contains "$required/$current"
        Assert ($score.Denominator -eq 2 -and $score.Rows[0].Earned -eq [int]$matches) "Minimum $required/$current includes compliant supersets."
    }
}}
foreach ($current in @($null,'1',$true,1.5,-1,4)) {
    $score=Get-WelaConfigurationScore (Plan @(Policy exact 1 $current)) $precedence
    Assert ($score.Unknown -eq 1 -and $score.Denominator -eq 2 -and $score.Numerator -eq 1) 'Unknown/malformed effective values remain in the denominator with zero credit.'
}
foreach ($mode in @('exact','minimum','optional')) {
    Throws {Get-WelaConfigurationScore (Plan @(Policy $mode '0' 0) -Optional) $precedence} 'Invalid selected'
}
foreach ($mode in @('unchanged','not-configured','not-applicable','optional')) {
    $score=Get-WelaConfigurationScore (Plan @(Policy $mode 3 3)) $precedence
    Assert ($score.Denominator -eq 0 -and $score.Numerator -eq 0 -and $null -eq $score.Percent) 'Preserve, N/A and unselected optional rows do not improve scores.'
}
$score=Get-WelaConfigurationScore (Plan @(Policy optional 1 3) -Optional) $precedence
Assert ($score.Denominator -eq 2 -and $score.Rows[0].State -eq 'Drift') 'Selected optional mask is exact, not minimum.'
foreach ($registry in @($null,[pscustomobject]@{ValueExists=$true;Type='String';Value='1'},[pscustomobject]@{ValueExists=$true;Type='DWord';Value='1'})) {
    $score=Get-WelaConfigurationScore (Plan @(Policy exact 1 1)) ([pscustomobject]@{Registry=$registry})
    Assert ($score.Unknown -eq 1 -and $score.Denominator -eq 2 -and $score.Percent -eq 50) 'Unknown/mistyped precedence stays in denominator without credit.'
}
$reference=Plan @();$reference.referenceOnly=$true
Throws {Get-WelaConfigurationScore $reference $precedence} 'Reference-only'
Assert ($null -eq (Get-WelaScorePercent 0 0)) 'Empty denominator is null, never perfect or zero percent.'
function Rule($Id,$State='Conditional') {[pscustomobject]@{Id=$Id;Title='Fixture <script>alert(1)</script>';State=$State;Reasons=@('Evidence unverified <tag>');ScopeExclusion=$null;EvidenceAsOfUtc=$null;EvidenceContext=$null;EvidenceArtifacts=@();MetadataSha256=('a'*64);ConfigurationEstimate=$true}}
$levels=@{a='critical';b='high';c='medium';d='low';e='informational';f='unknown';g='';h='CRITICAL'}
$rules=@(foreach($id in @('a','b','c','d','e','f','g','h')){Rule $id})
$readiness=Get-WelaReadinessScore ([pscustomobject]@{Results=$rules}) $levels $definition
Assert ($readiness.Denominator -eq 73 -and $readiness.Numerator -eq 0 -and $readiness.UnknownSeverity -eq 2) 'All severity weights, including unknown=1, are explicit; configuration hints earn no readiness credit.'
$rules[0].State='Ready';$rules[0].EvidenceAsOfUtc='2026-09-19T10:00:00Z';$rules[0].EvidenceContext=[pscustomobject]@{computer='lab<&>';role='Client';build=26100;patch='fixture';backend='fixture-backend';backendVersion='1'}
$rules[0].EvidenceArtifacts=@([pscustomobject]@{path='event.xml';sha256=('b'*64)})
$rules[1].State='NotApplicable';$rules[1].ScopeExclusion='Different role';$rules[2].State='Excluded';$rules[2].ScopeExclusion='Sysmon';$rules[3].State='Blocked'
$readiness=Get-WelaReadinessScore ([pscustomobject]@{Results=$rules}) $levels $definition
Assert ($readiness.Denominator -eq 48 -and $readiness.Numerator -eq 20 -and $readiness.Ready -eq 1 -and $readiness.Excluded -eq 2) 'Only evidence-qualified Ready earns weight; Blocked/Conditional stay in scope and explicit exclusions are removed.'
Assert ($readiness.Rows[0].EvidenceContext.computer -ceq 'lab<&>' -and $readiness.Rows[0].EvidenceArtifacts[0].path -eq 'event.xml') 'Recorded evidence context and artifact references survive scoring.'
Throws {Get-WelaReadinessScore ([pscustomobject]@{Results=@($rules[0],$rules[0])}) $levels $definition} 'Duplicate'
Throws {Get-WelaReadinessScore ([pscustomobject]@{Results=@(Rule '')}) $levels $definition} 'ID is missing'
$empty=Get-WelaReadinessScore ([pscustomobject]@{Results=@()}) @{} $definition
Assert ($empty.Denominator -eq 0 -and $null -eq $empty.Percent) 'Empty readiness scope is N/A.'
$none=Get-WelaReadinessScore ([pscustomobject]@{Results=@((Rule x Excluded),(Rule y NotApplicable))}) @{} $definition
Assert ($none.Denominator -eq 0 -and $null -eq $none.Percent) 'All-excluded readiness scope is N/A.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-score-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
try {
    $report=[pscustomobject]@{Note='Two measures <not a security grade>';Definition=$definition;Observation=[pscustomobject]@{Basis='Offline <fixture>';CapturedUtc='2026-09-19T09:00:00Z';Diagnostic='Access denied <observation>';Context=[pscustomobject]@{Computer='observed-fixture'}};ProfilePlan=[pscustomobject]@{profile='fixture';role='Client';build=26100};Configuration=$score;Readiness=$readiness;Eligibility=[pscustomobject]@{Corpus=[pscustomobject]@{Sha256=('c'*64)}};OverallGrade=$null}
    $json=Join-Path $temp 'score.json';$html=Join-Path $temp 'score.html'
    Export-WelaAuditScore $report $json $html
    $loaded=Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
    $rendered=[IO.File]::ReadAllText($html)
    Assert ($loaded.Readiness.Numerator -eq 20 -and $loaded.Readiness.Rows[0].EvidenceContext.computer -ceq 'lab<&>' -and $null -eq $loaded.OverallGrade) 'JSON retains separate measures and historical evidence scope, without an overall grade.'
    Assert ($rendered -notmatch '<script>' -and $rendered -match '&lt;script&gt;' -and $rendered -match '2026-09-19T10:00:00Z' -and $rendered -match 'fixture-backend') 'HTML encodes arbitrary text and visibly retains evidence time/backend context.'
    Assert ($rendered -match '2026-09-19T09:00:00Z' -and $rendered -match 'Access denied &lt;observation&gt;' -and $rendered -match 'observed-fixture') 'HTML explains unknown native reads with observation time, encoded diagnostic and observed context.'
    $decoded=[Net.WebUtility]::HtmlDecode($rendered)
    Assert ($decoded -match 'lab<&>|lab\\u003c\\u0026\\u003e') 'Rendered JSON context preserves its value under PowerShell 5.1/7 escaping differences.'
    $hash=(Get-FileHash -LiteralPath $json).Hash
    Throws {Export-WelaAuditScore $report $json $null} 'new files'
    Assert ((Get-FileHash -LiteralPath $json).Hash -ceq $hash) 'Existing reports are not overwritten.'
    $same=Join-Path $temp 'same.json'
    Throws {Export-WelaAuditScore $report $same (Join-Path $temp './same.json')} 'differ'
    Assert (-not (Test-Path -LiteralPath $same)) 'Destination collision fails before either output is written.'
    Throws {Export-WelaAuditScore $report (Join-Path $temp 'missing/score.json') $null} 'parent'
    $script:realRead=(Get-Command Read-WelaScoreJsonBytes).ScriptBlock
    $script:metadataSnapshot=& $script:realRead (Join-Path $root 'config/security_rules.json')
    $script:ruleId=[string]$script:metadataSnapshot.Value[0].id
    $script:nativeReads=0;$script:scenario='normal';$script:manifestReads=0;$script:profileReads=0
    function Get-WelaAuditPrecedenceState {param([switch]$Offline) if(-not $Offline){$script:nativeReads++};[pscustomobject]@{Registry=$null}}
    function Get-WelaHostContext {$script:nativeReads++;throw 'Native reader must not be called by explicit offline context'}
    function Get-WelaDefaultContext {$script:nativeReads++;throw 'Native context must not be read offline'}
    function Get-WelaEffectiveAuditPolicy {$script:nativeReads++;throw 'Native policy must not be read offline'}
    function Get-WelaRuleEligibility {
        param($Role,$Build,$EvidencePath)
        [pscustomobject]@{Corpus=[pscustomobject]@{Pinned=($script:scenario -ne 'unpinned');Sha256=$script:metadataSnapshot.Sha256;MappingSha256=(Microsoft.PowerShell.Utility\Get-FileHash (Join-Path $root 'config/eid_subcategory_mapping.csv')).Hash.ToLowerInvariant()};Results=@(Rule $script:ruleId);RequestedContext=[pscustomobject]@{Role=$Role;Build=$Build}}
    }
    function Read-WelaScoreJsonBytes {param($Path) $result=& $script:realRead $Path;if($script:scenario -eq 'metadata-race' -and $Path -like '*security_rules.json'){$result.Sha256='d'*64};$result}
    function Get-WelaAuditProfilePlan {
        param($Profile,$Role,$Build,$Current,[switch]$IncludeOptional)
        $result=AuditProfiles\Get-WelaAuditProfilePlan @PSBoundParameters
        if($script:scenario -eq 'profile-plan-mismatch'){$result.schemaSha256='f'*64}
        $result
    }
    function Get-FileHash {
        param($LiteralPath,$Algorithm='SHA256')
        $result=Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
        if($LiteralPath -like '*rule_eligibility_manifest.json'){$script:manifestReads++;if($script:scenario -eq 'manifest-race' -and $script:manifestReads -ge 2){$result.Hash='e'*64}}
        if($LiteralPath -like '*audit_profiles.json'){
            $script:profileReads++
            if($script:scenario -eq 'profile-after-race' -and $script:profileReads -ge 2){$result.Hash='f'*64}
        }
        $result
    }
    $offline=Invoke-WelaAuditScore -Profile wela-2.2.0 -Role Client -Build 26100
    Assert ($script:nativeReads -eq 0 -and $offline.Configuration.Unknown -eq $offline.Configuration.Denominator -and $offline.Readiness.Ready -eq 0) 'Explicit Role/Build always stays offline with unknown configuration and no automatic readiness.'
    foreach($case in @('metadata-race','unpinned','manifest-race')){
        $script:scenario=$case;$script:manifestReads=0
        Throws {Invoke-WelaAuditScore -Profile wela-2.2.0 -Role Client -Build 26100} 'changed or is unpinned'
    }
    foreach($case in @('profile-after-race','profile-plan-mismatch')){
        $script:scenario=$case;$script:profileReads=0
        Throws {Invoke-WelaAuditScore -Profile wela-2.2.0 -Role Client -Build 26100} 'Profile source changed'
    }
    $script:scenario='normal'
    $script:hostRole='Client'
    function Get-WelaHostContext {$script:nativeReads++;[pscustomobject]@{Role=$script:hostRole;Build=26100}}
    function Get-WelaDefaultContext {
        $script:nativeReads++
        [pscustomobject]@{Computer='actual-fixture';Build=26100;UBR=1;Edition='Professional';ProductType=1;DomainRole=0;DomainJoined=$false;Domain='WORKGROUP';Architecture='64-bit';ProcessorArchitecture=9;InstalledRoles=@();Status='Observed';RolesStatus='Observed'}
    }
    function Get-WelaEffectiveAuditPolicy {$script:nativeReads++;throw 'Audit reader denied <fixture>'}
    $denied=Invoke-WelaAuditScore -Profile wela-2.2.0
    Assert ($denied.Observation.Basis -eq 'Actual native Windows observation' -and $denied.Observation.Context.Computer -eq 'actual-fixture' -and $denied.Observation.Diagnostic -ceq 'Audit reader denied <fixture>' -and $denied.Configuration.Unknown -eq $denied.Configuration.Denominator) 'Denied native policy reads preserve exact observed context and diagnostic while remaining unknown.'
    $script:hostRole='MemberServer'
    Throws {Invoke-WelaAuditScore -Profile wela-2.2.0} 'role contradicts'
    Throws {Invoke-WelaAuditScore -Profile wela-2.2.0 -Role Client} 'both Role and Build'
    $exe=(Get-Process -Id $PID).Path
    foreach($arguments in @(@('configure','-ScoreProfile','wela-2.2.0'),@('score','-Auto'),@('score','-Profile','wela-2.2.0'),@('score'))){
        $ErrorActionPreference='Continue';try{$output=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference='Stop'}
        Assert ($code -ne 0 -and ($output -join ' ') -match 'No command|requires an explicit') 'Public score guard rejects unrelated mutations and ambiguous profile selection.'
    }
    Write-Host "PASS: $script:count audit-scoring assertions; all evidence rows are synthetic and native readers mocked."
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$global:LASTEXITCODE=0
