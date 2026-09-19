# Offline public exporter and independent Microsoft DDF fact fixtures.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'modules/AuditProfiles.psm1') -Force
. (Join-Path $repo 'scripts/IntuneAuditExport.ps1')
$script:checks=0
function Assert($Value,[string]$Message) { if (-not $Value) { throw "FAIL: $Message" };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Pattern) { $message='';try { & $Action | Out-Null } catch { $message=$_.Exception.Message };Assert ($message -match $Pattern) "Expected '$Pattern'; got '$message'" }
# Any hidden endpoint, policy or network dependency must fail this offline suite.
function Get-CimInstance { throw 'Forbidden endpoint query' }
function Get-WinEvent { throw 'Forbidden endpoint query' }
function Get-WelaEffectiveAuditPolicy { throw 'Forbidden endpoint query' }
function Set-WelaEffectiveAuditPolicy { throw 'Forbidden Windows mutation' }
function Invoke-WelaNative { throw 'Forbidden native command' }
function Set-ItemProperty { throw 'Forbidden registry mutation' }
function Invoke-RestMethod { throw 'Forbidden network request' }
function Invoke-WebRequest { throw 'Forbidden network request' }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-intune-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$profilePath=Join-Path $repo 'config/audit_profiles.json';$mappingPath=Join-Path $repo 'config/intune_audit_csp.json'
function New-FixtureProfile($Controls) {
    $data=Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    $fixture=[pscustomobject]@{id='fixture';version='1';sourceIds=@('wela');scope='advanced-audit-policy-only';omitted='unchanged';appliesTo=@([pscustomobject]@{roles=@('Client');minBuild=26100;maxBuild=26100});controls=$Controls;roleOverrides=[pscustomobject]@{}}
    $data.profiles=@($data.profiles)+$fixture
    $path=Join-Path $temp 'profile.json';$data | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}
try {
    $catalog=Import-WelaAuditProfiles
    $mapping=Import-WelaIntuneAuditMappings -Catalog $catalog.catalog
    $facts=Get-Content (Join-Path $PSScriptRoot 'fixtures/intune-audit-ddf-facts.json') -Raw | ConvertFrom-Json
    Assert ($facts.sha256 -ceq $mapping.provenance.auditSha256 -and $facts.facts.Count -eq 59) 'Independent source facts identify the pinned official DDF bytes'
    foreach ($entry in $mapping.mappings) {
        $fact=@($facts.facts | Where-Object node -ceq $entry.omaUri.Split('/')[-1])
        Assert ($fact.Count -eq 1 -and $fact[0].gpName -ceq $entry.gpEnglishName -and $fact[0].default -eq $entry.cspDocumentedDefault) "Exact CSP spelling, policy identity and source default: $($entry.id)"
        Assert ($fact[0].format -ceq 'int' -and ($fact[0].values -join ',') -ceq '0,1,2,3' -and $fact[0].conflict -ceq 'LastWrite') "Documented value/conflict contract: $($entry.id)"
        # A separate name check catches accidental swaps between valid CSP URIs.
        # Retain the DDF's literal "Distributio" spelling as source evidence.
        $expected=switch ($entry.id) { 'Plug and Play Events' {'Audit PNP Activity'} 'Token Right Adjusted Events' {'Audit Token Right Adjusted'} 'Audit Policy Change' {'Audit Policy Change'} 'Distribution Group Management' {'Audit Distributio Group Management'} default { 'Audit '+$entry.id } }
        Assert (($expected -replace '[^A-Za-z0-9]','') -ieq ($entry.gpEnglishName -replace '[^A-Za-z0-9]','')) "GUID catalog identity matches Microsoft GP identity: $($entry.id)"
    }
    foreach ($change in @('unknown-guid','duplicate-uri','bad-format','bad-precedence')) {
        $data=Get-Content $mappingPath -Raw | ConvertFrom-Json
        switch ($change) {
            'unknown-guid' {$data.mappings[0].guid='00000000-0000-0000-0000-000000000000'}
            'duplicate-uri' {$data.mappings[1].omaUri=$data.mappings[0].omaUri}
            'bad-format' {$data.auditDefinition.dataType='String'}
            'bad-precedence' {$data.precedenceDefinition.value=0}
        }
        $path=Join-Path $temp 'bad-map.json';$data|ConvertTo-Json -Depth 15|Set-Content $path -Encoding UTF8
        Reject {Import-WelaIntuneAuditMappings -Path $path -Catalog $catalog.catalog} 'Unknown|Unexpected'
    }
    foreach ($build in @(22000,22621,22631,20348,28000)) { Reject {Get-WelaIntuneAuditExportPlan wela-2.2.0 $build Enterprise} 'builds 26100 and 26200' }
    foreach ($edition in @('Home','Server','Unknown','enterprise')) { Reject {Get-WelaIntuneAuditExportPlan wela-2.2.0 26100 $edition} 'reviewed client edition' }
    Reject {Get-WelaIntuneAuditExportPlan microsoft-sct-server2025-2602 26100 Enterprise} 'does not support role'
    foreach ($edition in @('Pro','Enterprise','Education','IoTEnterprise')) { Assert ((Get-WelaIntuneAuditExportPlan wela-2.2.0 26200 $edition).ExitCode -eq 0) 'Reviewed CSP edition/build can be declared without endpoint reads' }
    $reference=Get-WelaIntuneAuditExportPlan windows-defaults-reviewed-2026-09 26100 Enterprise
    Assert ($reference.ExitCode -eq 1 -and ($reference.Blockers -join '') -match 'reference only') 'Documentary defaults cannot be exported as a deployment baseline'
    foreach ($mask in 0..3) {
        $path=New-FixtureProfile ([pscustomobject]@{Logon=[pscustomobject]@{mode='exact';mask=$mask}})
        $plan=Get-WelaIntuneAuditExportPlan fixture 26100 Enterprise -ProfilePath $path
        Assert ($plan.ExitCode -eq 0 -and $plan.CandidateSettings.Count -eq 2 -and $plan.CandidateSettings[1].Value -eq $mask -and $plan.CandidateSettings[1].Value -is [int]) 'Exact masks remain typed integers, including explicit no-auditing zero'
    }
    foreach ($mask in 0..3) {
        $path=New-FixtureProfile ([pscustomobject]@{Logon=[pscustomobject]@{mode='minimum';mask=$mask}})
        $reject=Get-WelaIntuneAuditExportPlan fixture 26100 Enterprise -ProfilePath $path
        $both=Get-WelaIntuneAuditExportPlan fixture 26100 Enterprise -ProfilePath $path -MinimumMode PromoteToBoth
        $row=@($both.Rows|Where-Object Id -eq Logon)[0]
        if ($mask -eq 0) { Assert ($both.CandidateSettings.Count -eq 0 -and $row.Disposition -eq 'MinimumZeroPreserved') 'Minimum zero emits neither a setting nor a precedence-only payload' }
        else {
            Assert ($both.ExitCode -eq 0 -and $row.CandidateValue -eq 3) 'A nonzero promoted minimum produces a static both-outcomes setting'
            foreach ($current in 0..3) { Assert (($row.CandidateValue -band $current) -eq $current -and ($row.CandidateValue -band $mask) -eq $mask) 'Promoted both preserves every possible existing native mask bit and satisfies the minimum' }
            Assert ($row.ExpandedBeyondMinimum -eq ($mask -in @(1,2))) 'Only promotion of one-bit minima is marked as a source expansion'
        }
        if ($mask -in @(1,2)) { Assert ($reject.ExitCode -eq 1 -and ($reject.Blockers -join '') -match 'cannot preserve unknown') 'Default mode refuses a false static minimum/merge claim' }
    }
    $path=New-FixtureProfile ([pscustomobject]@{Logon=[pscustomobject]@{mode='exact';mask=3};Logoff=[pscustomobject]@{mode='optional';mask=1};'Process Creation'=[pscustomobject]@{mode='not-configured'}})
    $plan=Get-WelaIntuneAuditExportPlan fixture 26100 Enterprise -ProfilePath $path
    Assert ($plan.Rows.Count -eq 59 -and @($plan.Rows|Where-Object Disposition -eq 'NotApplicable').Count -eq 10 -and $plan.CandidateSettings.Count -eq 2) 'All catalog rows survive while server-only and omitted rows never become payload settings'
    Assert (@($plan.Rows|Where-Object Disposition -eq 'NotConfiguredPreserved').Count -eq 1 -and @($plan.Rows|Where-Object Disposition -eq 'OptionalNotSelected').Count -eq 1) 'NotConfigured and unselected optional states remain distinct preservation reasons'
    $selected=Get-WelaIntuneAuditExportPlan fixture 26100 Enterprise -ProfilePath $path -IncludeOptional
    Assert ($selected.CandidateSettings.Count -eq 3 -and @($selected.Rows|Where-Object Disposition -eq 'SelectedOptionalExact').Count -eq 1) 'Optional selection is explicit and exact'
    foreach ($profile in @('wela-2.2.0','microsoft-sct-win11-24h2','cis-win11-v4-l1','cis-win11-v4-l2','asd-native-2021-10')) {
        $plan=Get-WelaIntuneAuditExportPlan $profile 26100 Enterprise
        $shared=Get-WelaAuditProfilePlan $profile Client 26100
        foreach ($setting in @($plan.CandidateSettings|Select-Object -Skip 1)) {
            $row=@($plan.Rows|Where-Object OmaUri -eq $setting.OmaUri)[0];$original=@($shared.policies|Where-Object guid -eq $row.Guid)[0]
            Assert ($setting.Value -eq $original.requiredMask -and $original.mode -eq 'exact') "Shared profile masks are unchanged: $profile / $($row.Id)"
        }
    }
    $output=Join-Path $temp 'bundle'
    $result=Invoke-WelaIntuneAuditExport wela-2.2.0 26100 Enterprise $output
    $manifest=Get-Content (Join-Path $output 'manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $body=Get-Content (Join-Path $output 'graph-body.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $csv=@(Import-Csv (Join-Path $output 'oma-settings.csv'))
    Assert ($manifest.PayloadEmitted -and -not $manifest.TenantContacted -and -not $manifest.Assigned -and $manifest.Rows.Count -eq 59 -and $manifest.SigmaCredit -eq 0) 'Public manifest reports artifact generation separately from deployment and rule evidence'
    Assert ($body.'@odata.type' -ceq '#microsoft.graph.windows10CustomConfiguration' -and -not $body.PSObject.Properties['assignments'] -and -not $body.PSObject.Properties['id']) 'Offline Graph body has the exact resource type without assignments or a tenant object ID'
    Assert ($body.omaSettings.Count -eq $csv.Count -and $body.omaSettings[0].value -eq 1 -and $body.omaSettings[0].omaUri -ceq $mapping.precedenceDefinition.omaUri) 'Prerequisite and settings agree between manual CSV and typed Graph artifacts'
    foreach ($setting in $body.omaSettings) {
        $c=@($csv|Where-Object 'OMA-URI' -ceq $setting.omaUri)
        Assert ($c.Count -eq 1 -and $c[0].DataType -ceq 'Integer' -and [int]$c[0].Value -eq $setting.value -and $setting.value -is [ValueType] -and $setting.'@odata.type' -ceq '#microsoft.graph.omaSettingInteger') 'Every exported CSP is exactly typed and identical across artifact formats'
    }
    Assert (($body|ConvertTo-Json -Depth 8) -notmatch 'MDMWinsOverGP|Sysmon|EMET|<Delete>') 'Payload contains no extra ownership, excluded provider or deletion controls'
    $receipt=Get-Content (Join-Path $output 'SHA256SUMS.json') -Raw|ConvertFrom-Json
    foreach ($file in $receipt.Files) { Assert ((Get-FileHash (Join-Path $output $file.Name)).Hash -ceq $file.Sha256) 'Receipt fingerprints every emitted artifact after readback' }
    Assert ($receipt.BundleComplete -and $receipt.Files.Count -eq 4) 'Complete receipt is distinct from its four reviewed artifacts'
    Reject {Invoke-WelaIntuneAuditExport wela-2.2.0 26100 Enterprise $output} 'already exists'
    $blockedPath=Join-Path $temp 'blocked'
    $blocked=Invoke-WelaIntuneAuditExport microsoft-wef-reviewed-2026-09 26100 Enterprise $blockedPath
    Assert ($blocked.ExitCode -eq 1 -and -not $blocked.PayloadEmitted -and -not(Test-Path (Join-Path $blockedPath 'graph-body.json')) -and -not(Test-Path (Join-Path $blockedPath 'oma-settings.csv'))) 'Blocked minimum export emits only review evidence, never a partial deployment policy'
    $promoted=Invoke-WelaIntuneAuditExport microsoft-wef-reviewed-2026-09 26100 Enterprise (Join-Path $temp 'promoted') -MinimumMode PromoteToBoth
    Assert ($promoted.ExitCode -eq 0 -and @($promoted.Plan.Rows|Where-Object ExpandedBeyondMinimum).Count -gt 0) 'Explicit promotion creates a usable artifact with recorded expansions'
    foreach ($bad in @('\\server\share','\\?\C:\temp','../parent','wild*card','HKLM:\new','C:relative')) { Reject {Get-WelaIntuneOutputDirectory $bad} 'local|exact' }
    Reject {Get-WelaIntuneOutputDirectory (Join-Path $temp 'absent-parent/new')} 'parent directory'
    $file=Join-Path $temp 'file';Set-Content $file 'do not overwrite';Reject {Get-WelaIntuneOutputDirectory $file} 'already exists'
    $unchanged=(Get-FileHash (Join-Path $output 'manifest.json')).Hash
    Reject {Write-WelaIntuneArtifact $output 'manifest.json' 'replacement'} 'already exists|exists'
    Assert ((Get-FileHash (Join-Path $output 'manifest.json')).Hash -ceq $unchanged) 'CreateNew refuses overwrite even at the final file-open boundary'
    $partialPath=Join-Path $temp 'partial'
    $writer=${function:Write-WelaIntuneArtifact}
    try {
        function Write-WelaIntuneArtifact {
            param($Directory,$Name,$Text)
            if ($Name -eq 'oma-settings.csv') { throw 'fixture disk write failure' }
            & $writer -Directory $Directory -Name $Name -Text $Text
        }
        Reject {Invoke-WelaIntuneAuditExport wela-2.2.0 26100 Enterprise $partialPath} 'fixture disk write failure'
        Assert ((Test-Path $partialPath) -and -not(Test-Path (Join-Path $partialPath 'SHA256SUMS.json'))) 'Partial export retains evidence but cannot create a complete receipt'
    } finally { Set-Item Function:\Write-WelaIntuneArtifact $writer }
    Write-Host "PASS: $script:checks offline Intune export assertions. Windows and network adapters were forbidden."
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
$global:LASTEXITCODE=0
