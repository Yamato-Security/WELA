$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/ControlApplicability.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1')
$script:count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Copy-Object($Value) { ConvertFrom-WelaDefaultEvidenceJson ($Value | ConvertTo-Json -Depth 20) }
$context=[pscustomobject]@{Status='Observed';Build=22631;UBR=1234;Edition='Enterprise';ProductType=1;DomainRole=1;DomainJoined=$true;Domain='lab.test';Architecture='64-bit';ProcessorArchitecture=9;InstalledRoles=@('FeatureB','FeatureA');RolesStatus='Observed';Diagnostic='fixture'}
$script:processorRows=@()
function Get-CimInstance { param($ClassName,$ErrorAction) if ($ClassName -ne 'Win32_Processor') { throw 'Unexpected fixture CIM class.' }; $script:processorRows }
foreach ($code in @(9,12)) {
    $script:processorRows=@([pscustomobject]@{Architecture=[uint16]$code},[pscustomobject]@{Architecture=[uint16]$code})
    Assert ((Get-WelaDefaultProcessorArchitecture) -eq $code) 'Native processor platform code distinguishes x64 and ARM64 independently of OS string/process emulation.'
}
foreach ($codes in @(@(),@(9,12),@($null),@(99),@('9'))) {
    $script:processorRows=@($codes | ForEach-Object { [pscustomobject]@{Architecture=$_} })
    $rejected=$false; try { Get-WelaDefaultProcessorArchitecture | Out-Null } catch { $rejected=$true }
    Assert $rejected 'Missing, conflicting, unsupported or malformed processor architecture cannot qualify exact context.'
}
$definition=(Get-WelaControlCatalog).controls[0]
foreach ($build in @(26100,26200,30000)) {
    $ctx=Copy-Object $context; $ctx.Build=$build
    foreach ($feature in @('Enabled','Disabled','Unknown')) {
        $row=Resolve-WelaControlApplicability $definition $ctx $feature
        Assert ($row.Status -eq 'NotApplicable' -and $null -eq $row.Remediation -and $row.Reason -match 'Removed') 'Removed Application Guard has no misleading remediation, even if stale feature metadata says Enabled.'
    }
}
foreach ($product in @(2,3)) {
    $ctx=Copy-Object $context; $ctx.ProductType=$product
    Assert ((Resolve-WelaControlApplicability $definition $ctx Enabled).Status -eq 'NotApplicable') 'Client historical source does not apply to a server/DC/CA.'
}
foreach ($state in @('Disabled','DisabledWithPayloadRemoved','NotPresent')) {
    Assert ((Resolve-WelaControlApplicability $definition $context $state).Status -eq 'NotApplicable') 'Absent/disabled feature is distinguished from an auditing mismatch.'
}
foreach ($state in @('Unknown','EnablePending','DisablePending')) {
    Assert ((Resolve-WelaControlApplicability $definition $context $state).Status -eq 'Unknown') 'Unknown/pending feature cannot claim applicability.'
}
Assert ((Resolve-WelaControlApplicability $definition $context Enabled).Status -eq 'Applicable') 'Reviewed historical enabled feature is applicable.'
$ctx=Copy-Object $context; $ctx.Build=25000
Assert ((Resolve-WelaControlApplicability $definition $ctx Enabled).Status -eq 'Unknown') 'Unreviewed insider build remains unknown.'
$ctx=Copy-Object $context; $ctx.Edition='Core'
Assert ((Resolve-WelaControlApplicability $definition $ctx Enabled).Status -eq 'Unknown') 'Unreviewed edition is never given remediation.'
$script:featureReads=0; $script:registryReads=0
function Get-WindowsOptionalFeature { param([switch]$Online,$FeatureName,$ErrorAction) $script:featureReads++; [pscustomobject]@{FeatureName=$FeatureName;State='Enabled'} }
function Get-WelaRegistryState { param($Path,$Name) $script:registryReads++; [pscustomobject]@{KeyExists=$true;ValueExists=$true;Type='DWord';Value=1} }
$ctx=Copy-Object $context; $ctx.Build=26100
$row=@(Get-WelaHistoricalControls $ctx)[0]
Assert ($row.Applicability.Status -eq 'NotApplicable' -and $script:featureReads -eq 0 -and $script:registryReads -eq 0) 'Removed feature is not queried or remediated.'
$row=@(Get-WelaHistoricalControls $context)[0]
Assert ($row.PolicyState -eq 'Policy matches' -and $row.EventGeneration -eq 'Unverified') 'Actual policy observation stays separate from event proof.'
function Get-WelaDefaultContext { $context }
function Get-WelaNativeChannel { param($Name) [pscustomobject]@{Name=$Name;State='Enabled';IsEnabled=$true;LogMode='Circular'} }
function Get-WelaAuditPolicyMask { param($Guid) 1 }
$snapshot=New-WelaDefaultSnapshot
Assert ($snapshot.EvidenceKind -eq 'ObservedState' -and $snapshot.Observations.Count -gt 59) 'Capture always labels current observations, including canonical audit categories.'
$reference=Copy-Object $snapshot
$compare=Get-WelaDefaultComparison $snapshot $reference
Assert (-not $compare.ReferenceReview.Accepted -and @($compare.Results | Where-Object DefaultSetting -ne 'Unknown').Count -eq 0) 'Observed current settings are never promoted to defaults.'
$reference.EvidenceKind='ReviewedCleanInstall'
$reference.Review=[pscustomobject]@{Reviewer='Fixture reviewer';ReviewedUtc=[DateTime]::UtcNow.ToString('o');ImageSha256=('a'*64);SnapshotId='test-only';PolicyEvidenceSha256=('b'*64);ProvisioningNotes='Synthetic validation fixture, not Windows lab evidence'}
$reference.Context.InstalledRoles=@('FeatureA','FeatureB')
$compare=Get-WelaDefaultComparison $snapshot $reference
Assert ($compare.ReferenceReview.Accepted -and @($compare.Results | Where-Object Comparison -ne 'Matches reference').Count -eq 0) 'Exact reviewed context can provide a scenario reference, with order-independent role inventory.'
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind') -or $PSVersionTable.PSVersion.Major -le 5) {
    Assert ($reference.CapturedUtc -is [string] -and $reference.Review.ReviewedUtc -is [string]) 'JSON import retains exact timestamp strings instead of silently localizing them.'
} else {
    Assert ($reference.CapturedUtc -is [DateTime] -and $reference.CapturedUtc.Kind -eq [DateTimeKind]::Utc) 'Earlier PowerShell 7 imports explicit Z timestamps as UTC, not Local or Unspecified.'
}
$candidate=Copy-Object $reference
$candidate.CapturedUtc=([DateTimeOffset]$candidate.CapturedUtc).UtcDateTime
$candidate.Review.ReviewedUtc=([DateTimeOffset]$candidate.Review.ReviewedUtc).UtcDateTime
Assert ((Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Earlier PowerShell 7 deserialized UTC DateTime values retain their explicit UTC semantics.'
foreach ($kind in @([DateTimeKind]::Local,[DateTimeKind]::Unspecified)) {
    foreach ($field in @('Capture','Review')) {
        $candidate=Copy-Object $reference
        if ($field -eq 'Capture') { $candidate.CapturedUtc=[DateTime]::SpecifyKind(([DateTimeOffset]$candidate.CapturedUtc).UtcDateTime,$kind) }
        else { $candidate.Review.ReviewedUtc=[DateTime]::SpecifyKind(([DateTimeOffset]$candidate.Review.ReviewedUtc).UtcDateTime,$kind) }
        Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Local or Unspecified DateTime cannot qualify UTC provenance even on a UTC-configured host.'
    }
}
$candidate=Copy-Object $reference; $candidate.Review.ReviewedUtc=[DateTime]::UtcNow.AddDays(1)
Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Deserialized UTC DateTime retains the nonfuture validation boundary.'
foreach ($time in @('2040-01-01T00:00:00Z','09/19/2026 01:00:00','2026-09-19T01:00:00','2026-09-19T01:00:00+00:00','2026-99-99T01:00:00Z',"2020-01-01T00:00:00Z`n")) {
    foreach ($field in @('Capture','Review')) {
        $candidate=Copy-Object $reference
        if ($field -eq 'Capture') {$candidate.CapturedUtc=$time} else {$candidate.Review.ReviewedUtc=$time}
        Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Future, malformed, localized or non-Z timestamps cannot qualify a clean-install reference.'
    }
}
$candidate=Copy-Object $reference; $candidate.CapturedUtc='2040-01-01T00:00:00Z'; $candidate.Review.ReviewedUtc='2040-01-01T00:00:01Z'
Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources ([DateTimeOffset]'2039-12-31T23:59:59Z')).Accepted) 'Chronologically ordered future capture and review still fail the assessment-time boundary.'
foreach ($helper in @('scripts/Configuration.ps1','modules/NativeProviders.psm1','modules/AuditProfiles.psm1')) {
    $candidate=Copy-Object $reference
    $source=@($candidate.Sources | Where-Object Path -eq $helper)
    Assert ($source.Count -eq 1) "Actual collector helper is fingerprinted: $helper"
    $source[0].Sha256=('d'*64)
    Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) "Changed native reader semantics invalidate reference provenance: $helper"
}
foreach ($field in @('Build','UBR','Edition','ProductType','DomainRole','DomainJoined','Domain','Architecture','ProcessorArchitecture','InstalledRoles','Status','RolesStatus')) {
    $candidate=Copy-Object $reference
    switch ($field) {
        'Build' {$candidate.Context.Build=26100}
        'UBR' {$candidate.Context.UBR=1235}
        'ProductType' {$candidate.Context.ProductType=3}
        'DomainRole' {$candidate.Context.DomainRole=3}
        'DomainJoined' {$candidate.Context.DomainJoined=$false}
        'ProcessorArchitecture' {$candidate.Context.ProcessorArchitecture=12}
        'InstalledRoles' {$candidate.Context.InstalledRoles=@('ADCS-Cert-Authority')}
        default {$candidate.Context.$field='Different'}
    }
    $compare=Get-WelaDefaultComparison $snapshot $candidate
    Assert (-not $compare.ReferenceReview.Accepted -and @($compare.Results | Where-Object DefaultSetting -ne 'Unknown').Count -eq 0) "Context mismatch $field cannot leak a default."
}
$candidate=Copy-Object $reference; $candidate.Context.PSObject.Properties.Remove('ProcessorArchitecture')
Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Legacy evidence without native processor architecture remains Unknown, even when localized OS architecture matches.'
foreach ($field in @('Reviewer','ReviewedUtc','ImageSha256','SnapshotId','PolicyEvidenceSha256','ProvisioningNotes')) {
    $candidate=Copy-Object $reference; $candidate.Review.$field=$null
    Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) "Missing $field fails review."
}
$candidate=Copy-Object $reference; $candidate.Sources[0].Sha256=('c'*64)
Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Changed source/catalog/collector bytes invalidate the reference.'
$candidate=Copy-Object $reference; $candidate.Observations+=@($candidate.Observations[0])
Assert (-not (Test-WelaReviewedDefaultEvidence $candidate $snapshot.Context $snapshot.Sources).Accepted) 'Duplicate IDs invalidate reference.'
$candidate=Copy-Object $reference; $candidate.Observations[0].Status='Unknown'
$compare=Get-WelaDefaultComparison $snapshot $candidate
Assert ($compare.ReferenceReview.Accepted -and $compare.Results[0].DefaultSetting -eq 'Unknown') 'Unknown individual control remains unknown in an otherwise reviewed artifact.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wela-default-reference-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $referencePath=Join-Path $temp 'reference.json'
    $reference | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $referencePath -Encoding UTF8
    $beforeHash=(Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash
    foreach ($output in @($referencePath,(Join-Path $temp './reference.json'))) {
        $rejected=$false
        try { Invoke-WelaDefaultEvidenceCommand -Action Compare -ReferencePath $referencePath -ResultsPath $output | Out-Null }
        catch { $rejected=$_.Exception.Message -match 'cannot overwrite its reference artifact' }
        Assert $rejected 'Equivalent input/output paths are rejected before exporting over reviewed evidence.'
        Assert ((Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash -ceq $beforeHash) 'Rejected reference/output collision preserves exact evidence bytes.'
    }
    $output=Join-Path $temp 'comparison.json'
    $report=Invoke-WelaDefaultEvidenceCommand -Action Compare -ReferencePath $referencePath -ResultsPath $output
    Assert ($report.Comparison.ReferenceReview.Accepted -and (Test-Path -LiteralPath $output) -and (Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash -ceq $beforeHash) 'Distinct comparison output imports strict timestamps and preserves its reviewed input.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
function Get-WelaNativeChannel { param($Name) throw 'channel read denied' }
$partial=New-WelaDefaultSnapshot
Assert (@($partial.Observations | Where-Object {$_.Kind -eq 'native-channel' -and $_.Status -eq 'Unknown'}).Count -gt 0 -and @($partial.Observations | Where-Object {$_.Kind -eq 'auditpol' -and $_.Status -eq 'Observed'}).Count -eq 59) 'One failed source does not discard independent successful observations.'
# The real renderer keeps source-less legacy strings explicitly separate in all assessment rows.
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'WELA.ps1'),[ref]$tokens,[ref]$errors)
Assert ($errors.Count -eq 0) 'Public script parses.'
$class=$ast.Find({param($node) $node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'WELA'},$true)
. ([scriptblock]::Create($class.Extent.Text))
$row=[WELA]::New('Test','Test','Enabled',@(),'Enabled','Enabled','','')
Assert ($row.DefaultSetting -eq 'Unknown' -and $row.LegacyDefaultHint -eq 'Enabled' -and $row.DefaultEvidence -match 'No exact-context') 'Legacy default hints cannot be shown as current host defaults.'
$exe=(Get-Process -Id $PID).Path
$ErrorActionPreference='Continue'
try { $out=& $exe -NoProfile -File (Join-Path $root 'WELA.ps1') configure -Profile wela-2.2.0 -DefaultEvidenceAction Capture 2>&1; $code=$LASTEXITCODE } finally { $ErrorActionPreference='Stop' }
Assert ($code -ne 0 -and ($out -join "`n") -match 'Default evidence options require') 'Wrong-command evidence options fail before profile configuration.'
Write-Host "PASS: $script:count applicability/default evidence assertions (synthetic fixtures, no default claims)."
$global:LASTEXITCODE=0
