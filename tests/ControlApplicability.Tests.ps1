$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/ControlApplicability.ps1')
Import-Module (Join-Path $root 'modules/AuditProfiles.psm1')
$script:count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Copy-Object($Value) { $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
$context=[pscustomobject]@{Status='Observed';Build=22631;UBR=1234;Edition='Enterprise';ProductType=1;DomainRole=1;DomainJoined=$true;Domain='lab.test';Architecture='64-bit';InstalledRoles=@('FeatureB','FeatureA');RolesStatus='Observed';Diagnostic='fixture'}
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
$reference.Review=[pscustomobject]@{Reviewer='Fixture reviewer';ReviewedUtc=[DateTime]::UtcNow.AddMinutes(1).ToString('o');ImageSha256=('a'*64);SnapshotId='test-only';PolicyEvidenceSha256=('b'*64);ProvisioningNotes='Synthetic validation fixture, not Windows lab evidence'}
$reference.Context.InstalledRoles=@('FeatureA','FeatureB')
$compare=Get-WelaDefaultComparison $snapshot $reference
Assert ($compare.ReferenceReview.Accepted -and @($compare.Results | Where-Object Comparison -ne 'Matches reference').Count -eq 0) 'Exact reviewed context can provide a scenario reference, with order-independent role inventory.'
foreach ($field in @('Build','UBR','Edition','ProductType','DomainRole','DomainJoined','Domain','Architecture','InstalledRoles','Status','RolesStatus')) {
    $candidate=Copy-Object $reference
    switch ($field) {
        'Build' {$candidate.Context.Build=26100}
        'UBR' {$candidate.Context.UBR=1235}
        'ProductType' {$candidate.Context.ProductType=3}
        'DomainRole' {$candidate.Context.DomainRole=3}
        'DomainJoined' {$candidate.Context.DomainJoined=$false}
        'InstalledRoles' {$candidate.Context.InstalledRoles=@('ADCS-Cert-Authority')}
        default {$candidate.Context.$field='Different'}
    }
    $compare=Get-WelaDefaultComparison $snapshot $candidate
    Assert (-not $compare.ReferenceReview.Accepted -and @($compare.Results | Where-Object DefaultSetting -ne 'Unknown').Count -eq 0) "Context mismatch $field cannot leak a default."
}
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
