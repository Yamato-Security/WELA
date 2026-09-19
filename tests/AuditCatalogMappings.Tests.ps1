$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/AuditCatalog.psm1') -Force
$script:count = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Reject([scriptblock]$Action) {
    try { & $Action; throw 'Expected rejection did not occur.' }
    catch { Assert ($_.Exception.Message -match 'mismatch|Duplicate|duplicate') "Unexpected failure: $_" }
}
$root = Split-Path $PSScriptRoot -Parent
$canonical = (Import-WelaAuditProfiles).catalog
$legacyPath = Join-Path $root 'config/baselines.json'
$legacy = Get-Content $legacyPath -Raw | ConvertFrom-Json
Assert-WelaAuditCatalog $legacy.catalog $canonical
foreach ($case in @('wrong-guid','duplicate-guid','unknown-name','duplicate-id')) {
    $copy = Get-Content $legacyPath -Raw | ConvertFrom-Json
    $row = $copy.catalog | Where-Object subCategory -eq 'Token Right Adjusted Events'
    switch ($case) {
        'wrong-guid' { $row.select.guid='0CCE922E-69AE-11D9-BED3-505054503030' }
        'duplicate-guid' { $copy.catalog += $row }
        'unknown-name' { $row.subCategory='Token Right Adjusted Typo' }
        'duplicate-id' { ($copy.catalog | Where-Object subCategory -eq 'RPC Events').id=$row.id }
    }
    Reject { Assert-WelaAuditCatalog $copy.catalog $canonical }
}
$mappings = @(Import-Csv (Join-Path $root 'config/eid_subcategory_mapping.csv'))
$ambiguous = Get-WelaEventMappingReview $mappings $canonical 4703
Assert ($ambiguous.State -eq 'Conditional' -and $ambiguous.Candidates.Count -eq 2 -and $ambiguous.Reasons -contains 'MultipleSubcategories' -and -not $ambiguous.DetectionReady) '4703 conflicting source mappings must remain conditional.'
$object = Get-WelaEventMappingReview $mappings $canonical 4663
Assert ($object.State -eq 'Conditional' -and -not $object.DetectionReady) 'Object EventID alone never establishes matching object/SACL/outcome.'
$unknown = Get-WelaEventMappingReview $mappings $canonical 65535
Assert ($unknown.State -eq 'Unknown' -and $unknown.Candidates.Count -eq 0) 'Unknown events cannot acquire a policy or readiness.'
$zero = Get-WelaEventMappingReview $mappings $canonical 0
Assert ($zero.MappingCount -eq 0 -and $zero.State -eq 'Unknown') 'Blank category rows must not turn into EventID zero.'
$category = Get-WelaEventMappingReview $mappings $canonical 4608
Assert ($category.Reasons -contains 'CategoryOnlyOrUnknownGuid' -and -not $category.DetectionReady) 'Category GUIDs cannot establish advanced subcategory readiness.'
$rpc = Get-WelaEventMappingReview $mappings $canonical 5712
Assert ($rpc.Candidates.Count -eq 1 -and $rpc.Candidates[0].Name -eq 'RPC Events' -and $rpc.State -eq 'Conditional') 'A unique mapping still retains outcome/context uncertainty.'
$bad = [pscustomobject]@{'Event ID'='5712';Subcategory='Token Right Adjusted Events';GUID='0CCE922E-69AE-11D9-BED3-505054503030'}
$mismatch = Get-WelaEventMappingReview @($bad) $canonical 5712
Assert ($mismatch.State -eq 'Unknown' -and $mismatch.Reasons -contains 'NameGuidMismatch') 'Mismatched candidate metadata must not be accepted.'

# Exercise the actual legacy renderer for every named baseline with distinct RPC/token state.
. (Join-Path $root 'WELA.ps1') help -Role Client -Build 26100 6>$null | Out-Null
function GetAuditpol { @{ '0CCE922E-69AE-11D9-BED3-505054503030'='Failure'; '0CCE924A-69AE-11D9-BED3-505054503030'='Success' } }
function CheckRegistryValue { $false }
function Get-WelaNativeSources { @() }
function Get-WelaNativeSourceState { 'Unknown' }
function Get-WelaOutgoingNtlmState { [pscustomobject]@{Description='Unknown';PolicySource='Unknown'} }
function Get-WelaDomainNtlmState { [pscustomobject]@{Description='Unknown'} }
foreach ($baselineName in $legacy.baselines.PSObject.Properties.Name) {
    $rows = BuildAuditResult -all_rules @() -Baseline $baselineName -enabledguid @('0CCE924A-69AE-11D9-BED3-505054503030')
    Assert (($rows | Where-Object SubCategory -eq 'RPC Events').CurrentSetting -eq 'Failure') "$baselineName must read RPC independently."
    Assert (($rows | Where-Object SubCategory -eq 'Token Right Adjusted Events').CurrentSetting -eq 'Success') "$baselineName must read Token independently."
}
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('wela-mapping-review-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    & (Join-Path $root 'scripts/Review-AuditCatalog.ps1') -ResultsPath $tmp | Out-Null
    $export = Get-Content $tmp -Raw | ConvertFrom-Json
    Assert ($export.DetectionReadyCount -eq 0 -and $export.MappingSha256.Length -eq 64 -and $export.Events.Count -gt 100) 'Review export retains corpus fingerprint and explicit no-readiness semantics.'
} finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
Write-Host "PASS: $script:count catalog/mapping assertions; all legacy baselines preserve distinct RPC/token state."
