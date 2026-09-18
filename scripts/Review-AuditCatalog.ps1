# Developer-facing, read-only catalog review. No Windows query or policy changes.
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/AuditCatalog.psm1') -Force
$root = Split-Path $PSScriptRoot -Parent
$canonical = (Import-WelaAuditProfiles).catalog
$legacy = Get-Content (Join-Path $root 'config/baselines.json') -Raw | ConvertFrom-Json
Assert-WelaAuditCatalog -Catalog $legacy.catalog -CanonicalCatalog $canonical
$mappingPath = Join-Path $root 'config/eid_subcategory_mapping.csv'
$mappings = @(Import-Csv -LiteralPath $mappingPath)
$rows = @($mappings | Where-Object { $_.'Event ID' -match '^\d+$' } | ForEach-Object { [int]$_.'Event ID' } | Sort-Object -Unique | ForEach-Object {
    Get-WelaEventMappingReview -Mappings $mappings -CanonicalCatalog $canonical -EventId $_
})
$result = [pscustomobject]@{
    SchemaVersion=1; Scope='catalog-identifiers-and-mapping-uncertainty'; GeneratedUtc=[DateTime]::UtcNow.ToString('o')
    CanonicalCount=$canonical.Count; LegacyCount=@($legacy.catalog | Where-Object { $_.currentSetting.type -eq 'auditpol' }).Count
    MappingSha256=(Get-FileHash -LiteralPath $mappingPath -Algorithm SHA256).Hash
    CategoryHeadingRows=@($mappings | Where-Object { -not $_.'Event ID' }).Count
    Provenance='Bundled mapping candidates, not a build-specific event-generation contract. See docs/audit-catalog-mappings.md.'
    Events=$rows; DetectionReadyCount=0
}
if ($ResultsPath) { $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
$result
