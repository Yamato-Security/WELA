# Query only: no audit-policy writes or benign event generation.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/AuditProfiles.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/AuditCatalog.psm1') -Force
$legacy = Get-Content (Join-Path $PSScriptRoot '../config/baselines.json') -Raw | ConvertFrom-Json
$canonical = (Import-WelaAuditProfiles).catalog
Assert-WelaAuditCatalog $legacy.catalog $canonical
$listing = @(& auditpol.exe /list '/subcategory:*' /v 2>&1)
if ($LASTEXITCODE -ne 0) { throw "auditpol listing failed: $($listing -join ' ')" }
$text = $listing -join "`n"
$current = Get-WelaEffectiveAuditPolicy
foreach ($name in @('RPC Events','Token Right Adjusted Events')) {
    $row = $legacy.catalog | Where-Object subCategory -eq $name
    if ($text -notmatch [regex]::Escape($row.select.guid) -or -not $current.ContainsKey($row.select.guid)) { throw "Native Windows omitted $name / $($row.select.guid)." }
    # The hosted image uses English; on localized hosts only GUID presence is asserted.
    if ([Globalization.CultureInfo]::InstalledUICulture.TwoLetterISOLanguageName -eq 'en') {
        if (-not @($listing | Where-Object { $_ -match [regex]::Escape($row.select.guid) -and $_ -match [regex]::Escape($name) }).Count) { throw "Native name/GUID mismatch for $name." }
    }
    Write-Host "$name $($row.select.guid) observed mask=$($current[$row.select.guid])"
}
Write-Host 'PASS: native audit identifiers queried; no policy changes or event-generation claims.'
