# Identifier validation is separate from recommendations and detection readiness.
Set-StrictMode -Version 2.0

function ConvertTo-WelaCanonicalAuditName {
    param([string]$Name)
    # Only reviewed spelling aliases; do not accept arbitrary fuzzy matches.
    switch -CaseSensitive ($Name) {
        'Non-Sensitive Privilege Use' { return 'Non Sensitive Privilege Use' }
        'User / Device Claims' { return 'User/Device Claims' }
        'Central Policy Staging' { return 'Central Access Policy Staging' }
        default { return $Name }
    }
}

function Assert-WelaAuditCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)]$CanonicalCatalog)
    $canonical = @{}; $canonicalGuids = @{}; $seen = @{}; $ids = @{}
    foreach ($row in $CanonicalCatalog) {
        if (-not $row.id -or $canonical.ContainsKey($row.id) -or
            $row.guid -notmatch '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$' -or $canonicalGuids.ContainsKey($row.guid)) {
            throw 'Invalid or duplicate canonical audit identifier.'
        }
        $canonical[$row.id] = $row.guid; $canonicalGuids[$row.guid] = $true
    }
    foreach ($row in @($Catalog | Where-Object { $_.currentSetting.type -eq 'auditpol' })) {
        $name = ConvertTo-WelaCanonicalAuditName $row.subCategory
        if (-not $row.id -or $ids.ContainsKey($row.id)) { throw "Duplicate or empty legacy audit id: $($row.id)" }
        if ($row.select.type -ne 'guid' -or -not $canonical.ContainsKey($name) -or $canonical[$name] -ine $row.select.guid) {
            throw "Audit catalog name/GUID mismatch: $($row.subCategory) / $($row.select.guid)"
        }
        if ($seen.ContainsKey($row.select.guid)) { throw "Duplicate legacy audit GUID: $($row.select.guid)" }
        $seen[$row.select.guid] = $true; $ids[$row.id] = $true
    }
}

function Get-WelaEventMappingReview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Mappings,
        [Parameter(Mandatory)]$CanonicalCatalog,
        [Parameter(Mandatory)][ValidateRange(0,65535)][int]$EventId
    )
    $byGuid = @{}
    foreach ($row in $CanonicalCatalog) { $byGuid[$row.guid] = $row.id }
    # Empty category-heading rows must never become EventID 0 through a cast.
    $matches = @($Mappings | Where-Object { $_.'Event ID' -match '^\d+$' -and [int]$_.'Event ID' -eq $EventId })
    $candidates = @(); $uncertain = @()
    foreach ($row in $matches) {
        if (-not $row.Subcategory -or -not $byGuid.ContainsKey($row.GUID)) {
            $uncertain += 'CategoryOnlyOrUnknownGuid'; continue
        }
        if ((ConvertTo-WelaCanonicalAuditName $row.Subcategory) -cne $byGuid[$row.GUID]) {
            $uncertain += 'NameGuidMismatch'; continue
        }
        $candidates += [pscustomobject]@{ Name=$byGuid[$row.GUID]; Guid=$row.GUID }
    }
    $candidates = @($candidates | Sort-Object Guid -Unique)
    $reasons = @($uncertain | Select-Object -Unique)
    if (-not $matches.Count) { $reasons += 'NoMapping' }
    if ($candidates.Count -gt 1) { $reasons += 'MultipleSubcategories' }
    # Even an unambiguous mapping does not prove outcome, object, fields or source role.
    $reasons += 'OutcomeObjectAndRoleUnverified'
    [pscustomobject]@{
        EventId=$EventId
        State=$(if (-not $matches.Count -or -not $candidates.Count) { 'Unknown' } else { 'Conditional' })
        MappingCount=$matches.Count; Candidates=$candidates; Reasons=$reasons
        DetectionReady=$false
    }
}

Export-ModuleMember -Function Assert-WelaAuditCatalog, Get-WelaEventMappingReview
