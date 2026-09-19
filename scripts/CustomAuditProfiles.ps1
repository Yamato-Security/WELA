# Loaded inside AuditProfiles.psm1. Custom profiles are data, never scripts.
function Assert-WelaCustomObject {
    param($Object,[string[]]$Allowed,[string[]]$Required=@())
    if ($Object -isnot [pscustomobject]) { throw 'Expected a custom-profile JSON object.' }
    $keys=@($Object.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($key in $keys) { if ($key -cnotin $Allowed) { throw "Unknown custom-profile property: $key" } }
    foreach ($key in $Required) { if ($key -cnotin $keys) { throw "Missing custom-profile property: $key" } }
}
function Assert-WelaCustomText {
    param($Value,[string]$Field)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 2048) { throw "Invalid custom-profile text: $Field" }
}
function Assert-WelaCustomStringArray {
    param($Values,[string[]]$Allowed,[switch]$AllowEmpty)
    if ($Values -isnot [array] -or (-not $AllowEmpty -and $Values.Count -eq 0)) { throw 'Expected a nonempty custom-profile array.' }
    $seen=@{}
    foreach ($value in $Values) {
        if ($value -isnot [string] -or $value -cnotin $Allowed -or $seen.ContainsKey($value)) { throw "Unknown or duplicate custom-profile array value: $value" }
        $seen[$value]=$true
    }
}
function ConvertFrom-WelaCustomProfileJson {
    param([string]$Text)
    # Match JSON strings first; braces/property-looking text inside strings is inert.
    $withoutStrings=[regex]::Replace($Text,'"(?:\\.|[^"\\])*"','""')
    if ($withoutStrings -match '//|/\*|,\s*[}\]]') { throw 'Custom profiles require strict JSON without comments or trailing commas.' }
    $tokens=[regex]::Matches($Text,'"(?:\\.|[^"\\])*"|[{}\[\]:,]')
    $stack=New-Object 'System.Collections.Generic.Stack[object]'
    for ($i=0;$i -lt $tokens.Count;$i++) {
        $token=$tokens[$i].Value
        if ($token -eq '{') { $stack.Push(@{}) }
        elseif ($token -eq '[') { $stack.Push($null) }
        elseif ($token -in @('}',']')) { if (-not $stack.Count) { throw 'Unbalanced custom-profile JSON.' }; $null=$stack.Pop() }
        elseif ($token.StartsWith('"') -and $i+1 -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
            if (-not $stack.Count -or $null -eq $stack.Peek()) { throw 'JSON property outside object.' }
            $holder=ConvertFrom-Json -InputObject ('{'+$token+':null}') -ErrorAction Stop
            $name=@($holder.PSObject.Properties.Name)[0]
            if ($stack.Peek().ContainsKey($name)) { throw "Duplicate or case-colliding custom-profile property: $name" }
            $stack.Peek()[$name]=$true
        }
        if ($stack.Count -gt 20) { throw 'Custom-profile nesting exceeds 20 levels.' }
    }
    ConvertFrom-Json -InputObject $Text -ErrorAction Stop
}
function Get-WelaCustomFileHash {
    param([byte[]]$Bytes)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $algorithm.Dispose() }
}
function Import-WelaCustomAuditProfiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $ErrorActionPreference='Stop'
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file -isnot [IO.FileInfo] -or $file.Length -lt 1 -or $file.Length -gt 1048576) { throw 'Custom profile must be a nonempty JSON file no larger than 1 MiB.' }
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -gt 1048576) { throw 'Custom profile grew beyond 1 MiB.' }
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $data=ConvertFrom-WelaCustomProfileJson ($utf8.GetString($bytes).TrimStart([char]0xFEFF))
    Assert-WelaCustomObject $data @('schemaVersion','kind','catalog','sources','profiles') @('schemaVersion','kind','catalog','sources','profiles')
    if (($data.schemaVersion -isnot [int] -and $data.schemaVersion -isnot [long]) -or $data.schemaVersion -ne 1 -or $data.kind -cne 'WelaCustomAuditProfiles') { throw 'Unsupported custom-profile kind/schema version.' }
    $canonicalPath=Join-Path $PSScriptRoot '../config/audit_profiles.json'
    $canonicalHash=(Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $builtin=Import-WelaAuditProfiles
    if ((Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $canonicalHash) { throw 'Canonical profile catalog changed during validation.' }
    $canonical=@{}; foreach ($entry in $builtin.catalog) { $canonical[$entry.id]=$entry }
    if ($data.catalog -isnot [array] -or $data.catalog.Count -lt 1 -or $data.catalog.Count -gt 59) { throw 'Declare 1..59 canonical custom catalog references.' }
    $declared=@{}; $guids=@{}
    foreach ($entry in $data.catalog) {
        Assert-WelaCustomObject $entry @('id','guid','category') @('id','guid','category')
        Assert-WelaCustomText $entry.id 'catalog id'
        if (-not $canonical.ContainsKey($entry.id) -or $canonical[$entry.id].id -cne $entry.id -or $entry.guid -isnot [string] -or
            $entry.guid -ine $canonical[$entry.id].guid -or $entry.category -cne $canonical[$entry.id].category) { throw "Canonical name/GUID/category mismatch: $($entry.id)" }
        if ($declared.ContainsKey($entry.id) -or $guids.ContainsKey($entry.guid)) { throw 'Duplicate custom catalog name/GUID.' }
        $declared[$entry.id]=$true; $guids[$entry.guid]=$true
    }
    if ($data.sources -isnot [pscustomobject] -or @($data.sources.PSObject.Properties).Count -eq 0) { throw 'Custom sources are required.' }
    $sourceIds=@($data.sources.PSObject.Properties.Name)
    foreach ($source in $data.sources.PSObject.Properties) {
        if ($source.Name -cnotmatch '\A[a-z][a-z0-9-]{0,63}\z') { throw 'Invalid custom source id.' }
        Assert-WelaCustomObject $source.Value @('title','version','url') @('title','version','url')
        foreach ($field in @('title','version','url')) { Assert-WelaCustomText $source.Value.$field $field }
        $uri=$null
        if (-not [Uri]::TryCreate($source.Value.url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https') { throw 'Source URL must be an absolute HTTPS reference; it is not fetched.' }
    }
    if ($data.profiles -isnot [array] -or $data.profiles.Count -lt 1 -or $data.profiles.Count -gt 128) { throw 'Custom file requires 1..128 profiles.' }
    $ids=@{}; $roles=@('Client','MemberServer','DomainController','ADCS')
    foreach ($profile in $data.profiles) {
        Assert-WelaCustomObject $profile @('id','version','sourceIds','omitted','scope','appliesTo','controls','roleOverrides','note','referenceOnly') @('id','version','sourceIds','omitted','scope','appliesTo','controls','roleOverrides')
        Assert-WelaCustomText $profile.id 'profile id'; Assert-WelaCustomText $profile.version 'profile version'
        if ($profile.id -cnotmatch '\A[a-z][a-z0-9-]{0,127}\z' -or $ids.ContainsKey($profile.id) -or $profile.id -in @($builtin.profiles.id)) { throw 'Duplicate, invalid or built-in custom profile id.' }
        $ids[$profile.id]=$true
        if ($profile.scope -cne 'advanced-audit-policy-only' -or $profile.omitted -cne 'unchanged') { throw 'Custom scope must be advanced-audit-policy-only with omitted unchanged.' }
        if ($profile.PSObject.Properties['referenceOnly'] -and $profile.referenceOnly -isnot [bool]) { throw 'referenceOnly must be boolean.' }
        if ($profile.PSObject.Properties['note'] -and $profile.note -isnot [string]) { throw 'Profile note must be text.' }
        Assert-WelaCustomStringArray $profile.sourceIds $sourceIds
        if ($profile.appliesTo -isnot [array] -or -not $profile.appliesTo.Count) { throw 'Custom profile applicability array is required.' }
        foreach ($range in $profile.appliesTo) {
            Assert-WelaCustomObject $range @('roles','minBuild','maxBuild') @('roles','minBuild','maxBuild')
            Assert-WelaCustomStringArray $range.roles $roles
            foreach ($field in @('minBuild','maxBuild')) { if (($range.$field -isnot [int] -and $range.$field -isnot [long]) -or $range.$field -lt 1 -or $range.$field -gt 999999) { throw 'Custom build bounds must be integers in 1..999999.' } }
            if ($range.maxBuild -lt $range.minBuild) { throw 'Reversed custom build range.' }
        }
        Assert-WelaCustomObject $profile.roleOverrides $roles
        $sets=@($profile.controls)+@($profile.roleOverrides.PSObject.Properties | ForEach-Object { $_.Value })
        foreach ($set in $sets) {
            Assert-WelaCustomObject $set @($declared.Keys)
            foreach ($control in $set.PSObject.Properties) {
                $value=$control.Value
                Assert-WelaCustomObject $value @('mode','mask','note','evidence','sourceIds') @('mode')
                if ($value.mode -cnotin @('exact','minimum','optional','unchanged','not-configured','not-applicable')) { throw 'Invalid custom policy mode.' }
                $hasMask=$null -ne $value.PSObject.Properties['mask']
                if ($value.mode -in @('exact','minimum','optional')) {
                    if (-not $hasMask -or ($value.mask -isnot [int] -and $value.mask -isnot [long]) -or $value.mask -notin @(0,1,2,3)) { throw 'Custom audit mask must be an integer 0..3.' }
                } elseif ($hasMask) { throw 'Preserve/non-applicable modes must not specify a mask.' }
                if ($value.PSObject.Properties['sourceIds']) { Assert-WelaCustomStringArray $value.sourceIds $sourceIds }
                foreach ($field in @('note','evidence')) { if ($value.PSObject.Properties[$field] -and $value.$field -isnot [string]) { throw 'Control note/evidence must be text.' } }
            }
        }
    }
    # Roles and prerequisites come only from the authoritative bundled catalog.
    $data.catalog=$builtin.catalog
    $source=[pscustomobject]@{Path=$file.FullName;Sha256=(Get-WelaCustomFileHash $bytes);CanonicalPath=[IO.Path]::GetFullPath($canonicalPath);CanonicalSha256=$canonicalHash;Kind='OperatorCustomFile';Provenance='Operator-declared policy; not a Microsoft/CIS/ASD endorsement.'}
    $data | Add-Member NoteProperty customSource $source
    Assert-WelaCustomProfileSource $source
    return $data
}
function Assert-WelaCustomProfileSource {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Source)
    foreach ($entry in @(@($Source.Path,$Source.Sha256),@($Source.CanonicalPath,$Source.CanonicalSha256))) {
        if ((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $entry[1]) { throw 'Custom profile or canonical catalog changed since validation; no further configuration is authorized by this plan.' }
    }
}
