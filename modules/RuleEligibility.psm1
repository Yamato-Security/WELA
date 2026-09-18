# Read-only, offline evidence assessment. Imported artifacts are never executed.
function Get-WelaEligibilityTextHash {
    param([string]$Text)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function ConvertFrom-WelaEligibilityJson {
    param([string]$Text)
    # Reject property collisions instead of depending on ConvertFrom-Json's
    # different duplicate-key behavior across Windows PowerShell and PowerShell.
    $tokens = [regex]::Matches($Text, '"(?:\\.|[^"\\])*"|[{}\[\]:,]')
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i].Value
        if ($token -eq '{') { $stack.Push(@{}) }
        elseif ($token -eq '[') { $stack.Push($null) }
        elseif ($token -in @('}', ']')) { if ($stack.Count -eq 0) { throw 'Unbalanced JSON.' }; $null = $stack.Pop() }
        elseif ($token.StartsWith('"') -and $i + 1 -lt $tokens.Count -and $tokens[$i + 1].Value -eq ':') {
            if ($stack.Count -eq 0 -or $null -eq $stack.Peek()) { throw 'JSON property outside an object.' }
            $holder = ('{' + $token + ':null}' | ConvertFrom-Json -ErrorAction Stop)
            $name = @($holder.PSObject.Properties.Name)[0]
            if ($stack.Peek().ContainsKey($name)) { throw 'Duplicate or case-colliding JSON property.' }
            $stack.Peek()[$name] = $true
        }
        if ($stack.Count -gt 32) { throw 'JSON nesting exceeds 32 levels.' }
    }
    $arguments = @{InputObject=$Text;ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $arguments.DateKind = 'String' }
    return (ConvertFrom-Json @arguments)
}

function Read-WelaEligibilityJson {
    param([string]$Path, [long]$MaximumBytes = 16777216)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt $MaximumBytes) { throw 'JSON input is a directory or exceeds the supported size limit.' }
    $text = [IO.File]::ReadAllText($file.FullName)
    return ($text | ConvertFrom-Json -ErrorAction Stop)
}

function Read-WelaEligibilityInput {
    param([string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 16777216) { throw 'Input is a directory or exceeds 16 MiB.' }
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -gt 16777216) { throw 'Input grew beyond 16 MiB.' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $sha256 = ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    [pscustomobject]@{ Sha256=$sha256; Text=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) }
}

function Get-WelaEligibilityRuleHash {
    param($Rule)
    $ordered = [ordered]@{}
    foreach ($name in @('id', 'title', 'level', 'category', 'service', 'channel', 'event_ids', 'subcategory_guids', 'description', 'tags')) {
        $ordered[$name] = $Rule.$name
    }
    Get-WelaEligibilityTextHash (ConvertTo-Json -InputObject $ordered -Depth 12 -Compress)
}

function Get-WelaEligibilityArtifact {
    param([string]$Root, $Reference)
    if ($Reference.path -isnot [string] -or $Reference.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        $Reference.path -match '^(?:[/\\]|[A-Za-z]:)' -or $Reference.path -match '[:*?\x00-\x1F]') { throw 'Invalid artifact path or SHA256.' }
    $segments = @($Reference.path -split '[/\\]')
    if (@($segments | Where-Object { -not $_ -or $_ -in @('.', '..') -or $_ -match '[ .]$' }).Count) { throw 'Artifact path has ambiguous components.' }
    $rootPath = [IO.Path]::GetFullPath($Root)
    if ($rootPath.StartsWith('\\')) { throw 'Remote evidence roots are not accessed.' }
    # Inspect ancestors before descendants; never follow a link into another tree.
    $cursor = [IO.Path]::GetPathRoot($rootPath)
    $rootSegments = @($rootPath.Substring($cursor.Length) -split '[/\\]' | Where-Object { $_ })
    foreach ($part in @($rootSegments) + @($segments)) {
        $cursor = Join-Path $cursor $part
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked artifact paths require separate review.' }
    }
    if ($item.PSIsContainer -or $item.Length -eq 0 -or $item.Length -gt 4194304) { throw 'Artifact must be a nonempty file of at most 4 MiB.' }
    # Read once and hash the same bytes that are parsed (no hash/read race).
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    if ($bytes.Length -gt 4194304) { throw 'Artifact grew beyond its size limit.' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    if ($actual -ne $Reference.sha256) { throw "Artifact hash mismatch: $($Reference.path)" }
    [pscustomobject]@{ Path = $Reference.path; Sha256 = $actual; Text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) }
}

function ConvertFrom-WelaEligibilityEvent {
    param([string]$Text)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null; $settings.MaxCharactersInDocument = 4194304
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($Text), $settings)
    try { $xml = New-Object Xml.XmlDocument; $xml.XmlResolver = $null; $xml.Load($reader) }
    finally { $reader.Dispose() }
    if ($xml.DocumentElement.LocalName -ne 'Event' -or $xml.DocumentElement.NamespaceURI -ne 'http://schemas.microsoft.com/win/2004/08/events/event') { throw 'Expected one native Windows Event XML document.' }
    $ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e', $xml.DocumentElement.NamespaceURI)
    if (@($xml.SelectNodes('/e:Event/e:System', $ns)).Count -ne 1 -or @($xml.SelectNodes('/e:Event/e:EventData', $ns)).Count -ne 1 -or $xml.SelectSingleNode('/e:Event/e:UserData', $ns)) { throw 'Unsupported or ambiguous event payload.' }
    $system = @{}
    foreach ($name in @('EventID', 'Version', 'EventRecordID', 'Channel', 'Computer', 'Keywords')) {
        $nodes = @($xml.SelectNodes('/e:Event/e:System/e:' + $name, $ns))
        if ($nodes.Count -ne 1 -or -not $nodes[0].InnerText) { throw "Missing/duplicate event system field: $name" }
        $system[$name] = $nodes[0].InnerText
    }
    $provider = @($xml.SelectNodes('/e:Event/e:System/e:Provider', $ns))
    $time = @($xml.SelectNodes('/e:Event/e:System/e:TimeCreated', $ns))
    if ($provider.Count -ne 1 -or $time.Count -ne 1) { throw 'Missing/duplicate event provider or timestamp.' }
    $system.Provider = $provider[0].GetAttribute('Name'); $system.TimeCreated = $time[0].GetAttribute('SystemTime')
    $data = @{}
    foreach ($node in $xml.SelectNodes('/e:Event/e:EventData/e:Data', $ns)) {
        $name = $node.GetAttribute('Name')
        if (-not $name -or $data.ContainsKey($name)) { throw 'Unnamed or duplicate EventData field.' }
        $data[$name] = $node.InnerText
    }
    [pscustomobject]@{ System = $system; Data = $data }
}

function ConvertTo-WelaEligibilityTime {
    param($Value)
    if ($Value -isnot [string] -or $Value -notmatch 'Z$') { throw 'Evidence timestamps must be explicit UTC strings ending in Z.' }
    return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Test-WelaEligibilityEvidence {
    param($Record, $Rule, [string]$MetadataHash, [string]$Root, [string]$CorpusHash, [string]$MappingHash,
          $Policy, [string]$Role, [int]$Build, [DateTime]$Now = [DateTime]::UtcNow)
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $artifactNames = @('sourceRule', 'normalizedRule', 'review', 'beforeState', 'afterState', 'eventXml', 'ingestion', 'query', 'queryResult')
    try {
        if ($Record.metadataSha256 -ne $MetadataHash -or $Record.corpusSha256 -ne $CorpusHash -or $Record.mappingSha256 -ne $MappingHash) { throw 'Corpus, mapping or per-rule metadata identity mismatch.' }
        if ($Record.adapter -ne 'security-single-event-exact-v1') { return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedEvidenceAdapter'); References = @() } }
        $a = @{}
        foreach ($name in $artifactNames) { $a[$name] = Get-WelaEligibilityArtifact $Root $Record.artifacts.$name }
        $definition = ConvertFrom-WelaEligibilityJson $a.normalizedRule.Text
        $review = ConvertFrom-WelaEligibilityJson $a.review.Text
        if ($definition.id -ne $Rule.id -or $review.ruleId -ne $Rule.id -or $review.sourceRuleSha256 -ne $a.sourceRule.Sha256 -or
            $review.normalizedRuleSha256 -ne $a.normalizedRule.Sha256 -or -not $review.reviewer -or
            $review.statement -cne 'Complete rule normalization reviewed; no detection logic omitted.') { throw 'Missing complete normalization review bound to both rule artifacts.' }
        $reviewed = ConvertTo-WelaEligibilityTime $review.reviewedAtUtc
        # This is a deliberately small full-rule parser, never a partial Sigma compiler.
        $detectionNames = @($definition.detection.PSObject.Properties.Name)
        if ($definition.correlation -or $definition.logsource.product -ne 'windows' -or
            $definition.detection.condition -cne 'selection' -or $detectionNames.Count -ne 2 -or
            $detectionNames -notcontains 'selection' -or $definition.detection.selection -isnot [pscustomobject]) {
            return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedRuleLogic'); References = @($artifactNames) }
        }
        if (($definition.logsource.service -and $definition.logsource.service -ne 'security') -or
            ($definition.logsource.category -and $definition.logsource.category -ne 'process_creation') -or
            ($definition.logsource.category -eq 'process_creation' -and @($Rule.event_ids) -notcontains '4688') -or
            $definition.logsource.definition -or $definition.status -in @('deprecated', 'unsupported')) {
            return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedRuleSourceOrPrerequisite'); References = @($artifactNames) }
        }
        $selectors = @($definition.detection.selection.PSObject.Properties)
        if ($selectors.Count -eq 0) { throw 'Empty selection cannot demonstrate a rule match.' }
        foreach ($selector in $selectors) {
            if ($selector.Name -match '\|' -or $null -eq $selector.Value -or
                $selector.Value -is [array] -or $selector.Value -is [pscustomobject] -or
                $selector.Value -is [bool] -or [string]$selector.Value -match '[*?]') {
                return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedRuleLogic'); References = @($artifactNames) }
            }
        }
        if (-not $Policy -or ($Policy.prerequisites -and $Policy.id -ne 'Process Creation')) { return [pscustomobject]@{ State = 'Conditional'; Reasons = @('SaclOrProviderPrerequisiteAdapterRequired'); References = @($artifactNames) } }
        $before = ConvertFrom-WelaEligibilityJson $a.beforeState.Text
        $after = ConvertFrom-WelaEligibilityJson $a.afterState.Text
        $ingestion = ConvertFrom-WelaEligibilityJson $a.ingestion.Text
        $queryResult = ConvertFrom-WelaEligibilityJson $a.queryResult.Text
        $event = ConvertFrom-WelaEligibilityEvent $a.eventXml.Text
        $context = $after.context
        if ($context.role -notin @('Client', 'MemberServer', 'DomainController', 'ADCS') -or
            $context.build -isnot [ValueType] -or $context.build -is [bool] -or $context.build -lt 1 -or [double]$context.build -ne [math]::Floor([double]$context.build) -or
            $context.computer -isnot [string] -or -not $context.computer.Trim() -or
            $context.patch -isnot [string] -or -not $context.patch.Trim() -or $context.domainJoined -isnot [bool] -or
            $context.installedRoles -isnot [array] -or $context.backend -isnot [string] -or -not $context.backend.Trim() -or
            $context.backendVersion -isnot [string] -or -not $context.backendVersion.Trim()) { throw 'Incomplete source host/build/patch/backend context.' }
        foreach ($name in @('computer', 'role', 'build', 'patch', 'domainJoined', 'backend', 'backendVersion')) {
            if ([string]$before.context.$name -cne [string]$context.$name) { throw "Before/after context mismatch: $name" }
        }
        if ((@($before.context.installedRoles) -join '|') -cne (@($context.installedRoles) -join '|')) { throw 'Installed roles changed during the evidence window.' }
        if (($Role -and $Role -ne $context.role) -or ($Build -and $Build -ne $context.build)) { throw 'Evidence does not match the requested role/build.' }
        if ($Policy.roles -notcontains $context.role) { throw 'The event source belongs to a different Windows role.' }
        $beforeTime = ConvertTo-WelaEligibilityTime $before.capturedAtUtc
        $eventTime = ConvertTo-WelaEligibilityTime $event.System.TimeCreated
        $afterTime = ConvertTo-WelaEligibilityTime $after.capturedAtUtc
        $arrivalTime = ConvertTo-WelaEligibilityTime $ingestion.receivedAtUtc
        $queryTime = ConvertTo-WelaEligibilityTime $queryResult.executedAtUtc
        if ($beforeTime -gt $eventTime -or $eventTime -gt $afterTime -or $eventTime -gt $arrivalTime -or
            $arrivalTime -gt $queryTime -or $queryTime -gt $reviewed -or $afterTime -gt $reviewed -or
            @($beforeTime, $eventTime, $afterTime, $arrivalTime, $queryTime, $reviewed | Where-Object { $_ -gt $Now }).Count -gt 0 -or
            $beforeTime -lt $Now.AddDays(-30)) { throw 'Evidence timing is stale, future-dated or inconsistent (30-day maximum window).' }
        if ($event.System.Provider -cne 'Microsoft-Windows-Security-Auditing' -or $event.System.Channel -cne 'Security' -or
            $event.System.Computer -ine $context.computer -or @($Rule.event_ids).Count -ne 1 -or
            [string]$Rule.event_ids[0] -ne $event.System.EventID) { throw 'Native source event identity does not match the rule or host.' }
        if (@($Rule.channel | Where-Object { $_ -notin @('sec', 'Security') }).Count -or @($Rule.channel).Count -eq 0) { throw 'Evidence adapter supports only an explicit native Security source.' }
        if ($event.System.Keywords -notmatch '^0x[0-9a-fA-F]+$') { throw 'Unknown Security event outcome.' }
        $keywords = [Convert]::ToUInt64($event.System.Keywords.Substring(2), 16)
        $outcome = if ($keywords -band [uint64]0x0020000000000000) { 1 } elseif ($keywords -band [uint64]0x0010000000000000) { 2 } else { 0 }
        if (-not $outcome -or (($keywords -band [uint64]0x0030000000000000) -eq [uint64]0x0030000000000000)) { throw 'Ambiguous Security event outcome.' }
        $mask = $after.auditPolicies.($Policy.guid)
        if ($mask -isnot [ValueType] -or $mask -is [bool] -or $mask -notin @(0, 1, 2, 3) -or ($mask -band $outcome) -ne $outcome -or
            $after.auditPrecedence.kind -ne 'DWord' -or $after.auditPrecedence.value -isnot [ValueType] -or $after.auditPrecedence.value -is [bool] -or
            $after.auditPrecedence.value -ne 1 -or $after.securityChannelEnabled -isnot [bool] -or -not $after.securityChannelEnabled) { throw 'Recorded effective policy does not verify the observed event outcome and precedence.' }
        $beforeMask = $before.auditPolicies.($Policy.guid)
        if ($beforeMask -isnot [ValueType] -or $beforeMask -is [bool] -or $beforeMask -notin @(0, 1, 2, 3)) { throw 'Before-state effective policy is missing or invalid.' }
        if ($event.System.EventID -eq '4688' -and ($outcome -ne 1 -or $event.System.Version -notin @('0', '1', '2'))) { throw 'Unsupported 4688 outcome or event version.' }
        $supported4688 = @('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId', 'NewProcessId', 'NewProcessName', 'TokenElevationType', 'ProcessId', 'CommandLine', 'TargetUserSid', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'ParentProcessName', 'MandatoryLabel')
        foreach ($selector in $selectors) {
            $field = $selector.Name
            $sourceField = [string]$Record.fieldMappings.$field
            if ($field -eq 'EventID' -and $sourceField -eq 'System.EventID') { $actual = $event.System.EventID }
            elseif ($sourceField.StartsWith('EventData.')) {
                $nativeName = $sourceField.Substring(10)
                # Reviewed aliases only: an imported map cannot turn Image into
                # Hashes, or substitute an unrelated field that happens to match.
                $aliases = @{}
                if ($event.System.EventID -eq '4688') { $aliases = @{ Image = 'NewProcessName'; ParentImage = 'ParentProcessName'; ProcessId = 'NewProcessId'; ParentProcessId = 'ProcessId' } }
                $expectedName = if ($aliases.ContainsKey($field)) { $aliases[$field] } else { $field }
                if ($nativeName -cne $expectedName) { return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedFieldMapping'); References = @($artifactNames) } }
                if ($event.System.EventID -eq '4688' -and ($supported4688 -notcontains $nativeName -or
                    ($nativeName -eq 'CommandLine' -and $event.System.Version -eq '0') -or
                    ($nativeName -in @('TargetUserSid', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'ParentProcessName', 'MandatoryLabel') -and $event.System.Version -ne '2'))) { throw 'Required field is unsupported in this native 4688 schema/version.' }
                if (-not $event.Data.ContainsKey($nativeName) -or [string]::IsNullOrEmpty($event.Data[$nativeName])) { throw "Required native field missing or empty: $field" }
                $actual = $event.Data[$nativeName]
                if ($event.System.EventID -eq '4688' -and $nativeName -eq 'CommandLine' -and
                    ($after.commandLineCapture.kind -ne 'DWord' -or $after.commandLineCapture.value -isnot [ValueType] -or
                     $after.commandLineCapture.value -is [bool] -or $after.commandLineCapture.value -ne 1)) { throw '4688 command-line capture policy is unverified.' }
            } else { return [pscustomobject]@{ State = 'Conditional'; Reasons = @('UnsupportedFieldMapping'); References = @($artifactNames) } }
            if ([string]$actual -ine [string]$selector.Value -or [string]$ingestion.normalizedFields.$field -cne [string]$actual) { throw "Rule selection or ingested normalized field did not match: $field" }
        }
        foreach ($name in @('backend', 'backendVersion')) {
            if ($ingestion.$name -cne $context.$name -or $queryResult.$name -cne $context.$name) { throw 'Backend identity/version mismatch.' }
        }
        if ($ingestion.eventSha256 -ne $a.eventXml.Sha256 -or $queryResult.eventSha256 -ne $a.eventXml.Sha256 -or
            $queryResult.ruleSha256 -ne $a.normalizedRule.Sha256 -or $queryResult.querySha256 -ne $a.query.Sha256 -or
            $queryResult.matched -isnot [bool] -or -not $queryResult.matched -or $queryResult.exitCode -isnot [ValueType] -or
            $queryResult.exitCode -is [bool] -or $queryResult.exitCode -ne 0 -or
            $ingestion.computer -ine $event.System.Computer -or $ingestion.channel -cne 'Security' -or
            [string]$ingestion.eventId -ne $event.System.EventID -or [string]$ingestion.recordId -ne $event.System.EventRecordID) { throw 'Ingestion or translated-query match evidence is incomplete or inconsistent.' }
        [pscustomobject]@{ State = 'Ready'; Reasons = @('ImportedEvidenceVerified'); References = @($artifactNames); Context = $context; AsOfUtc = $queryResult.executedAtUtc }
    } catch { [pscustomobject]@{ State = 'Conditional'; Reasons = @('EvidenceRejected', $_.Exception.Message); References = @() } }
}

function Get-WelaRuleEligibility {
    [CmdletBinding()]
    param([string]$CorpusPath = (Join-Path $PSScriptRoot '../config/security_rules.json'),
          [string]$MappingPath = (Join-Path $PSScriptRoot '../config/eid_subcategory_mapping.csv'),
          [string]$ManifestPath = (Join-Path $PSScriptRoot '../config/rule_eligibility_manifest.json'),
          [string]$EvidencePath, [ValidateSet('Client', 'MemberServer', 'DomainController', 'ADCS')][string]$Role,
          [int]$Build, [array]$Observations = @(), [DateTime]$Now = [DateTime]::UtcNow)
    $corpusInput = Read-WelaEligibilityInput $CorpusPath
    $mappingInput = Read-WelaEligibilityInput $MappingPath
    $corpusHash = $corpusInput.Sha256; $mappingHash = $mappingInput.Sha256
    if (-not $corpusInput.Text.TrimStart().StartsWith('[')) { throw 'Extracted corpus must be a JSON array.' }
    $parsed = $corpusInput.Text | ConvertFrom-Json -ErrorAction Stop
    $raw = @($parsed)
    $manifest = $null
    if (Test-Path -LiteralPath $ManifestPath) { $manifest = Read-WelaEligibilityJson $ManifestPath }
    $pinned = $manifest.schemaVersion -eq 1 -and $manifest.corpusSha256 -eq $corpusHash -and $manifest.mappingSha256 -eq $mappingHash
    $profileData = Read-WelaEligibilityJson (Join-Path $PSScriptRoot '../config/audit_profiles.json')
    $policies = @{}; foreach ($policy in $profileData.catalog) { $policies[$policy.guid] = $policy }
    $nameAliases = @{
        'Non-Sensitive Privilege Use' = 'Non Sensitive Privilege Use'
        'User / Device Claims' = 'User/Device Claims'
        'Central Policy Staging' = 'Central Access Policy Staging'
    }
    $eventMap = @{}
    foreach ($mapping in @($mappingInput.Text | ConvertFrom-Csv -ErrorAction Stop)) {
        if ($mapping.'Event ID' -notmatch '^\d+$') { continue } # Category headers never match events.
        $name = [string]$mapping.Subcategory
        if ($nameAliases.ContainsKey($name)) { $name = $nameAliases[$name] }
        $canonical = $policies.ContainsKey([string]$mapping.GUID) -and $policies[[string]$mapping.GUID].id -eq $name -and $policies[[string]$mapping.GUID].category -eq $mapping.Category
        $mapping | Add-Member NoteProperty Canonical ([bool]$canonical)
        $id = $mapping.'Event ID'
        if (-not $eventMap.ContainsKey($id)) { $eventMap[$id] = @() }
        $eventMap[$id] += $mapping
    }
    $evidence = @{}; $evidenceRoot = $null
    if ($EvidencePath) {
        $bundleFile = Get-Item -LiteralPath $EvidencePath -ErrorAction Stop
        if ($bundleFile.Length -gt 16777216 -or $bundleFile.FullName.StartsWith('\\')) { throw 'Evidence bundle is remote or too large.' }
        $bundle = ConvertFrom-WelaEligibilityJson ([IO.File]::ReadAllText($bundleFile.FullName))
        if ($bundle.schemaVersion -ne 1 -or $bundle.kind -ne 'WelaNativeRuleEvidence' -or $bundle.records -isnot [array]) { throw 'Unsupported evidence bundle schema.' }
        $evidenceRoot = Split-Path -Parent ([IO.Path]::GetFullPath($EvidencePath))
        foreach ($record in $bundle.records) {
            if (-not $record.id -or $evidence.ContainsKey([string]$record.id)) { throw 'Missing or duplicate evidence rule ID.' }
            $evidence[[string]$record.id] = $record
        }
    }
    $observedById = @{}
    foreach ($observation in $Observations) {
        foreach ($rule in $observation.Rules) {
            if (-not $observedById.ContainsKey([string]$rule.id)) { $observedById[[string]$rule.id] = @() }
            $observedById[[string]$rule.id] += $observation
        }
    }
    $seen = @{}; $rows = New-Object 'System.Collections.Generic.List[object]'; $duplicateCount = 0
    foreach ($rule in $raw) {
        if ($rule -isnot [pscustomobject] -or $rule.id -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.id)) { throw 'Corpus entries require a nonempty string rule ID.' }
        $metadataHash = Get-WelaEligibilityRuleHash $rule
        if ($seen.ContainsKey($rule.id)) {
            if ($seen[$rule.id] -ne $metadataHash) { throw "Conflicting metadata for duplicate rule ID: $($rule.id)" }
            $duplicateCount++; continue
        }
        $seen[$rule.id] = $metadataHash
        $reasons = New-Object 'System.Collections.Generic.List[string]'
        $state = 'Conditional'; $scopeReason = $null; $mappedPolicies = @(); $mappingComplete = $true
        $channels = @($rule.channel); $eventIds = @($rule.event_ids)
        $validMetadata = $rule.channel -is [array] -and $rule.event_ids -is [array] -and $rule.subcategory_guids -is [array] -and
            @($channels | Where-Object { $_ -isnot [string] -or -not $_ }).Count -eq 0 -and
            @($eventIds | Where-Object { $_ -isnot [string] -or $_ -notmatch '^\d+$' }).Count -eq 0 -and
            @($rule.subcategory_guids | Where-Object { $_ -isnot [string] -or -not $_ }).Count -eq 0
        if (-not $validMetadata) { $reasons.Add('UnsupportedMetadataShape') }
        if (@($channels | Where-Object { [string]$_ -match '(?i)sysmon' }).Count -or $rule.service -eq 'sysmon') { $state = 'Excluded'; $scopeReason = 'ExplicitSysmonSource' }
        elseif ($rule.service -in @('msexchange-management', 'mssql', 'sqlserver', 'microsoft-servicebus-client', 'screenconnect')) { $state = 'Excluded'; $scopeReason = 'ExternalProductSource' }
        foreach ($id in $eventIds) {
            $mappings = @($eventMap[[string]$id])
            $canonical = @($mappings | Where-Object { $_ -and $_.Canonical })
            $distinct = @($canonical.GUID | Sort-Object -Unique)
            if ($distinct.Count -ne 1 -or @($mappings | Where-Object { $_ -and -not $_.Canonical }).Count) { $mappingComplete = $false }
            foreach ($guid in $distinct) { $mappedPolicies += $policies[$guid] }
        }
        if (@($rule.subcategory_guids | Where-Object { -not $policies.ContainsKey([string]$_) -or ($mappedPolicies.Count -gt 0 -and $mappedPolicies.guid -notcontains $_) }).Count) { $mappingComplete = $false }
        if ($eventIds.Count -eq 0) { $mappingComplete = $false; $reasons.Add('EventIdentityUnknown') }
        elseif (-not $mappingComplete -and @($channels | Where-Object { $_ -in @('sec', 'Security') }).Count) { $reasons.Add('AuditMappingAmbiguousOrUnknown') }
        if ($channels.Count -eq 0) { $reasons.Add('NativeSourceUnknown') }
        $securityOnly = $channels.Count -gt 0 -and @($channels | Where-Object { $_ -notin @('sec', 'Security') }).Count -eq 0
        if ($state -ne 'Excluded' -and $validMetadata -and $securityOnly -and $mappingComplete -and $Role -and
            $mappedPolicies.Count -gt 0 -and @($mappedPolicies | Where-Object { $_.roles -contains $Role }).Count -eq 0) {
            $state = 'NotApplicable'; $reasons.Add('AllKnownEventSourcesBelongToOtherRoles')
        }
        $matchingRows = @($observedById[$rule.id] | Where-Object { $null -ne $_ })
        $configurationEstimate = @($matchingRows | Where-Object { $_.CurrentSetting -match 'Success|Failure|^Enabled$' }).Count -gt 0
        if ($state -eq 'Conditional' -and $matchingRows.Count -gt 0 -and
            @($matchingRows | Where-Object { $_.CurrentSetting -notin @('No Auditing', 'Disabled', 'Not installed') }).Count -eq 0) {
            $state = 'Blocked'; $reasons.Add('ObservedSourcesDisabledOrAbsent')
        }
        $proof = $null
        if ($evidence.ContainsKey($rule.id) -and $state -eq 'Conditional' -and $validMetadata) {
            if (-not $pinned) { $reasons.Add('CorpusOrMappingNotPinned') }
            elseif (-not $mappingComplete -or $eventIds.Count -ne 1) { $reasons.Add('EvidenceRequiresUnambiguousSingleEventMapping') }
            else {
                $proof = Test-WelaEligibilityEvidence -Record $evidence[$rule.id] -Rule $rule -MetadataHash $metadataHash -Root $evidenceRoot `
                    -CorpusHash $corpusHash -MappingHash $mappingHash -Policy $mappedPolicies[0] -Role $Role -Build $Build -Now $Now
                $state = $proof.State; foreach ($reason in $proof.Reasons) { $reasons.Add($reason) }
            }
        } elseif ($state -eq 'Conditional') { $reasons.Add('FullRuleDefinitionAndLabEvidenceMissing') }
        if ($state -eq 'Conditional') { $reasons.Add('EnabledPolicyOrChannelIsNotRuleReadiness') }
        $rows.Add([pscustomobject][ordered]@{
            Id = $rule.id; Title = $rule.title; State = $state; Reasons = @($reasons.ToArray() | Select-Object -Unique)
            ScopeExclusion = $scopeReason; MetadataSha256 = $metadataHash; Channels = $channels; EventIds = $eventIds
            AuditMapping = $(if ($mappingComplete) { 'Canonical candidates; outcome still requires event evidence' } else { 'Ambiguous or unknown' })
            PolicyPrerequisites = @($mappedPolicies | ForEach-Object { $_.prerequisites } | Where-Object { $_ } | Select-Object -Unique)
            ConfigurationEstimate = $configurationEstimate; EvidenceArtifacts = @($proof.References)
            EvidenceAsOfUtc = $proof.AsOfUtc; EvidenceContext = $proof.Context
        })
    }
    foreach ($id in $evidence.Keys) { if (-not $seen.ContainsKey($id)) { throw "Evidence references a rule outside this corpus: $id" } }
    $counts = @{}; foreach ($state in @('Ready', 'Conditional', 'Blocked', 'NotApplicable', 'Excluded')) { $counts[$state] = @($rows | Where-Object State -eq $state).Count }
    $native = $rows.Count - $counts.Excluded; $applicable = $native - $counts.NotApplicable
    [pscustomobject][ordered]@{
        SchemaVersion = 1; GeneratedAtUtc = $Now.ToString('o'); Scope = 'native-windows-rule-eligibility'
        AssessmentBasis = $(if ($EvidencePath) { 'Imported lab artifacts; Ready applies only to the recorded context/time and is not a current-host or universal guarantee.' } else { 'Metadata/configuration assessment only; no event-generation, ingestion or query evidence imported.' })
        Corpus = [pscustomobject]@{ Sha256 = $corpusHash; MappingSha256 = $mappingHash; Pinned = [bool]$pinned; Manifest = $manifest; Kind = 'WELA extracted Hayabusa rule metadata; not the complete upstream Sigma corpus' }
        RequestedContext = [pscustomobject]@{ Role = $Role; Build = $(if ($Build) { $Build } else { $null }) }
        Summary = [pscustomobject]@{
            InputRecords = $raw.Count; UniqueRules = $rows.Count; DuplicateRecords = $duplicateCount
            NativeCandidates = $native; ApplicableCandidates = $applicable; Ready = $counts.Ready; Conditional = $counts.Conditional
            Blocked = $counts.Blocked; NotApplicable = $counts.NotApplicable; Excluded = $counts.Excluded
            ReadyPercentNative = $(if ($native) { 100.0 * $counts.Ready / $native } else { $null })
            ReadyPercentApplicable = $(if ($applicable) { 100.0 * $counts.Ready / $applicable } else { $null })
            ReadyPercentFullCorpus = $(if ($rows.Count) { 100.0 * $counts.Ready / $rows.Count } else { $null })
            ConfigurationEstimateCount = @($rows | Where-Object ConfigurationEstimate).Count
            ExclusionsByReason = @($rows | Where-Object State -eq 'Excluded' | Group-Object ScopeExclusion | Select-Object Name, Count)
            DenominatorNote = 'Unknown/incomplete native candidates stay in the denominator. Only explicit Sysmon/external-product sources are excluded; excluded IDs remain in Results.'
        }
        Results = @($rows.ToArray())
    }
}

function Export-WelaRuleEligibility {
    param($Report, [string]$ResultsPath, [string]$HtmlPath)
    if ($ResultsPath) { $Report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    if ($HtmlPath) {
        $encode = { param($value) [Net.WebUtility]::HtmlEncode([string]$value) }
        $html = New-Object Text.StringBuilder
        [void]$html.Append('<!doctype html><html lang="en"><meta charset="utf-8"><title>WELA native rule eligibility</title><style>body{font:16px sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.5rem;text-align:left}code{overflow-wrap:anywhere}</style><h1>Native rule eligibility</h1>')
        [void]$html.Append('<p>' + (& $encode $Report.AssessmentBasis) + '</p><pre>' + (& $encode ($Report.Summary | ConvertTo-Json -Depth 6)) + '</pre><p>Corpus SHA256: <code>' + (& $encode $Report.Corpus.Sha256) + '</code></p><table><tr><th>Rule</th><th>State</th><th>Reasons</th></tr>')
        foreach ($row in $Report.Results) { [void]$html.Append('<tr><td>' + (& $encode ($row.Title + ' [' + $row.Id + ']')) + '</td><td>' + (& $encode $row.State) + '</td><td>' + (& $encode ((@($row.Reasons) + @($row.ScopeExclusion)) -join '; ')) + '</td></tr>') }
        [void]$html.Append('</table></html>')
        $html.ToString() | Set-Content -LiteralPath $HtmlPath -Encoding UTF8 -ErrorAction Stop
    }
}

Export-ModuleMember -Function Get-WelaRuleEligibility, Export-WelaRuleEligibility
