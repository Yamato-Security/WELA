$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/RuleEligibility.psm1') -Force
$checks = 0
function Assert($Value, $Message) { if (-not $Value) { throw $Message }; $script:checks++ }
function Assert-Throws($Action, $Message) { $caught=$false; try { & $Action | Out-Null } catch { $caught=$true }; Assert $caught $Message }
$root = Join-Path ([IO.Path]::GetTempPath()) ('wela-eligibility-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$corpusPath = Join-Path $root 'rules.json'; $manifestPath = Join-Path $root 'manifest.json'; $bundlePath = Join-Path $root 'evidence.json'
$mappingPath = Join-Path $PSScriptRoot '../config/eid_subcategory_mapping.csv'
$now = [DateTime]::Parse('2026-09-19T12:00:00Z').ToUniversalTime()
function Save-Json($Object, $Path) { ConvertTo-Json -InputObject $Object -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8 }
function Hash($Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Save-Corpus($Rules) {
    Save-Json @($Rules) $corpusPath
    Save-Json @{schemaVersion=1;corpusSha256=(Hash $corpusPath);mappingSha256=(Hash $mappingPath)} $manifestPath
}
function Fixture-Rule($Id='process') {
    [pscustomobject]@{id=$Id;title='Benign process fixture';category='process_creation';service='';channel=@('sec');event_ids=@('4688');subcategory_guids=@('0CCE922B-69AE-11D9-BED3-505054503030');level='low';description='Synthetic evidence; not a live Windows test.';tags=@()}
}
function Report([switch]$Evidence) {
    $args = @{CorpusPath=$corpusPath;ManifestPath=$manifestPath;MappingPath=$mappingPath;Now=$now}
    if ($Evidence) { $args.EvidencePath=$bundlePath }
    Get-WelaRuleEligibility @args
}
function Save-Artifact($Name, $Object, [switch]$Text) {
    $path = Join-Path $root ($Name + '.txt')
    if ($Text) { [IO.File]::WriteAllText($path, [string]$Object, [Text.UTF8Encoding]::new($false)) }
    else { Save-Json $Object $path }
    $script:record.artifacts.$Name = @{path=($Name+'.txt');sha256=(Hash $path)}
}
function Save-Bundle { Save-Json @{schemaVersion=1;kind='WelaNativeRuleEvidence';records=@($script:record)} $bundlePath }
function Reset-Evidence {
    Save-Corpus @(Fixture-Rule)
    $base = Report
    $script:record = @{id='process';metadataSha256=$base.Results[0].MetadataSha256;corpusSha256=(Hash $corpusPath);mappingSha256=(Hash $mappingPath);adapter='security-single-event-exact-v1';fieldMappings=@{EventID='System.EventID';Image='EventData.NewProcessName';CommandLine='EventData.CommandLine'};artifacts=@{}}
    $script:definition = @{id='process';logsource=@{product='windows';category='process_creation'};detection=@{selection=@{EventID=4688;Image='C:\Windows\System32\notepad.exe';CommandLine='notepad.exe --wela-fixture'};condition='selection'}}
    Save-Artifact sourceRule "id: process`nlogsource: {product: windows, category: process_creation}`ndetection:`n  selection:`n    EventID: 4688`n    Image: C:\Windows\System32\notepad.exe`n    CommandLine: notepad.exe --wela-fixture`n  condition: selection`n" -Text
    Save-Artifact normalizedRule $script:definition
    $context=@{computer='lab.example.test';role='Client';build=26100;patch='fixture-1';domainJoined=$false;installedRoles=@();backend='fixture-backend';backendVersion='1'}
    $script:before=@{context=$context;capturedAtUtc='2026-09-19T10:00:00Z';auditPolicies=@{'0CCE922B-69AE-11D9-BED3-505054503030'=0}}
    $script:after=@{context=$context;capturedAtUtc='2026-09-19T10:02:00Z';auditPolicies=@{'0CCE922B-69AE-11D9-BED3-505054503030'=1};auditPrecedence=@{kind='DWord';value=1};securityChannelEnabled=$true;commandLineCapture=@{kind='DWord';value=1}}
    Save-Artifact beforeState $script:before; Save-Artifact afterState $script:after
    $script:eventXml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Version>2</Version><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-19T10:01:00Z"/><EventRecordID>42</EventRecordID><Channel>Security</Channel><Computer>lab.example.test</Computer></System><EventData><Data Name="NewProcessName">C:\Windows\System32\notepad.exe</Data><Data Name="CommandLine">notepad.exe --wela-fixture</Data></EventData></Event>'
    Save-Artifact eventXml $script:eventXml -Text
    $script:ingestion=@{computer='lab.example.test';channel='Security';eventId=4688;recordId=42;eventSha256=$script:record.artifacts.eventXml.sha256;backend='fixture-backend';backendVersion='1';receivedAtUtc='2026-09-19T10:03:00Z';normalizedFields=@{EventID='4688';Image='C:\Windows\System32\notepad.exe';CommandLine='notepad.exe --wela-fixture'}}
    Save-Artifact ingestion $script:ingestion
    Save-Artifact query 'Fixture backend query artifact; this test never executes a query.' -Text
    $script:queryResult=@{backend='fixture-backend';backendVersion='1';executedAtUtc='2026-09-19T10:04:00Z';eventSha256=$script:record.artifacts.eventXml.sha256;ruleSha256=$script:record.artifacts.normalizedRule.sha256;querySha256=$script:record.artifacts.query.sha256;matched=$true;exitCode=0}
    Save-Artifact queryResult $script:queryResult
    $script:review=@{ruleId='process';reviewer='Fixture author (synthetic evidence only)';reviewedAtUtc='2026-09-19T10:05:00Z';statement='Complete rule normalization reviewed; no detection logic omitted.';sourceRuleSha256=$script:record.artifacts.sourceRule.sha256;normalizedRuleSha256=$script:record.artifacts.normalizedRule.sha256}
    Save-Artifact review $script:review
    Save-Bundle
}
function Assert-NotReady($Message) { Save-Bundle; $r=Report -Evidence; Assert ($r.Summary.Ready -eq 0 -and $r.Results[0].Reasons.Count -gt 0) $Message }
try {
    # Construct Unicode explicitly so the test source also loads correctly in
    # Windows PowerShell 5.1 without relying on a UTF-8 BOM.
    $hashVector=Fixture-Rule 'hash-vector'
    $hashVector.title='Apostrophe' + [char]0x27 + 's <node> & "quoted" \ path ' + [char]0x65e5 + [char]0x672c + [char]0x8a9e + [char]::ConvertFromUtf32(0x1f600)
    $hashVector.description="line`nnext`ttab"
    $actualMetadataHash=& (Get-Module RuleEligibility) { param($rule) Get-WelaEligibilityRuleHash $rule } $hashVector
    # Expected digest independently calculated from the documented framing in Python.
    Assert ($actualMetadataHash -eq 'cfa5e1a0f73d8f0eef62716a44e56334461bbf55ddf0a07b39ee63e378597e9d') ("Metadata hash is independent of PowerShell JSON serialization: " + $actualMetadataHash)
    function Canonical($Value) { & (Get-Module RuleEligibility) { param($item) ConvertTo-WelaEligibilityCanonicalValue -Value $item } $Value }
    foreach ($pair in @(
        [pscustomobject]@{Left=$null;Right=''}, [pscustomobject]@{Left=$null;Right=@()},
        [pscustomobject]@{Left=@();Right=[pscustomobject]@{}}, [pscustomobject]@{Left=1;Right='1'},
        [pscustomobject]@{Left=$true;Right=1}, [pscustomobject]@{Left=1;Right=1.0},
        [pscustomobject]@{Left=@('ab','c');Right=@('a','bc')}, [pscustomobject]@{Left='a';Right=@('a')},
        [pscustomobject]@{Left=@('a','b');Right=@('b','a')},
        [pscustomobject]@{Left=([string][char]0xd800);Right=([string][char]0xfffd)},
        [pscustomobject]@{Left=([string][char]0x00e9);Right=('e'+[char]0x0301)}
    )) { Assert ((Canonical $pair.Left) -cne (Canonical $pair.Right)) 'Canonical framing preserves type, boundaries, array order and exact Unicode code units.' }
    Assert ((Canonical ([pscustomobject][ordered]@{z=@('x');a=@()})) -ceq (Canonical ([pscustomobject][ordered]@{a=@();z=@('x')}))) 'Object identity uses ordinal property order rather than insertion order.'
    Assert ((Canonical ([pscustomobject]@{a=@('x')})) -cne (Canonical ([pscustomobject]@{a='x'}))) 'Nested singleton arrays retain their type.'
    Assert ((Canonical ([pscustomobject]@{a=@()})) -cne (Canonical ([pscustomobject]@{a=$null}))) 'Nested empty arrays never collapse into null.'
    Save-Corpus @(Fixture-Rule)
    $r=Report
    Assert ($r.Summary.Ready -eq 0 -and $r.Results[0].State -eq 'Conditional') 'Lossy metadata cannot demonstrate usable rules.'
    $observed=[pscustomobject]@{CurrentSetting='Success';Rules=@(Fixture-Rule)}
    $r=Get-WelaRuleEligibility -CorpusPath $corpusPath -ManifestPath $manifestPath -Observations @($observed)
    Assert ($r.Summary.Ready -eq 0 -and $r.Results[0].ConfigurationEstimate) 'Enabled Security audit policy is an estimate, never Ready.'
    $observed.CurrentSetting='No Auditing'
    $r=Get-WelaRuleEligibility -CorpusPath $corpusPath -ManifestPath $manifestPath -Observations @($observed)
    Assert ($r.Results[0].State -eq 'Blocked') 'A positively observed disabled source is distinct from missing evidence.'
    $sysmon=Fixture-Rule 'sysmon';$sysmon.channel=@('Microsoft-Windows-Sysmon/Operational')
    $external=Fixture-Rule 'exchange';$external.service='msexchange-management'
    Save-Corpus @((Fixture-Rule),(Fixture-Rule),$sysmon,$external)
    $r=Report
    Assert ($r.Summary.InputRecords -eq 4 -and $r.Summary.UniqueRules -eq 3 -and $r.Summary.DuplicateRecords -eq 1) 'Identical duplicate IDs count once with explicit raw input count.'
    Assert ($r.Summary.NativeCandidates -eq 1 -and $r.Summary.Excluded -eq 2 -and $r.Results.Count -eq 3) 'Explicit exclusions remain inspectable and all denominator choices are visible.'
    $conflict=Fixture-Rule;$conflict.title='Conflicting title';Save-Corpus @((Fixture-Rule),$conflict)
    Assert-Throws { Report } 'Conflicting duplicate metadata cannot silently change the denominator.'
    Save-Corpus @();$r=Report
    Assert ($null -eq $r.Summary.ReadyPercentNative -and $null -eq $r.Summary.ReadyPercentFullCorpus) 'An empty denominator is unknown rather than fabricated zero percent.'
    $dc=Fixture-Rule 'directory';$dc.event_ids=@('5136');$dc.subcategory_guids=@('0CCE923C-69AE-11D9-BED3-505054503030');Save-Corpus @($dc)
    $r=Get-WelaRuleEligibility -CorpusPath $corpusPath -ManifestPath $manifestPath -Role ADCS
    Assert ($r.Results[0].State -eq 'NotApplicable' -and $r.Summary.ApplicableCandidates -eq 0) 'Directory change events originate on the DC, not automatically on an AD CS member.'
    $unknown=Fixture-Rule;$unknown.event_ids=@('4703');Save-Corpus @($unknown);$r=Report
    Assert ($r.Results[0].Reasons -contains 'AuditMappingAmbiguousOrUnknown') 'Multiple canonical mappings for 4703 remain ambiguous.'
    $unknown.event_ids=@('4608');Save-Corpus @($unknown);$r=Report
    Assert ($r.Results[0].Reasons -contains 'AuditMappingAmbiguousOrUnknown') 'A category-level GUID beside a canonical mapping is not silently ignored.'
    $unknown.event_ids=@('');Save-Corpus @($unknown);$r=Report
    Assert ($r.Results[0].Reasons -contains 'UnsupportedMetadataShape') 'Blank event IDs never match category headers.'
    $unknown.event_ids='4688';Save-Corpus @($unknown);$r=Report
    Assert ($r.Results[0].Reasons -contains 'UnsupportedMetadataShape') 'Unexpected scalar metadata fails conservatively instead of being partially parsed.'

    Reset-Evidence;$r=Report -Evidence
    Assert ($r.Summary.Ready -eq 1 -and $r.Results[0].State -eq 'Ready') ('Coherent complete synthetic evidence demonstrates the importer gates: '+($r.Results[0].Reasons -join '; '))
    Assert ($r.Results[0].EvidenceContext.computer -eq 'lab.example.test' -and $r.AssessmentBasis -like '*not a current-host*') 'Imported Ready states retain their recorded host/time and explicit limitations.'
    $evidenceHtml=Join-Path $root 'evidence.html'
    Export-WelaRuleEligibility -Report $r -HtmlPath $evidenceHtml
    $exported=[IO.File]::ReadAllText($evidenceHtml)
    foreach ($required in @('Requested context','lab.example.test','Client','26100','fixture-1','domainJoined','installedRoles','fixture-backend','backendVersion','2026-09-19T10:04:00Z')) {
        Assert ($exported.Contains($required)) "Shared HTML must retain evidence scope: $required"
    }
    $hostileContext='</pre><script>alert("fixture")</script>&'
    $r.Results[0].EvidenceContext.computer=$hostileContext
    Export-WelaRuleEligibility -Report $r -HtmlPath $evidenceHtml
    $exported=[IO.File]::ReadAllText($evidenceHtml)
    Assert (-not ($exported -match '<\s*script\b')) 'Evidence context cannot create executable script markup.'
    # Windows PowerShell 5.1 may JSON-escape angle brackets before HTML encoding;
    # compare the decoded value rather than requiring one serialization spelling.
    $contextBlock=[regex]::Match($exported, '(?s)Recorded context \(not the current host\):</p><pre>(.*?)</pre>')
    Assert $contextBlock.Success 'The evidence context remains inside its HTML text block.'
    $renderedContext=[Net.WebUtility]::HtmlDecode($contextBlock.Groups[1].Value) | ConvertFrom-Json
    Assert ($renderedContext.computer -ceq $hostileContext) 'HTML text and JSON decoding preserve the exact context value without creating markup.'
    foreach ($name in @('sourceRule','normalizedRule','review','beforeState','afterState','eventXml','ingestion','query','queryResult')) {
        Reset-Evidence;$script:record.artifacts.Remove($name);Assert-NotReady "Missing $name prevents Ready."
    }
    Reset-Evidence;$script:record.metadataSha256='0'*64;Assert-NotReady 'Metadata identity mismatches cannot import readiness.'
    Reset-Evidence;$script:record.mappingSha256='0'*64;Assert-NotReady 'Changed EventID mapping invalidates old evidence.'
    Reset-Evidence;$script:record.artifacts.eventXml.sha256='0'*64;Assert-NotReady 'Changed native XML invalidates its evidence chain.'
    Reset-Evidence;$script:record.artifacts.query.path='../outside.txt';Assert-NotReady 'Artifact traversal is rejected before access.'
    Reset-Evidence;$script:record.artifacts.query.path='\\server\share\query.txt';Assert-NotReady 'UNC artifacts are rejected before access.'
    foreach ($invalidNumber in @('1', $true)) {
        Reset-Evidence;$script:after.auditPrecedence.value=$invalidNumber;Save-Artifact afterState $script:after;Assert-NotReady 'Precedence evidence requires a numeric DWORD, not a coercible string/boolean.'
        Reset-Evidence;$script:after.commandLineCapture.value=$invalidNumber;Save-Artifact afterState $script:after;Assert-NotReady 'Command-line evidence requires a numeric DWORD.'
    }
    foreach ($invalidExit in @('0', $false)) {
        Reset-Evidence;$script:queryResult.exitCode=$invalidExit;Save-Artifact queryResult $script:queryResult;Assert-NotReady 'Query exit code must be numeric, never a coercible string/boolean.'
    }
    Reset-Evidence;$script:after.auditPolicies.'0CCE922B-69AE-11D9-BED3-505054503030'=2;Save-Artifact afterState $script:after;Assert-NotReady 'Failure-only auditing cannot satisfy successful 4688 evidence.'
    Reset-Evidence;$script:after.commandLineCapture.value=0;Save-Artifact afterState $script:after;Assert-NotReady 'Observed XML cannot substitute for unverified command-line capture policy.'
    Reset-Evidence;$script:eventXml=$script:eventXml.Replace('notepad.exe --wela-fixture','');Save-Artifact eventXml $script:eventXml -Text;Assert-NotReady 'Empty 4688 command-line field prevents readiness.'
    Reset-Evidence;$script:record.fieldMappings.Image='EventData.CommandLine';Assert-NotReady 'A supplied alias cannot substitute a different field for Image.'
    Reset-Evidence;$script:definition.detection.condition='selection and not filter';Save-Artifact normalizedRule $script:definition;$script:review.normalizedRuleSha256=$script:record.artifacts.normalizedRule.sha256;Save-Artifact review $script:review;Assert-NotReady 'Unsupported complete Boolean logic is not partially evaluated.'
    Reset-Evidence;$script:definition.detection.selection['Image|endswith']='notepad.exe';Save-Artifact normalizedRule $script:definition;$script:review.normalizedRuleSha256=$script:record.artifacts.normalizedRule.sha256;Save-Artifact review $script:review;Assert-NotReady 'Unsupported field modifiers cannot be silently ignored.'
    Reset-Evidence;$script:definition.logsource.service='sysmon';Save-Artifact normalizedRule $script:definition;$script:review.normalizedRuleSha256=$script:record.artifacts.normalizedRule.sha256;Save-Artifact review $script:review;Assert-NotReady 'A Sysmon source cannot use native Security evidence.'
    Reset-Evidence;$script:definition.detection.selection.Hashes='abc';$script:record.fieldMappings.Hashes='EventData.NewProcessName';Save-Artifact normalizedRule $script:definition;$script:review.normalizedRuleSha256=$script:record.artifacts.normalizedRule.sha256;Save-Artifact review $script:review;Assert-NotReady 'A fabricated hash alias cannot turn process names into rich 4688 fields.'
    Reset-Evidence;$script:queryResult.matched=$false;Save-Artifact queryResult $script:queryResult;Assert-NotReady 'Successful collection without a query match is not Ready.'
    Reset-Evidence;$script:queryResult.exitCode=1;Save-Artifact queryResult $script:queryResult;Assert-NotReady 'Failed query execution cannot be overridden by matched=true.'
    Reset-Evidence;$script:ingestion.normalizedFields.Image='wrong.exe';Save-Artifact ingestion $script:ingestion;Assert-NotReady 'Backend normalization must preserve the required source field.'
    Reset-Evidence;$script:before.capturedAtUtc='2020-01-01T00:00:00Z';Save-Artifact beforeState $script:before;Assert-NotReady 'Stale evidence cannot silently establish present eligibility.'
    Reset-Evidence;$script:after.capturedAtUtc='2040-01-01T00:00:00Z';Save-Artifact afterState $script:after;Assert-NotReady 'A future after-state snapshot cannot grant readiness.'
    Reset-Evidence;$script:after.capturedAtUtc='2026-09-19T10:06:00Z';Save-Artifact afterState $script:after;Assert-NotReady 'A review cannot certify a state snapshot captured later.'
    Reset-Evidence;Save-Artifact eventXml '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]><Event>&x;</Event>' -Text;Assert-NotReady 'DTD/external entities are rejected.'
    Reset-Evidence;Save-Artifact queryResult '{"matched":false,"matched":true}' -Text;Assert-NotReady 'Duplicate JSON keys are rejected on both PowerShell editions.'
    Reset-Evidence;Save-Artifact queryResult '{"matched":false,"MATCHED":true}' -Text;Assert-NotReady 'Case-colliding JSON keys cannot change evidence meaning.'
    Reset-Evidence;$r=Get-WelaRuleEligibility -CorpusPath $corpusPath -ManifestPath $manifestPath -EvidencePath $bundlePath -Role DomainController -Now $now
    Assert ($r.Summary.Ready -eq 0) 'Imported host role must match an explicit assessment filter.'
    Reset-Evidence;$script:record.id='unknown-rule';Save-Bundle;Assert-Throws { Report -Evidence } 'Evidence for a rule absent from the pinned corpus is rejected.'
    $originalMappingPath=$mappingPath
    try {
        $mappingPath=Join-Path $root 'invalid-mapping.csv'
        [IO.File]::WriteAllText($mappingPath, [IO.File]::ReadAllText($originalMappingPath).Replace('"4688","Detailed Tracking","Process Creation"','"4688","Detailed Tracking","RPC Events"'))
        Reset-Evidence;$r=Report -Evidence
        Assert ($r.Summary.Ready -eq 0 -and $r.Results[0].Reasons -contains 'AuditMappingAmbiguousOrUnknown') 'A known GUID with the wrong canonical name cannot grant Ready.'
    } finally { $mappingPath=$originalMappingPath }

    # Exercise only the option guard, never a mutating CLI dispatch.
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'),[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'The public CLI parses with eligibility options.'
    $guard=$ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith("if (`$Cmd -ne 'rule-eligibility'") } | Select-Object -First 1
    Assert ($null -ne $guard) 'Dedicated eligibility options have a public pre-dispatch guard.'
    $exercise=[scriptblock]::Create('param($Cmd,$RuleEvidencePath,$RuleCorpusPath,$RuleManifestPath)' + [Environment]::NewLine + $guard.Extent.Text)
    Assert-Throws { & $exercise -Cmd configure -RuleEvidencePath '' } 'Even an explicitly empty evidence option is not silently ignored by configure.'
    & $exercise -Cmd rule-eligibility -RuleEvidencePath 'operator.json'

    $timer=[Diagnostics.Stopwatch]::StartNew();$full=Get-WelaRuleEligibility
    $pinDiagnostic='Full shipped corpus/manifest mismatch. Corpus SHA256 actual={0}, expected={1}; mapping SHA256 actual={2}, expected={3}; input count actual={4}, expected={5}; unique count actual={6}, expected={7}.' -f $full.Corpus.Sha256,$full.Corpus.Manifest.corpusSha256,$full.Corpus.MappingSha256,$full.Corpus.Manifest.mappingSha256,$full.Summary.InputRecords,$full.Corpus.Manifest.recordCount,$full.Summary.UniqueRules,$full.Corpus.Manifest.uniqueRuleCount
    Assert ($full.Corpus.Pinned -and $full.Summary.InputRecords -eq $full.Corpus.Manifest.recordCount -and $full.Summary.UniqueRules -eq $full.Corpus.Manifest.uniqueRuleCount) $pinDiagnostic
    Assert ($full.Summary.Ready -eq 0 -and ($full.Summary.NativeCandidates+$full.Summary.Excluded) -eq $full.Summary.UniqueRules) 'Full corpus is partitioned without unverified detection credit.'
    $json=Join-Path $root 'full.json';$html=Join-Path $root 'full.html'
    Export-WelaRuleEligibility -Report $full -ResultsPath $json -HtmlPath $html
    Assert ((Get-Item $json).Length -lt 8388608 -and (Get-Item $html).Length -lt 8388608) 'Full per-rule reports stay below 8 MiB each.'
    Assert ($timer.Elapsed.TotalSeconds -lt 180) 'Full-corpus assessment/export completes within a bounded three-minute budget.'
    Write-Host ('Full corpus: {0} unique rules, {1:N1}s, JSON {2} bytes.' -f $full.Summary.UniqueRules,$timer.Elapsed.TotalSeconds,(Get-Item $json).Length)
    Write-Host "PASS: $checks native rule eligibility assertions. Evidence is synthetic; no Windows event or backend query was generated."
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
