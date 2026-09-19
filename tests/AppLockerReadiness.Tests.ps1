$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/Configuration.ps1')
. (Join-Path $PSScriptRoot '../scripts/AppLockerReadiness.ps1')
$count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Assert-Throws([scriptblock]$Action,$Pattern) { $message=''; try { & $Action | Out-Null } catch { $message=$_.Exception.Message }; Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'." }
$xml='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Test" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
$placeholderNodes = @('Exe','Dll','Msi','Script','Appx') | ForEach-Object { '<RuleCollection Type="' + $_ + '" EnforcementMode="NotConfigured" />' }
$placeholders = '<AppLockerPolicy Version="1">' + ($placeholderNodes -join '') + '</AppLockerPolicy>'
$unusedPlaceholders = '<AppLockerPolicy Version="1">' + (($placeholderNodes | Select-Object -Skip 1) -join '') + '</AppLockerPolicy>'
$readbackPlaceholders = $xml.Replace('</AppLockerPolicy>', (($placeholderNodes | Select-Object -Skip 1) -join '') + '</AppLockerPolicy>')
$emptyPolicy=ConvertFrom-WelaAppLockerXml -Xml '<AppLockerPolicy Version="1" />'
Assert ($emptyPolicy.TotalRules -is [int] -and $emptyPolicy.TotalRules -eq 0) 'An understood empty policy reports zero rules, not an unknown null count.'
$desired=ConvertFrom-WelaAppLockerXml -Xml $xml -ForImport
Assert ($desired.TotalRules -eq 1 -and -not $desired.HasEnforcement) 'Audit-only rule must parse.'
Assert ((Get-WelaAppLockerXmlKey $xml) -ceq (Get-WelaAppLockerXmlKey ($xml.Replace('Type="Exe" EnforcementMode="AuditOnly"', 'EnforcementMode="AuditOnly" Type="Exe"')))) 'Attribute ordering cannot change compliance.'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('AuditOnly','Enabled')) -ForImport } 'AuditOnly'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('AuditOnly','NotConfigured')) -ForImport } 'AuditOnly'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml '<AppLockerPolicy Version="1" />' -ForImport } 'empty'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ('<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]>'+ $xml) -ForImport } 'DTD'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('</RuleCollection>', '<RuleCollectionExtensions /></RuleCollection>')) -ForImport } 'extensions'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('12345678-1234-1234-1234-123456789abc','not-a-guid')) -ForImport } 'IDs'
$implicit=ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('AuditOnly','NotConfigured'))
Assert ($implicit.HasEnforcement) 'NotConfigured with rules may enforce; never call it disabled.'
$parsedPlaceholders=ConvertFrom-WelaAppLockerXml -Xml $placeholders
Assert ($parsedPlaceholders.Collections.Count -eq 5 -and $parsedPlaceholders.EmptyPlaceholderCount -eq 5) 'Raw placeholder collections remain in assessment XML/metadata while all five are recognized as empty.'
Assert ($parsedPlaceholders.Xml -match 'NotConfigured' -and -not $parsedPlaceholders.HasEnforcement) 'Normalization never deletes the original policy evidence or fabricates enforcement.'
$commented=ConvertFrom-WelaAppLockerXml -Xml '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured"> <!-- native comment --> </RuleCollection></AppLockerPolicy>'
Assert ($commented.EmptyPlaceholderCount -eq 1) 'Whitespace and comments do not turn an otherwise empty collection into policy content.'
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml $placeholders -ForImport } 'AuditOnly'
function Reset-Fixture {
    $script:localXml='<AppLockerPolicy Version="1" />'; $script:effectiveXml=$script:localXml
    $script:serviceState='Running'; $script:serviceMode='Auto'; $script:channelEnabled=$true
    $script:domain=$false; $script:managed=@(); $script:unknownPolicy=$false; $script:writes=0; $script:readCount=0
    $script:race=$false; $script:reject=$false; $script:drift=$false; $script:tamper=$false; $script:validations=0
    $script:withPlaceholders=$false
}
function Get-WelaAppLockerHost { [pscustomobject]@{Status='Candidate'; Is64BitProcess=$true; PartOfDomain=$script:domain} }
function Get-WelaAppLockerManagement { [pscustomobject]@{Status='Observed'; ManagementEntries=$script:managed; CspPolicyState='Unknown'} }
function Get-WelaAppLockerService { [pscustomobject]@{Status='Observed'; State=$script:serviceState; StartMode=$script:serviceMode} }
function Get-WelaAppLockerChannels { foreach ($name in @('EXE and DLL','MSI and Script','Packaged app-Execution','Packaged app-Deployment')) { [pscustomobject]@{Channel="Microsoft-Windows-AppLocker/$name"; Status='Observed'; Enabled=$script:channelEnabled} } }
function Get-WelaAppLockerPolicySnapshot {
    param($Scope)
    if ($Scope -eq 'Local') {
        $script:readCount++
        if ($script:race -and $script:readCount -eq 2) { $script:localXml=$xml.Replace('AuditOnly','Enabled') }
        if ($script:drift -and $script:readCount -ge 5) { $script:localXml='<AppLockerPolicy Version="1" />' }
    }
    if ($script:unknownPolicy) { return [pscustomobject]@{Status='Unknown'; Policy=$null} }
    $value=if ($Scope -eq 'Local') {$script:localXml} else {$script:effectiveXml}
    [pscustomobject]@{Status='Observed'; Policy=(ConvertFrom-WelaAppLockerXml -Xml $value)}
}
$script:originalImportFile = ${function:New-WelaAppLockerImportReadLock}
function New-WelaAppLockerImportReadLock {
    param($Path,$Xml)
    if (-not $script:tamper) { return & $script:originalImportFile -Path $Path -Xml $Xml }
    # Simulate a file replaced before the read lock, without races or native policy calls.
    [IO.File]::WriteAllText($Path, $Xml.Replace('AuditOnly', 'Enabled').Replace('<Conditions>', '<Conditions>  '), (New-Object Text.UTF8Encoding($false)))
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
}
function Test-AppLockerPolicy { [CmdletBinding()]param($XmlPolicy,$Path,$User) $script:validations++; [pscustomobject]@{PolicyDecision='Allowed'} }
function Set-AppLockerPolicy {
    [CmdletBinding()]param($XmlPolicy,[switch]$Merge)
    if (-not $Merge) { throw 'Import must never replace a policy.' }
    $script:writes++
    if ($script:reject) { throw 'native rejected policy' }
    $script:localXml=[IO.File]::ReadAllText($XmlPolicy); $script:effectiveXml=$script:localXml
    if ($script:withPlaceholders) { $script:localXml=$readbackPlaceholders; $script:effectiveXml=$script:localXml }
}
Reset-Fixture
$empty=Get-WelaAppLockerReadiness
Assert (@($empty.Collections | Where-Object PrerequisiteState -ne MissingGpPolicy).Count -eq 0) 'Enabled channels without rules must retain a missing GP policy prerequisite.'
Assert ($empty.CspPolicyState -eq 'Unknown' -and $empty.UsableRuleCredit -eq 0) 'GP readback never establishes CSP or detection readiness.'
$script:localXml=$xml; $script:effectiveXml=$xml
$ready=Get-WelaAppLockerReadiness
Assert ($ready.Collections[0].PrerequisiteState -eq 'Conditional' -and $ready.Collections[0].GenerationReadiness -eq 'Unverified') 'Audit policy plus service/channel is only conditional.'
$script:serviceState='Stopped'; $script:serviceMode='Disabled'
Assert ((Get-WelaAppLockerReadiness).Collections[0].PrerequisiteState -eq 'ServiceNotRunning') 'Disabled service must be explicit.'
$script:serviceState='Running';$script:serviceMode='Auto';$script:channelEnabled=$false
Assert ((Get-WelaAppLockerReadiness).Collections[0].PrerequisiteState -eq 'ChannelDisabled') 'Disabled channel must be explicit.'
Reset-Fixture; $script:effectiveXml=$xml.Replace('AuditOnly','Enabled')
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'enforcement'
Reset-Fixture; $script:localXml=$xml.Replace('AuditOnly','NotConfigured')
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'enforcement'
Reset-Fixture; $script:domain=$true
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'domain-joined'
Reset-Fixture; $script:managed=@('MDM provider')
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'managed'
Reset-Fixture; $script:unknownPolicy=$true
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'readable'
Reset-Fixture; $script:localXml=$placeholders; $script:effectiveXml=$placeholders
Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'NotConfigured.*merge may retain'
Assert (-not (Test-WelaAppLockerPolicyMatch (Get-WelaAppLockerReadiness) $desired)) 'Empty placeholders do not satisfy a requested policy with rules.'
Reset-Fixture; $script:localXml=$unusedPlaceholders; $script:effectiveXml=$unusedPlaceholders
Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired
Assert (-not (Test-WelaAppLockerPolicyMatch (Get-WelaAppLockerReadiness) $desired)) 'Untargeted empty placeholders permit initialization without pretending that requested rules already exist.'
foreach ($scope in @('Local','Effective')) {
    Reset-Fixture
    if ($scope -eq 'Local') { $script:localXml=$placeholders } else { $script:effectiveXml=$placeholders }
    Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'NotConfigured.*merge may retain'
}
Reset-Fixture; $script:localXml=$readbackPlaceholders; $script:effectiveXml=$readbackPlaceholders
Assert (Test-WelaAppLockerPolicyMatch (Get-WelaAppLockerReadiness) $desired) 'One imported collection plus four empty placeholders matches the requested one-collection policy.'
Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired
# A RuleCount == 0 filter would incorrectly ignore each of these. Test both the
# initial local/effective guards and the post-import comparison against real XML.
$nonPlaceholders=@(
    '<RuleCollection Type="Dll" EnforcementMode="Enabled" />',
    '<RuleCollection Type="Dll" EnforcementMode="AuditOnly" />',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured"><RuleCollectionExtensions /></RuleCollection>',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured"><FutureRule /></RuleCollection>',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured" Future="" />',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured" Description="" />',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured">unknown content</RuleCollection>',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured"><![CDATA[unknown content]]></RuleCollection>',
    '<RuleCollection Type="Dll" EnforcementMode="NotConfigured"><?future data?></RuleCollection>',
    '<RuleCollection xmlns="urn:unknown" Type="Dll" EnforcementMode="NotConfigured" />',
    '<RuleCollection xmlns:x="urn:unknown" Type="Dll" EnforcementMode="NotConfigured" x:Future="" />',
    ($desired.Collections[0].Xml.Replace('Type="Exe"','Type="Dll"').Replace('AuditOnly','NotConfigured'))
)
foreach ($node in $nonPlaceholders) {
    $policyXml='<AppLockerPolicy Version="1">' + $node + '</AppLockerPolicy>'
    $parsed=ConvertFrom-WelaAppLockerXml -Xml $policyXml
    Assert ($parsed.EmptyPlaceholderCount -eq 0 -and -not $parsed.Collections[0].IsEmptyPlaceholder) 'Configured/unknown collection content is never normalized away.'
    foreach ($scope in @('Local','Effective')) {
        Reset-Fixture
        if ($scope -eq 'Local') { $script:localXml=$policyXml } else { $script:effectiveXml=$policyXml }
        Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'preserved'
    }
    Reset-Fixture; $script:localXml=$xml.Replace('</AppLockerPolicy>', $node + '</AppLockerPolicy>')
    Assert (-not (Test-WelaAppLockerPolicyMatch (Get-WelaAppLockerReadiness) $desired)) 'Unexpected configured/unknown collection fails readback even when the requested Exe rule matches.'
}
foreach ($policyXml in @($placeholders.Replace('Version="1"','Version="1" Future=""'), $placeholders.Replace('</AppLockerPolicy>','unknown content</AppLockerPolicy>'))) {
    Reset-Fixture; $script:localXml=$policyXml
    Assert-Throws { Assert-WelaAppLockerImportSafe (Get-WelaAppLockerReadiness) $desired } 'Unknown policy'
}
Assert-Throws { ConvertFrom-WelaAppLockerXml -Xml ($xml.Replace('Version="1"','Version="1" Future=""')) -ForImport } 'Unknown policy'
$cleanup=@()
try {
    foreach ($scenario in @('apply','dry','race','failure','drift','existing','tamper','placeholders','placeholder-dry','placeholder-drift','target-placeholder')) {
        Reset-Fixture
        if ($scenario -like 'placeholder*') { $script:localXml=$unusedPlaceholders; $script:effectiveXml=$unusedPlaceholders; $script:withPlaceholders=$true }
        if ($scenario -eq 'target-placeholder') { $script:localXml=$placeholders; $script:effectiveXml=$placeholders }
        if ($scenario -eq 'race') {$script:race=$true}
        if ($scenario -eq 'tamper') {$script:tamper=$true}
        if ($scenario -eq 'failure') {$script:reject=$true}
        if ($scenario -eq 'drift') {$script:drift=$true}
        if ($scenario -eq 'existing') {$script:localXml=$xml;$script:effectiveXml=$xml}
        $path=Join-Path ([IO.Path]::GetTempPath()) ('wela-applocker-'+[guid]::NewGuid().ToString('N'));$cleanup+=$path
        $context=New-WelaConfigurationContext -Auto -DryRun:($scenario -in @('dry','placeholder-dry')) -BackupPath $path
        Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
        if ($scenario -eq 'placeholder-drift') { $script:localXml=$readbackPlaceholders.Replace('Type="Dll" EnforcementMode="NotConfigured"','Type="Dll" EnforcementMode="AuditOnly"') }
        $result=Complete-WelaConfiguration -Context $context
        switch ($scenario) {
            'apply' {
                Assert ($script:writes -eq 1 -and $result.ExitCode -eq 0) 'Verified initial audit-only merge should pass.'
                Assert (Test-Path (Join-Path $path 'before.jsonl')) 'Recovery journal must precede merge.'
                Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
                Assert ($script:writes -eq 1 -and $context.Results[1].Status -eq 'AlreadyCompliant') 'Reapplying same policy should not write.'
            }
            'dry' { Assert ($script:writes -eq 0 -and -not (Test-Path $path)) 'Dry-run must not write policy or recovery files.' }
            'tamper' { Assert ($script:writes -eq 0 -and $script:validations -eq 0 -and $result.ExitCode -eq 1 -and $result.Results[0].Diagnostic -match 'changed before its read lock') 'Altered prepared XML must fail before native validation or import, including equal-length mode tampering.' }
            'race' { Assert ($script:writes -eq 0 -and $result.ExitCode -eq 1) 'Concurrent enforcement must block merge.' }
            'failure' { Assert ($result.ExitCode -eq 1) 'Native write failure must propagate.' }
            'drift' { Assert ($result.ExitCode -eq 1) 'Final readback must detect policy drift.' }
            'existing' { Assert ($script:writes -eq 0 -and $result.ExitCode -eq 0) 'Identical policy stays unchanged.' }
            'placeholders' {
                Assert ($script:writes -eq 1 -and $result.ExitCode -eq 0 -and $result.Results[0].Status -eq 'Applied') 'Public runner imports from empty placeholders and verifies populated readback with remaining placeholders.'
                $journal=Get-Content (Join-Path $path 'before.jsonl') | ConvertFrom-Json
                Assert ($journal.Before.LocalPolicy.Policy.Collections.Count -eq 4 -and $journal.Before.LocalPolicy.Policy.EmptyPlaceholderCount -eq 4) 'Recovery journal preserves all original unused placeholder collection metadata.'
                $export=$result | ConvertTo-Json -Depth 20 | ConvertFrom-Json
                Assert ($export.Results[0].After.LocalPolicy.Policy.Collections.Count -eq 5 -and $export.Results[0].After.LocalPolicy.Policy.EmptyPlaceholderCount -eq 4) 'Result JSON distinguishes the configured collection from four retained placeholders.'
                Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
                Assert ($script:writes -eq 1 -and $context.Results[1].Status -eq 'AlreadyCompliant') 'Repeated import with placeholders performs no duplicate merge.'
            }
            'placeholder-dry' { Assert ($script:writes -eq 0 -and -not (Test-Path $path) -and $result.Results[0].Status -eq 'Skipped') 'Placeholder normalization does not weaken dry-run guarantees.' }
            'placeholder-drift' { Assert ($script:writes -eq 1 -and $result.ExitCode -eq 1 -and $result.Results[0].Status -in @('Failed','Overridden')) 'Final drift from an empty placeholder into a configured empty collection remains a failure.' }
            'target-placeholder' { Assert ($script:writes -eq 0 -and $script:validations -eq 0 -and $result.ExitCode -eq 1 -and $result.Results[0].Diagnostic -match 'merge may retain NotConfigured') 'A targeted empty NotConfigured collection blocks before native import to avoid accidental enforcement.' }
        }
    }
    $path=Join-Path ([IO.Path]::GetTempPath()) ('wela-applocker-existing-'+[guid]::NewGuid().ToString('N')+'.xml');$cleanup+=$path
    [IO.File]::WriteAllText($path,'Existing unrelated file')
    $rejected=$false
    try { $stream=& $script:originalImportFile -Path $path -Xml $xml; $stream.Dispose() } catch { $rejected=$true }
    Assert ($rejected -and [IO.File]::ReadAllText($path) -eq 'Existing unrelated file') 'Prepared import creation cannot overwrite a pre-existing file/link.'
    # Execute only actual top-level option guards; no command dispatcher/mutator.
    $tokens=$null;$parseErrors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'),[ref]$tokens,[ref]$parseErrors)
    Assert ($parseErrors.Count -eq 0) 'CLI option guards parse.'
    $guard=$ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith("if ((`$PSBoundParameters.ContainsKey('AppLockerAction')") } | Select-Object -First 1
    Assert ($null -ne $guard) 'Explicit AppLocker options must be guarded before dispatch.'
    $exercise=[scriptblock]::Create('param($AppLockerAction,$AppLockerPolicyPath,$Cmd)' + [Environment]::NewLine + $guard.Extent.Text)
    Assert-Throws { & $exercise -AppLockerAction Plan -Cmd configure } 'require applocker-readiness'
    Assert-Throws { & $exercise -AppLockerPolicyPath 'operator.xml' -Cmd configure-sacl } 'require applocker-readiness'
    & $exercise -AppLockerAction Plan -Cmd applocker-readiness
    $guard=$ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.StartsWith("if (`$Cmd -eq 'applocker-readiness' -and (`$Profile") } | Select-Object -First 1
    $Cmd='applocker-readiness';$Profile='wela-2.2.0';$Baseline=$null
    Assert-Throws { & ([scriptblock]::Create($guard.Extent.Text)) } 'not -Profile or -Baseline'
} finally { foreach ($path in $cleanup) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue } }
Write-Host "PASS: $count AppLocker readiness/import assertions; no Windows policies changed."
