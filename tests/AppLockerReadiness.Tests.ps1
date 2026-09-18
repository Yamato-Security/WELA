$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/Configuration.ps1')
. (Join-Path $PSScriptRoot '../scripts/AppLockerReadiness.ps1')
$count=0
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message }; $script:count++ }
function Assert-Throws([scriptblock]$Action,$Pattern) { $message=''; try { & $Action | Out-Null } catch { $message=$_.Exception.Message }; Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'." }
$xml='<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="12345678-1234-1234-1234-123456789abc" Name="Test" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
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
function Reset-Fixture {
    $script:localXml='<AppLockerPolicy Version="1" />'; $script:effectiveXml=$script:localXml
    $script:serviceState='Running'; $script:serviceMode='Auto'; $script:channelEnabled=$true
    $script:domain=$false; $script:managed=@(); $script:unknownPolicy=$false; $script:writes=0; $script:readCount=0
    $script:race=$false; $script:reject=$false; $script:drift=$false
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
function Test-AppLockerPolicy { [CmdletBinding()]param($XmlPolicy,$Path,$User) [pscustomobject]@{PolicyDecision='Allowed'} }
function Set-AppLockerPolicy {
    [CmdletBinding()]param($XmlPolicy,[switch]$Merge)
    if (-not $Merge) { throw 'Import must never replace a policy.' }
    $script:writes++
    if ($script:reject) { throw 'native rejected policy' }
    $script:localXml=[IO.File]::ReadAllText($XmlPolicy); $script:effectiveXml=$script:localXml
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
$cleanup=@()
try {
    foreach ($scenario in @('apply','dry','race','failure','drift','existing')) {
        Reset-Fixture
        if ($scenario -eq 'race') {$script:race=$true}
        if ($scenario -eq 'failure') {$script:reject=$true}
        if ($scenario -eq 'drift') {$script:drift=$true}
        if ($scenario -eq 'existing') {$script:localXml=$xml;$script:effectiveXml=$xml}
        $path=Join-Path ([IO.Path]::GetTempPath()) ('wela-applocker-'+[guid]::NewGuid().ToString('N'));$cleanup+=$path
        $context=New-WelaConfigurationContext -Auto -DryRun:($scenario -eq 'dry') -BackupPath $path
        Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
        $result=Complete-WelaConfiguration -Context $context
        switch ($scenario) {
            'apply' {
                Assert ($script:writes -eq 1 -and $result.ExitCode -eq 0) 'Verified initial audit-only merge should pass.'
                Assert (Test-Path (Join-Path $path 'before.jsonl')) 'Recovery journal must precede merge.'
                Set-WelaAppLockerAuditPolicy -Context $context -Desired $desired
                Assert ($script:writes -eq 1 -and $context.Results[1].Status -eq 'AlreadyCompliant') 'Reapplying same policy should not write.'
            }
            'dry' { Assert ($script:writes -eq 0 -and -not (Test-Path $path)) 'Dry-run must not write policy or recovery files.' }
            'race' { Assert ($script:writes -eq 0 -and $result.ExitCode -eq 1) 'Concurrent enforcement must block merge.' }
            'failure' { Assert ($result.ExitCode -eq 1) 'Native write failure must propagate.' }
            'drift' { Assert ($result.ExitCode -eq 1) 'Final readback must detect policy drift.' }
            'existing' { Assert ($script:writes -eq 0 -and $result.ExitCode -eq 0) 'Identical policy stays unchanged.' }
        }
    }
} finally { foreach ($path in $cleanup) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue } }
Write-Host "PASS: $count AppLocker readiness/import assertions; no Windows policies changed."
