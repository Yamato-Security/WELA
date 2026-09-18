# Real catalog + public audit renderer/exports; Windows reads are injected at the OS boundary.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/RuleEligibility.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../modules/NativeProviders.psm1') -Force
$module = Get-Module NativeProviders
& $module {
    $script:channelReads = @()
    $script:appLockerError = $false
    $script:defenderError = $false
    $script:channelStates = @{
        'Microsoft-Windows-PrintService/Operational' = 'Disabled'
        'Microsoft-Windows-Bits-Client/Operational' = 'Denied'
        'Microsoft-Windows-DFSN-Server/Admin' = 'Absent'
        'Microsoft-Windows-AppLocker/MSI and Script' = 'Disabled'
        'Microsoft-Windows-Security-Mitigations/UserMode' = 'Disabled'
        'System' = 'AclDenied'
    }
    function script:Get-WinEvent {
        [CmdletBinding()]param($ListLog)
        $script:channelReads += $ListLog
        $state = $script:channelStates[$ListLog]
        if ($state -eq 'Denied') {
            $exception = [UnauthorizedAccessException]::new('Access denied <provider-test>')
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($exception, 'UnauthorizedAccess', 'PermissionDenied', $ListLog))
        }
        if ($state -eq 'Absent') {
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([Exception]::new('No matching channel'), 'NoMatchingLogsFound', 'ObjectNotFound', $ListLog))
        }
        $log = [pscustomobject]@{
            LogName = $ListLog; IsEnabled = ($state -ne 'Disabled'); LogMode = 'Circular'
            SecurityDescriptor = 'O:BAG:SYD:(A;;0x1;;;SY)'; MaximumSizeInBytes = 1048576; ProviderNames = @('Fixture provider')
        }
        if ($state -eq 'AclDenied') {
            $log.PSObject.Properties.Remove('SecurityDescriptor')
            $log | Add-Member -MemberType ScriptProperty -Name SecurityDescriptor -Value { throw [UnauthorizedAccessException]::new('ACL denied') }
        }
        $log
    }
    function script:Get-Service { [CmdletBinding()]param($Name) [pscustomobject]@{ Name = $Name; Status = 'Running' } }
    function script:Get-AppLockerPolicy {
        [CmdletBinding()]param([switch]$Effective, [switch]$Xml)
        if ($script:appLockerError) { throw [UnauthorizedAccessException]::new('AppLocker policy denied') }
        '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="test" /></RuleCollection><RuleCollection Type="Script" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
    }
    function script:Get-MpComputerStatus {
        [CmdletBinding()]param()
        if ($script:defenderError) { throw 'Defender cmdlet unavailable' }
        [pscustomobject]@{ AMRunningMode = 'Passive'; AMServiceEnabled = $true; AntivirusEnabled = $false; RealTimeProtectionEnabled = $false; BehaviorMonitorEnabled = $false; NISEnabled = $false }
    }
    function script:Get-CimInstance { [CmdletBinding()]param($ClassName) [pscustomobject]@{ ProductType = 3 } }
    function script:Get-Item {
        [CmdletBinding()]param($LiteralPath)
        $key = [pscustomobject]@{}
        $key | Add-Member ScriptMethod GetValueNames { @('RestrictSendingNTLMTraffic', 'AuditReceivingNTLMTraffic', 'AuditNTLMInDomain') }
        $key | Add-Member ScriptMethod GetValueKind { param($Name) 'DWord' }
        $key | Add-Member ScriptMethod GetValue { param($Name) if ($Name -eq 'AuditNTLMInDomain') { 7 } elseif ($Name -eq 'AuditReceivingNTLMTraffic') { 2 } else { 1 } }
        $key
    }
}
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../WELA.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$class = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.TypeDefinitionAst] -and $node.Name -eq 'WELA' }, $true)
. ([scriptblock]::Create($class.Extent.Text))
foreach ($name in @('AsArray', 'RuleFilter', 'ApplyRules', 'GetBaselineConfig', 'BuildAuditResult', 'AuditLogSetting')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:assertions = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message. Expected '$Expected', got '$Actual'." }
    $script:assertions++
}
function TestAdministrator { $true }
function CollectAuditpol { param([switch]$UseCached) $true }
function GetAuditpol { @{ '0CCE9215-69AE-11D9-BED3-505054503030' = 'Success' } }
function CheckRegistryValue { param($registryPath, $valueName, $expectedValue) $false }
function Get-WelaOutgoingNtlmState { [pscustomobject]@{ Description = 'Audit all (1)'; PolicySource = 'Injected observation' } }
function Get-WelaDomainNtlmState { [pscustomobject]@{ Description = 'Not applicable (member server)' } }
function Export-MitreHeatmap { param($sigmaRules, $OutputPath, $UseIdealCount) $script:heatmapRules = @($sigmaRules) }

$script:BaselineConfigPath = Join-Path $PSScriptRoot '../config/baselines.json'
$script:ScriptRoot = Join-Path ([IO.Path]::GetTempPath()) ('wela-native-provider-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:ScriptRoot
$script:SecurityRulesPath = Join-Path $script:ScriptRoot 'rules.json'
try {
    # Exercise the real corpus's rule-side wildcard against the exact catalog
    # selectors, through the public CSV/JSON/HTML assessment path.
    $corpus = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../config/security_rules.json') -Raw | ConvertFrom-Json
    # Explicitly enumerate the parsed array on Windows PowerShell 5.1 as well.
    $wildcardRules = @($corpus | Where-Object { $_.channel -contains 'Microsoft-Windows-Security-Mitigations*' })
    Assert-Equal ($wildcardRules.Count -gt 0) $true 'Real Security-Mitigations wildcard rules are present'
    $fixtures = @(
        @{ id = 'application'; channel = @('Application') }
        @{ id = 'print'; channel = @('Microsoft-Windows-PrintService/Operational') }
        @{ id = 'denied'; channel = @('Microsoft-Windows-Bits-Client/Operational') }
        @{ id = 'absent'; channel = @('Microsoft-Windows-DFSN-Server/Admin') }
        @{ id = 'app-exe'; channel = @('Microsoft-Windows-AppLocker/EXE and DLL') }
        @{ id = 'app-script'; channel = @('Microsoft-Windows-AppLocker/MSI and Script') }
        @{ id = 'ntlm'; channel = @('Microsoft-Windows-NTLM/Operational') }
        @{ id = 'defender'; channel = @('Microsoft-Windows-Windows Defender/Operational') }
        @{ id = 'classic'; channel = @('pwsh'); event_ids = @('400') }
        @{ id = 'mitigation-kernel'; channel = @('Microsoft-Windows-Security-Mitigations/KernelMode') }
        @{ id = 'mitigation-user'; channel = @('Microsoft-Windows-Security-Mitigations/UserMode') }
        @{ id = 'security'; channel = @('sec'); subcategory_guids = @('0CCE9215-69AE-11D9-BED3-505054503030') }
    )
    foreach ($rule in $wildcardRules) {
        $fixtures += @{ id = $rule.id; channel = @($rule.channel); event_ids = @($rule.event_ids) }
    }
    foreach ($rule in $fixtures) {
        $rule.level = 'medium'; $rule.title = $rule.id
        if (-not $rule.ContainsKey('event_ids')) { $rule.event_ids = @() }
        if (-not $rule.ContainsKey('subcategory_guids')) { $rule.subcategory_guids = @() }
    }
    $fixtures | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:SecurityRulesPath -Encoding UTF8
    $jsonPath = Join-Path $script:ScriptRoot 'assessment.json'
    $htmlPath = Join-Path $script:ScriptRoot 'assessment.html'
    $output = AuditLogSetting -outType std -Baseline Microsoft_Server -ResultsPath $jsonPath -HtmlPath $htmlPath 6>&1 | Out-String
    $report = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $rows = @($report.Results | Where-Object { $_.NativeSources.Count -gt 0 })
    $sources = @($rows | ForEach-Object { $_.NativeSources })
    $expectedDefinitions = @((GetBaselineConfig).catalog | Where-Object { $_.currentSetting.type -eq 'native-channel' })
    Assert-Equal @((GetBaselineConfig).catalog | Where-Object { $_.currentSetting.type -eq 'static' }).Count 0 'No catalog entry retains a static Enabled claim'
    Assert-Equal $rows.Count $expectedDefinitions.Count 'Every native catalog entry appears in public JSON output'
    foreach ($definition in $expectedDefinitions) {
        foreach ($name in $definition.currentSetting.channels) {
            Assert-Equal ($sources.Channel.Name -contains $name) $true "Actual source $name is observed"
        }
    }
    $print = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-PrintService/Operational' }
    Assert-Equal $print.Channel.State 'Disabled' 'Former static PrintService channel is disabled'
    Assert-Equal (($rows | Where-Object { $_.NativeSources.Channel.Name -contains 'Microsoft-Windows-PrintService/Operational' }).CurrentSetting) 'Disabled' 'Disabled state survives public report'
    $denied = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-Bits-Client/Operational' }
    Assert-Equal $denied.Channel.State 'Unknown' 'Access denied is unknown, never absent or disabled'
    Assert-Equal $denied.Channel.Error.Category 'PermissionDenied' 'Access denied retains its reason'
    $absent = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-DFSN-Server/Admin' }
    Assert-Equal $absent.Channel.State 'Not installed' 'Missing registration is distinguished from denied access'
    $app = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-AppLocker/EXE and DLL' }
    Assert-Equal $app.Channel.State 'Enabled' 'AppLocker channel availability is separately visible'
    Assert-Equal $app.Provider.Readiness 'Conditional' 'AppLocker channel and GP rules do not prove all event prerequisites'
    Assert-Equal $app.Provider.Observations.Collections[0].EnforcementMode 'AuditOnly' 'Effective GP collection mode is retained'
    Assert-Equal $app.Provider.Observations.Collections[0].RuleCount 1 'Effective GP rule count is retained'
    Assert-Equal $app.Provider.Observations.Service.State 'Running' 'Application Identity service state is retained'
    Assert-Equal ($app.Provider.Evidence -join ' ' -match 'CSP') $true 'CSP blind spot is explicit'
    Assert-Equal ($app.MappedRuleIds -contains 'app-exe') $true 'EXE rule maps to its actual channel'
    Assert-Equal ($app.MappedRuleIds -contains 'app-script') $false 'Enabled EXE channel does not inherit MSI/Script rules'
    $scriptSource = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-AppLocker/MSI and Script' }
    Assert-Equal $scriptSource.Channel.State 'Disabled' 'Disabled sibling channel remains disabled'
    Assert-Equal ($scriptSource.MappedRuleIds -contains 'app-script') $true 'Disabled sibling retains its source mapping'
    $ntlm = $sources | Where-Object { $_.Provider.Name -eq 'NTLM' }
    Assert-Equal $ntlm.Provider.Observations.Outgoing.Type 'DWord' 'NTLM switch type retained'
    Assert-Equal $ntlm.Provider.Observations.Outgoing.Value 1 'Outgoing NTLM switch observed separately'
    Assert-Equal $ntlm.Provider.Observations.Incoming.Value 2 'Incoming NTLM switch observed separately'
    Assert-Equal $ntlm.Provider.Observations.Domain.State 'Not applicable' 'Domain NTLM applies only to DCs'
    $defender = $sources | Where-Object { $_.Provider.Name -eq 'Defender' }
    Assert-Equal $defender.Provider.Observations.Status.AMRunningMode 'Passive' 'Defender passive mode is preserved'
    Assert-Equal $defender.Provider.Observations.Status.RealTimeProtectionEnabled $false 'Disabled Defender protection remains explicit'
    Assert-Equal $defender.Provider.Readiness 'Conditional' 'Defender event generation is not inferred from a channel'
    Assert-Equal $app.Channel.LogMode 'Circular' 'Channel log mode survives JSON'
    Assert-Equal $app.Channel.SecurityDescriptor 'O:BAG:SYD:(A;;0x1;;;SY)' 'Channel ACL survives JSON'
    $system = $sources | Where-Object { $_.Channel.Name -eq 'System' }
    Assert-Equal $system.Channel.State 'Enabled' 'Unreadable ACL does not erase separately observed channel state'
    Assert-Equal ($null -ne $system.Channel.MetadataErrors.SecurityDescriptor) $true 'Unreadable ACL metadata is preserved'
    $classic = $sources | Where-Object { $_.Channel.Name -eq 'Windows PowerShell' }
    Assert-Equal ($classic.MappedRuleIds -contains 'classic') $true 'Classic PowerShell alias maps to its real channel'
    $kernel = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-Security-Mitigations/KernelMode' }
    $user = $sources | Where-Object { $_.Channel.Name -eq 'Microsoft-Windows-Security-Mitigations/UserMode' }
    Assert-Equal ($kernel.MappedRuleIds -contains 'mitigation-kernel') $true 'Exact mitigation channel matches its concrete catalog selector'
    Assert-Equal ($kernel.MappedRuleIds -contains 'mitigation-user') $false 'Kernel mitigation source does not inherit user-mode rules'
    Assert-Equal ($user.MappedRuleIds -contains 'mitigation-user') $true 'User mitigation source retains its exact rule'
    Assert-Equal ($user.MappedRuleIds -contains 'mitigation-kernel') $false 'User mitigation source does not inherit kernel rules'
    foreach ($rule in $wildcardRules) {
        Assert-Equal ($kernel.MappedRuleIds -contains $rule.id) $true 'Rule-side wildcard maps to the concrete KernelMode source'
        Assert-Equal ($user.MappedRuleIds -contains $rule.id) $true 'Rule-side wildcard maps to the concrete UserMode source'
        Assert-Equal (RuleFilter $rule @('999') @($kernel.Channel.Name) '') $false 'A wildcard channel match still requires the selected event ID'
        Assert-Equal (RuleFilter $rule @($rule.event_ids[0]) @($kernel.Channel.Name) '') $true 'Matching channel and event ID pass together'
    }
    foreach ($source in @($kernel, $user)) {
        Assert-Equal (($rows | Where-Object { $_.NativeSources.Channel.Name -contains $source.Channel.Name }).RuleCount) (1 + $wildcardRules.Count) 'Each category includes exact and wildcard rules without unrelated sibling rules'
    }
    Assert-Equal @(& $module { $script:channelReads | Where-Object { $_ -match '[*?]' } }).Count 0 'Wildcard rules never trigger wildcard native channel reads'
    Assert-Equal $report.Coverage.TotalRules $fixtures.Count 'Rules mapped to both native sources appear once in the full denominator'
    Assert-Equal $report.Coverage.UsableRules 0 'Enabled Security settings do not establish complete rule readiness'
    Assert-Equal @(Import-Csv (Join-Path $script:ScriptRoot 'UsableRules.csv')).Count 0 'Usable CSV matches conservative JSON coverage'
    Assert-Equal @(Import-Csv (Join-Path $script:ScriptRoot 'UnusableRules.csv')).Count $fixtures.Count 'Unconfirmed native rules are retained once in CSV'
    Assert-Equal @($script:heatmapRules | Where-Object { $_.id -ne 'security' -and ($_.applicable -or $_.ideal) }).Count 0 'No current or ideal native provider uplift is fabricated'
    $html = Get-Content -LiteralPath $htmlPath -Raw
    Assert-Equal ($html -match 'Not installed') $true 'HTML retains absent-feature state'
    Assert-Equal ($html -match 'PermissionDenied') $true 'HTML retains denied-access reason'
    # Windows PowerShell JSON escapes angle brackets as Unicode; PowerShell 7 may
    # leave them for HtmlEncode. Both must safely preserve the original evidence.
    $htmlRows = @([regex]::Matches($html, '(?s)<pre>(.*?)</pre>') | ForEach-Object {
        [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) | ConvertFrom-Json
    })
    $htmlErrorText = ($htmlRows | ForEach-Object { $_.NativeSources.Channel.Error.Message }) -join ' '
    Assert-Equal ($htmlErrorText -match '<provider-test>') $true 'HTML encoding preserves untrusted error text'
    Assert-Equal ($html -match '<provider-test>') $false 'HTML never interprets error text as markup'
    Assert-Equal ($output -match '(?m)^Applocker: Conditional') $true 'Console does not summarize AppLocker as enabled'
    Assert-Equal ($output -match 'Native provider rules remain unconfirmed') $true 'Console explains conservative coverage'
    $csv = @(Import-Csv (Join-Path $script:ScriptRoot 'WELA-Audit-Result.csv'))
    Assert-Equal (($csv | Where-Object Category -eq 'Applocker').NativeSourceEvidence -match 'SecurityDescriptor') $true 'CSV preserves structured native evidence'

    & $module { $script:appLockerError = $true; $script:defenderError = $true }
    $null = AuditLogSetting -outType table -Baseline Microsoft_Server -ResultsPath $jsonPath -HtmlPath $htmlPath
    $failed = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $failedSources = @($failed.Results | ForEach-Object { $_.NativeSources })
    foreach ($name in @('AppLocker', 'Defender')) {
        $provider = @($failedSources | Where-Object { $_.Provider.Name -eq $name })[0].Provider
        Assert-Equal $provider.Readiness 'Unknown' "$name provider read failures are not confused with ready state"
        Assert-Equal ([bool]$provider.Error.Message) $true "$name provider read failure retains evidence"
        Assert-Equal @($failed.Results | Where-Object { $_.NativeSources.Provider.Name -contains $name -and $_.CurrentSetting -ne 'Unknown' }).Count 0 "$name read failure is visible in the row state"
    }
    Assert-Equal $failed.Coverage.UsableRules 0 'Provider read failures do not inflate rule coverage'
    Write-Host "PASS: $script:assertions native provider/output assertions; no Windows settings changed."
} finally {
    Remove-Item -LiteralPath $script:ScriptRoot -Recurse -Force
    Remove-Module NativeProviders
}
