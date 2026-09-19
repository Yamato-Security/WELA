# Native Windows observations only. This module never changes policy, services or logs.
function Get-WelaNativeReadError {
    param([System.Management.Automation.ErrorRecord]$Record)
    [pscustomobject]@{
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Message = $Record.Exception.Message
    }
}

function Get-WelaNativeChannel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $result = [ordered]@{
        Name = $Name; State = 'Unknown'; IsEnabled = $null
        LogMode = $null; SecurityDescriptor = $null; MaximumSizeInBytes = $null
        ProviderNames = @(); MetadataErrors = @{}; Error = $null
    }
    try {
        # Catalog entries use exact names: an accessible sibling must not hide an error.
        $logs = @(Get-WinEvent -ListLog $Name -ErrorAction Stop | Where-Object LogName -eq $Name)
        if ($logs.Count -eq 0) {
            $result.State = 'Not installed'
            $result.Error = [pscustomobject]@{ Id = 'ChannelNotRegistered'; Category = 'ObjectNotFound'; Message = 'No matching channel registration was returned.' }
        } elseif ($logs.Count -ne 1) {
            throw "Multiple channel registrations returned for '$Name'."
        } else {
            $log = $logs[0]
            foreach ($property in @('IsEnabled', 'LogMode', 'SecurityDescriptor', 'MaximumSizeInBytes', 'ProviderNames')) {
                try {
                    $value = $log.$property
                    if ($null -eq $value) { throw "Channel metadata '$property' was not returned." }
                    $result[$property] = if ($property -in @('LogMode', 'SecurityDescriptor')) { [string]$value } else { $value }
                } catch { $result.MetadataErrors[$property] = Get-WelaNativeReadError $_ }
            }
            if ($result.IsEnabled -is [bool]) { $result.State = if ($result.IsEnabled) { 'Enabled' } else { 'Disabled' } }
        }
    } catch {
        $result.Error = Get-WelaNativeReadError $_
        # Missing registration is different from denied access or an unavailable cmdlet.
        if ($_.FullyQualifiedErrorId -match '^NoMatchingLogsFound(,|$)' -or
            $_.Exception.GetType().FullName -eq 'System.Diagnostics.Eventing.Reader.EventLogNotFoundException') {
            $result.State = 'Not installed'
        }
    }
    [pscustomobject]$result
}

function Get-WelaNativeService {
    param([string]$Name)
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        [pscustomobject]@{ Name = $Name; State = [string]$service.Status; Error = $null }
    } catch {
        $state = if ($_.FullyQualifiedErrorId -match '^NoServiceFoundForGivenName(,|$)') { 'Not installed' } else { 'Unknown' }
        [pscustomobject]@{ Name = $Name; State = $state; Error = Get-WelaNativeReadError $_ }
    }
}

function Get-WelaNativeRegistryValue {
    param([string]$Path, [string]$Name)
    $result = [ordered]@{ Path = $Path; Name = $Name; State = 'Unknown'; Type = $null; Value = $null; Error = $null }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $Name) { $result.State = 'Not configured' }
        else {
            $result.Type = $key.GetValueKind($Name).ToString()
            $result.Value = $key.GetValue($Name)
            $result.State = if ($result.Type -eq 'DWord') { 'Observed' } else { 'Unknown' }
        }
    } catch {
        $result.Error = Get-WelaNativeReadError $_
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound' -and $_.Exception -is [System.Management.Automation.ItemNotFoundException]) {
            $result.State = 'Not configured'
        }
    }
    [pscustomobject]$result
}

function Get-WelaNativeProvider {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Provider)
    $result = [ordered]@{
        Name = $Provider; Readiness = 'Conditional'; Evidence = @(); Observations = @{}
        Error = $null; EventGenerationVerified = $false
    }
    switch ($Provider) {
        'AppLocker' {
            $result.Observations.Service = Get-WelaNativeService AppIDSvc
            $result.Evidence += 'Application Identity service and GP effective rule collections are observed; AppLocker CSP policies are not visible to Get-AppLockerPolicy.'
            try {
                $xml = New-Object System.Xml.XmlDocument
                $xml.XmlResolver = $null
                $xml.LoadXml([string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop))
                if ($xml.DocumentElement.Name -ne 'AppLockerPolicy') { throw 'Unexpected AppLocker policy document.' }
                $result.Observations.Collections = @($xml.AppLockerPolicy.RuleCollection | ForEach-Object {
                    [pscustomobject]@{
                        Type = [string]$_.Type; EnforcementMode = [string]$_.EnforcementMode
                        RuleCount = @($_.ChildNodes | Where-Object { $_.Name -in @('FilePathRule', 'FileHashRule', 'FilePublisherRule') }).Count
                    }
                })
                $result.Evidence += 'GP collection mode/rules do not establish per-rule event generation, effective CSP policy, or every collection in a shared channel.'
            } catch { $result.Readiness = 'Unknown'; $result.Error = Get-WelaNativeReadError $_ }
        }
        'NTLM' {
            $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            $result.Observations.Outgoing = Get-WelaNativeRegistryValue $lsa 'RestrictSendingNTLMTraffic'
            $result.Observations.Incoming = Get-WelaNativeRegistryValue $lsa 'AuditReceivingNTLMTraffic'
            try {
                $productType = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
                if ($productType -notin @(1, 2, 3)) { throw 'Windows ProductType could not be determined.' }
                $result.Observations.ProductType = $productType
                $result.Observations.Domain = if ($productType -eq 2) {
                    Get-WelaNativeRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain'
                } else { [pscustomobject]@{ State = 'Not applicable'; Evidence = 'Domain NTLM auditing applies only to domain controllers.' } }
            } catch { $result.Readiness = 'Unknown'; $result.Error = Get-WelaNativeReadError $_ }
            $result.Evidence += 'Outgoing, incoming and domain policies cover different traffic. DWORD observations are not interchangeable; exceptions, authentication activity and event-specific prerequisites require validation.'
            if (@($result.Observations.Values | Where-Object { $_.State -eq 'Unknown' }).Count) { $result.Readiness = 'Unknown' }
        }
        'Defender' {
            $result.Observations.Service = Get-WelaNativeService WinDefend
            try {
                $status = Get-MpComputerStatus -ErrorAction Stop
                if ($null -eq $status) { throw 'Defender status was not returned.' }
                $result.Observations.Status = $status | Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, NISEnabled
            } catch { $result.Readiness = 'Unknown'; $result.Error = Get-WelaNativeReadError $_ }
            $result.Evidence += 'Active/passive mode and protection flags are observations, not proof of ASR, network protection, controlled folder access, or every Defender event prerequisite.'
        }
        'PowerShellClassic' {
            $result.Evidence += 'Windows PowerShell classic channel only; PowerShell 7 and session-specific logging preferences are not inferred from this registration.'
        }
        default {
            $serviceNames = @{
                BITS = 'BITS'; PrintService = 'Spooler'; WMI = 'Winmgmt'; TerminalServices = 'TermService'
                DFSN = 'Dfs'; Firewall = 'MpsSvc'; SMBClient = 'LanmanWorkstation'; TaskScheduler = 'Schedule'
            }
            if ($serviceNames.ContainsKey($Provider)) { $result.Observations.Service = Get-WelaNativeService $serviceNames[$Provider] }
            $result.Evidence += 'Channel registration and service state do not prove provider policy, event-specific prerequisites, activity, or detection-rule fields.'
        }
    }
    if ($result.Observations.Service -and $result.Observations.Service.State -eq 'Unknown') { $result.Readiness = 'Unknown' }
    [pscustomobject]$result
}

function Get-WelaNativeSources {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Definition, [array]$Rules = @(), [hashtable]$Cache = @{})
    $providerKey = 'provider:' + $Definition.provider
    if (-not $Cache.ContainsKey($providerKey)) { $Cache[$providerKey] = Get-WelaNativeProvider $Definition.provider }
    foreach ($channel in $Definition.channels) {
        $channelKey = 'channel:' + $channel
        if (-not $Cache.ContainsKey($channelKey)) { $Cache[$channelKey] = Get-WelaNativeChannel $channel }
        $matchedRules = @($Rules | Where-Object {
            $matchesSource = $false
            foreach ($ruleChannel in $_.channel) {
                if ($channel -like $ruleChannel -or ($ruleChannel -eq 'pwsh' -and $channel -eq 'Windows PowerShell')) { $matchesSource = $true }
            }
            $matchesSource
        })
        [pscustomobject]@{
            Channel = $Cache[$channelKey]; Provider = $Cache[$providerKey]
            MappedRuleIds = @($matchedRules | Select-Object -ExpandProperty id -Unique)
            RuleCoverage = 'Unconfirmed'
            Evidence = 'A mapped source is a candidate, not proof that the rule event and required fields will be generated. No usable-rule credit is assigned from channel enablement alone.'
        }
    }
}

function Get-WelaNativeSourceState {
    param([array]$Sources)
    $states = @($Sources | ForEach-Object { $_.Channel.State } | Select-Object -Unique)
    if ($states.Count -eq 1 -and $states[0] -ne 'Enabled') { return $states[0] }
    if ($states -contains 'Unknown' -or @($Sources | Where-Object { $_.Provider.Readiness -eq 'Unknown' }).Count) { return 'Unknown' }
    if ($states -contains 'Enabled') { return 'Conditional' }
    return 'Unknown'
}

function Export-WelaAuditAssessment {
    [CmdletBinding()]
    param([array]$Rows, [array]$Rules, [string]$Baseline, [string]$ResultsPath, [string]$HtmlPath, $Eligibility)
    $report = [pscustomobject][ordered]@{
        SchemaVersion = 1; AssessedAtUtc = [DateTime]::UtcNow.ToString('o'); Baseline = $Baseline
        Scope = 'Built-in Windows functionality; Sysmon and external telemetry are excluded.'
        Coverage = [pscustomobject]@{
            TotalRules = @($Rules).Count
            UsableRules = @($Rules | Where-Object applicable -eq $true).Count
            Note = 'Only evidence-qualified Ready rules are usable. Policy/channel matches are configuration estimates; missing full rule logic, fields, outcomes, SACL, ingestion or query evidence remains Conditional.'
        }
        Eligibility = $Eligibility
        Results = @($Rows | Select-Object Category, SubCategory, CurrentSetting, DefaultSetting, DefaultEvidence, LegacyDefaultHint, RecommendedSetting, RuleCount, ChannelState, GenerationReadiness, NativeSources, Note)
    }
    if ($ResultsPath) { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
    if ($HtmlPath) {
        $parts = @('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WELA audit assessment</title><style>body{font:16px sans-serif;max-width:1100px;margin:2rem auto;padding:1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1rem}section{border-top:1px solid #ccc;margin-top:2rem}</style></head><body><h1>WELA audit assessment</h1>')
        $parts += '<p>' + [System.Net.WebUtility]::HtmlEncode($report.Scope) + '</p>'
        $parts += '<p>' + [System.Net.WebUtility]::HtmlEncode($report.Coverage.Note) + '</p>'
        if ($Eligibility) {
            $parts += '<h2>Rule eligibility</h2><pre>' + [System.Net.WebUtility]::HtmlEncode(($Eligibility.Summary | ConvertTo-Json -Depth 6)) + '</pre>'
            $parts += '<details><summary>All rule states and reasons</summary><pre>' + [System.Net.WebUtility]::HtmlEncode(($Eligibility.Results | ConvertTo-Json -Depth 8)) + '</pre></details>'
        }
        foreach ($row in $report.Results) {
            $parts += '<section><h2>' + [System.Net.WebUtility]::HtmlEncode(($row.Category + ' / ' + $row.SubCategory)) + '</h2><pre>'
            $parts += [System.Net.WebUtility]::HtmlEncode(($row | ConvertTo-Json -Depth 14))
            $parts += '</pre></section>'
        }
        $parts += '</body></html>'
        $parts -join "`n" | Set-Content -LiteralPath $HtmlPath -Encoding UTF8 -ErrorAction Stop
    }
}

Export-ModuleMember -Function Get-WelaNativeChannel, Get-WelaNativeProvider, Get-WelaNativeSources, Get-WelaNativeSourceState, Export-WelaAuditAssessment
