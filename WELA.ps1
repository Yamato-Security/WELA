param (
    [string]$Cmd,
    [string]$OutType = "std",
    [bool]$Debug = $false,
    [string]$Baseline,
    [switch]$Auto,
    [switch]$Help
)

class WELA {
    static [array] $Levels = @('critical', 'high', 'medium', 'low', 'informational')
    [string] $Category
    [string] $SubCategory
    [string] $CurrentSetting = ""
    [array] $Rules
    [hashtable] $RulesCount
    [string] $DefaultSetting = ""
    [string] $RecommendedSetting = ""
    [string] $Volume = ""
    [string] $Note = ""

    WELA([string] $Category, [string] $SubCategory, [String] $CurrentSetting, [array] $Rules) {
        $this.Category = $Category
        $this.SubCategory = $SubCategory
        $this.CurrentSetting = $CurrentSetting
        $this.Rules = $Rules
        $this.RulesCount = @{'critical' = 0; 'high' = 0; 'medium' = 0; 'low' = 0; 'informational' = 0}
    }


    WELA([string] $Category, [string] $SubCategory, [string] $CurrentSetting, [array] $Rules, [string] $DefaultSetting, [string] $RecommendedSetting, [string] $Volume, [string] $Note) {
        $this.Category = $Category
        $this.SubCategory = $SubCategory
        $this.CurrentSetting = $CurrentSetting
        $this.Rules = $Rules
        $this.DefaultSetting = $DefaultSetting
        $this.RecommendedSetting = $RecommendedSetting
        $this.Volume = $Volume
        $this.Note = $Note
        $this.RulesCount = @{'critical' = 0; 'high' = 0; 'medium' = 0; 'low' = 0; 'informational' = 0}
    }

    [void] SetApplicable([array] $Enabledguid) {
        if ($this.CurrentSetting -ne "No Auditing") {
            foreach ($rule in $this.Rules) {
                $rule.applicable = $true
            }
            return
        }
        foreach ($rule in $this.Rules) {
            $rule.applicable = $false
            foreach ($guid in $rule.subcategory_guid) {
                if ($Enabledguid -contains $guid) {
                    $rule.applicable = $true
                    break
                }
            }
        }
    }

    [void] CountByLevel() {
        $this.RulesCount = @{}
        foreach ($level in [WELA]::Levels) {
            $this.RulesCount[$level] = @($this.Rules | Where-Object { $_.level -eq $level }).Count
        }
    }

    [void] Output([string] $Format) {
        switch ($Format.ToLower()) {
            "std" {
                $color = if ($this.CurrentSetting -eq "Enabled" -or $this.CurrentSetting -contains "Success" -or $this.CurrentSetting -contains "Failure") { "Green" } else { "Red" }
                $ruleCounts = ""
                $logEnabled = $this.CurrentSetting
                $allZero = ($this.RulesCount.Values | Where-Object { $_ -ne 0 }).Count
                if ($allZero -eq 0) {
                    $ruleCounts = "(no rules)"
                    $color = "DarkYellow"
                } else {
                    $ruleCounts = "$($logEnabled) ("
                    foreach ($level in [WELA]::Levels) {
                        $count = $this.RulesCount[$level]
                        if (-not $count) {
                            $count = 0 # 明示的に0を設定しないと空文字列に変換されるため
                        }
                        if ($level -eq "informational") {
                            $ruleCounts += "info: $([string]$count)"
                        } else {
                            $ruleCounts += "$($level): $($count), "
                        }
                    }
                    $ruleCounts += ")"
                }
                if ($this.SubCategory) {
                    Write-Host "  - $($this.SubCategory): $ruleCounts" -ForegroundColor $color
                } else {
                    Write-Host "  - $($ruleCounts)" -ForegroundColor $color
                }
                if ($this.DefaultSetting) {
                    Write-Host "    - Default Setting: $($this.DefaultSetting)"
                }
                if ($this.CurrentSetting) {
                    Write-Host "    - Current Setting: $($this.CurrentSetting)"
                }
                if ($this.RecommendedSetting) {
                    Write-Host "    - Recommended Setting: $($this.RecommendedSetting)"
                }
                if ($this.Volume) {
                    Write-Host "    - Volume: $($this.Volume)"
                }
                if ($this.Note) {
                    Write-Host "    - Note: $($this.Note)"
                }

            }
            default {
                Write-Error "Invalid output format specified."
            }
        }
    }
}

function ApplyRules {
    param (
        [bool] $enabled,
        [array] $rules,
        [string] $guid
    )
    $rules = $rules | Where-Object { $_.subcategory_guids -contains $guid }
    if ($rules.Count -eq 0) {
        $rules = @()
    } else {
        $rules | ForEach-Object { $_.applicable = $enabled }
    }
    return ,@($rules) # 暗黙の型変換でPSCustomObjectに変換されてしまうため、型を明示
}


function RuleFilter {
    [OutputType([bool])]
    param (
        [pscustomobject] $rule,
        [array] $category_eids,
        [array] $category_channels,
        [string] $category_guid
    )
    $result = $false
    if ($category_channels.Count -gt 0) {
        foreach ($channel in $rule.channel) {
            if ($category_channels -contains $channel) {
                $result = $true
                break
            }
            $result = $false
        }

    }
    if ($category_eids.Count -gt 0) {
        foreach ($eid in $rule.event_ids) {
           if ($category_eids -contains $eid) {
                $result = $true
                break
            }
            $result = $false
        }
    }
    if ($category_guid) {
        foreach ($guid in $rule.subcategory_guid) {
            if ($category_guid -eq $guid) {
                $result = $true
                break
            }
            $result = $false
        }
    }
    return $result
}

function CheckRegistryValue {
    param (
        [string]$registryPath,
        [string]$valueName,
        [int]$expectedValue
    )

    try {
        $value = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop
        if ($value.$valueName -eq $expectedValue) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

function GetAuditpol {
    $mapping = @{}
    Get-Content "./auditpol.txt" | Select-Object -Skip 3 |　ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            return
        }
        $columns = $_ -split ','

        $guid = $columns[3].Trim() -replace '^\{|\}$', ''  # 波括弧を削除
        $inclusionSetting = $columns[4].Trim()
        if ($guid -and $inclusionSetting) {
            $mapping[$guid] = $inclusionSetting
        }
    }
    return $mapping
}

function GuideYamatoSecurity
{
    param (
        [object[]] $all_rules
    )

    $auditResult = @()
    $auditpol = GetAuditpol

    # Application
    $guid    = ""
    $eids     = @()
    $channels = @("Application")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Application",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Applocker
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Applocker",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            "Enabled if AppLocker is enabled?"
    )

    # Bits-Client Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Bits-Client/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Crypto-DPAPI Debug
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Crypto-DPAPI/Debug")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Crypto-DPAPI Debug",
            "",
            $current,
            [array]$rules,
            "Disabled",
            "Enabled",
            "",
            ""
    )

    # CodeIntegrity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-CodeIntegrity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Diagnosis-Scripted Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Diagnosis-Scripted/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Diagnosis-Scripted Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # DriverFrameworks-UserMode Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-DriverFrameworks-UserMode/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "DriverFrameworks-UserMode Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Firewall
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Firewall",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # NTLM Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-NTLM/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Microsoft-Windows-NTLM/Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            "This log is recommended to enable if you want to disable NTLM authentication"
    )

    # PowerShell
    ## Classic
    $guid    = ""
    $eids     = @("400")
    $channels = @("pwsh")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Classic",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    ## Module
    $guid    = ""
    $eids     = @("4103")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Module",
            $current,
            [array]$rules,
            "No Auditing",
            "Enabled",
            "High",
            ""
    )

    ## ScriptBlock
    $guid    = ""
    $eids     = @("4104")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "ScriptBlock",
            $current,
            [array]$rules,
            "Partially Enabled",
            "Enabled",
            "High",
            "On Win 10/2016+, if a PowerShell script is flagged as suspicious by AMSI, it will be logged with a level of Warning in default setting"
    )

    # PrintService Admin
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Admin")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Admin",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # PrintService Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Operational",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Security
    ## Advanced
    ### Account Logon
    #### Credential Validation
    $guid    = "0CCE923F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Credential Validation",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Client and Server OSes: Success and Failure",
            "Depends on NTLM usage. Could be high on DCs and low on clients and servers.",
            ""
    )

    #### Kerberos Authentication Service
    $guid    = "0CCE9242-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Authentication Service",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Client OS: No Auditing | Server OS: Success and Failure",
            "High",
            ""
    )

    #### Kerberos Service Ticket Operations
    $guid    = "0CCE9240-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Service Ticket Operations",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Domain Controllers: Success and Failure",
            "High",
            ""
    )

    ### Account Management
    #### Computer Account Management
    $guid    = "0CCE9236-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Computer Account Management",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Domain Controllers: Success and Failure",
            "High",
            ""
    )

    #### Other Account Management Events
    $guid    = "0CCE923A-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Other Account Management Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    #### Security Group Management
    $guid    = "0CCE9237-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Security Group Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    #### User Account Management
    $guid    = "0CCE9235-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "User Account Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    ### Detailed Tracking
    #### Plug and Play Events
    $guid    = "0CCE9248-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Plug and Play Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    #### Process Creation
    $guid    = "0CCE922B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Creation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High",
            "if sysmon is not configured"
    )

    #### Process Termination
    $guid    = "0CCE922C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Termination",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "High",
            "unless you want to track the lifespan of processes"
    )

    #### RPC Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "RPC Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "High on RPC servers (According to Microsoft)",
            ""
    )

    #### Token Right Adjusted Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Token Right Adjusted Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "",
            ""
    )

    ### DS (Directory Service) Access
    #### Directory Service Access
    $guid    = "0CCE923B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Access",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Client OS: No Auditing | ADDS Server: Success and Failure",
            "High",
            ""
    )

    #### Directory Service Changes
    $guid    = "0CCE923C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Changes",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Client OS: No Auditing | ADDS Server: Success and Failure",
            "High",
            ""
    )

    ### Logon/Logoff
    #### Account Lockout
    $guid    = "0CCE9217-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Account Lockout",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "Low",
            ""
    )

    #### Group Membership
    $guid    = "0CCE9249-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "Adds an extra 4627 event to every logon",
            ""
    )

    #### Logoff
    $guid    = "0CCE9216-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logoff",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Logon
    $guid    = "0CCE9215-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logon",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: Success | Server OS: Success and Failure",
            "Success and Failure",
            "Low on clients, medium on DCs or network servers",
            ""
    )

    #### Other Logon/Logoff Events
    $guid    = "0CCE921C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Other Logon/Logoff Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    #### Special Logon
    $guid    = "0CCE921B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Special Logon",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "Low on clients. Medium on DC or network servers",
            ""
    )


    ### Object Access
    #### Certification Services
    $guid    = "0CCE9221-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure for AD CS role servers",
            "Low to medium",
            ""
    )

    #### Detailed File Share
    $guid    = "0CCE9244-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Detailed File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "Very high for file servers and DCs, however, may be necessary if you want to track who is accessing what files as well as detect various lateral movement",
            "Due to the high noise level. Enable if you can though"
    )

    #### File Share
    $guid    = "0CCE9224-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High for file servers and DCs",
            ""
    )

    #### File System
    $guid    = "0CCE921D-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File System",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Enable",
            "Depends on SACL rules",
            "Enable SACLs just for sensitive files"
    )

    #### Filtering Platform Connection
    $guid    = "0CCE9226-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Connection",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High",
            "Success and Failure if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though"
    )

    #### Filtering Platform Packet Drop
    $guid    = "0CCE9225-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Packet Drop",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High",
            "for AD CS role servers"
    )

    #### Kernel Object
    $guid    = "0CCE921F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Kernel Object",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High if auditing access of global object access is enabled",
            "Success and Failure but do not enable Audit the access of global system objects as you will generate too many 4663: Object Access events"
    )

    #### Handle Manipulation
    $guid    = "0CCE9223-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Handle Manipulation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High",
            ""
    )

    #### Other Object Access Events
    $guid    = "0CCE9227-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Other Object Access Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low",
            ""
    )

    #### Registry
    $guid    = "0CCE921E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Registry",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Depends on SACLs",
            "Set SACLs for only the registry keys that you want to monitor"
    )

    #### Removable Storage
    $guid    = "0CCE9245-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Removable Storage",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Depends on how much removable storage is used",
            "if you want to monitor external device usage"
    )

    #### SAM
    $guid    = "0CCE9220-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "SAM",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Success and Failure if you can but may cause too high volume of noise so should be tested beforehand",
            "for AD CS role servers"
    )

    ### Policy Change
    #### Audit Policy Change
    $guid    = "0CCE922F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Audit Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "Low",
            ""
    )

    #### Authentication Policy Change
    $guid    = "0CCE9230-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authentication Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "Low",
            ""
    )

    #### Authorization Policy Change
    $guid    = "0CCE9231-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authorization Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "Medium to High",
            ""
    )

    #### Filtering Platform Policy Change
    $guid    = "0CCE9233-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Filtering Platform Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "Low",
            ""
    )

    #### MPSSVC Rule-Level Policy Change
    $guid    = "0CCE9232-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "MPSSVC Rule-Level Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "Low",
            ""
    )

    #### Other Policy Change Events
    $guid    = "0CCE9234-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Other Policy Change Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing ",
            "Low",
            "ACSC recommends Success and Failure, however, this results in a lot of noise of 5447 (A Windows Filtering Platform filter has been changed) events being generated"
    )

    ### Privilege Use
    #### Non-Sensitive Privilege Use
    $guid    = "0CCE9229-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Non-Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "Very high",
            ""
    )

    #### Sensitive Privilege Use
    $guid    = "0CCE9228-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "High",
            "However, this may be too noisy"
    )

    ### System
    #### Other System Events
    $guid    = "0CCE9214-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "",
            "Low",
            ""
    )

    #### Security State Change
    $guid    = "0CCE9210-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security State Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "Low",
            ""
    )

    #### Security System Extension
    $guid    = "0CCE9211-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security System Extension",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "Low, but more on DCs",
            ""
    )

    #### System Integrity
    $guid    = "0CCE9212-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "System Integrity",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "Success and Failure",
            "Low",
            ""
    )

    # Security-Mitigations KernelMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations KernelMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Security-Mitigations UserMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations UserMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # SMBClient Security
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-SmbClient/Security")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "SMBClient Security",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # System
    $guid    = ""
    $eids     = @()
    $channels = @("System")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "System",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # TaskScheduler Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TaskScheduler/Operational")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TaskScheduler Operational",
            "",
            $current,
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # TerminalServices-LocalSessionManager Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TerminalServices-LocalSessionManager Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # WMI-Activity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-WMI-Activity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "WMI-Activity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Windows Defender Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Defender/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Windows Defender Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )
    return $auditResult
}

function GuideASD {
    param (
        [object[]] $all_rules
    )

    $auditResult = @()
    $auditpol = GetAuditpol

    # Application
    $guid    = ""
    $eids     = @()
    $channels = @("Application")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Application",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Applocker
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Applocker",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "Enabled",
            "",
            ""
    )

    # Bits-Client Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Bits-Client/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # CodeIntegrity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-CodeIntegrity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Crypto-DPAPI Debug
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Crypto-DPAPI/Debug")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Crypto-DPAPI Debug",
            "",
            $current,
            [array]$rules,
            "Disabled",
            "",
            "",
            ""
    )

    # Diagnosis-Scripted Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Diagnosis-Scripted/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Diagnosis-Scripted Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # DriverFrameworks-UserMode Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-DriverFrameworks-UserMode/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "DriverFrameworks-UserMode Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Firewall
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Firewall",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # NTLM Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-NTLM/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "Microsoft-Windows-NTLM/Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PowerShell
    ## Classic
    $guid    = ""
    $eids     = @("400")
    $channels = @("pwsh")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $enabled }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Classic",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    ## Module
    $guid    = ""
    $eids     = @("4103")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Module",
            $current,
            [array]$rules,
            "No Auditing",
            "Enabled",
            "",
            ""
    )

    ## ScriptBlock
    $guid    = ""
    $eids     = @("4104")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "ScriptBlock",
            $current,
            [array]$rules,
            "Patially",
            "Enabled",
            "",
            ""
    )

    # PrintService Admin
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Admin")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Admin",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PrintService Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Operational",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security
    ## Advanced
    ### Account Logon
    #### Credential Validation
    $guid    = "0CCE923F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Credential Validation",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Kerberos Authentication Service
    $guid    = "0CCE9242-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Authentication Service",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    #### Kerberos Service Ticket Operations
    $guid    = "0CCE9240-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Service Ticket Operations",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    ### Account Management
    #### Computer Account Management
    $guid    = "0CCE9236-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Computer Account Management",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Other Account Management Events
    $guid    = "0CCE923A-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Other Account Management Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Security Group Management
    $guid    = "0CCE9237-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Security Group Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### User Account Management
    $guid    = "0CCE9235-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "User Account Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Detailed Tracking
    #### Plug and Play Events
    $guid    = "0CCE9248-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Plug and Play Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Process Creation
    $guid    = "0CCE922B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Creation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            "Include command line in process creation events"
    )

    #### Process Termination
    $guid    = "0CCE922C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Termination",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### RPC Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "RPC Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "",
            ""
    )

    #### Token Right Adjusted Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Token Right Adjusted Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "",
            ""
    )

    ### DS (Directory Service) Access
    #### Directory Service Access
    $guid    = "0CCE923B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Access",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    #### Directory Service Changes
    $guid    = "0CCE923C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Changes",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### Logon/Logoff
    #### Account Lockout
    $guid    = "0CCE9217-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Account Lockout",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Failure",
            "",
            ""
    )

    #### Group Membership
    $guid    = "0CCE9249-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### Logoff
    $guid    = "0CCE9216-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logoff",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Logon
    $guid    = "0CCE9215-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logon",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: Success | Server OS: Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    #### Other Logon/Logoff Events
    $guid    = "0CCE921C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Other Logon/Logoff Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Special Logon
    $guid    = "0CCE921B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Special Logon",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )


    ### Object Access
    #### Certification Services
    $guid    = "0CCE9221-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Detailed File Share
    $guid    = "0CCE9244-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Detailed File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "",
            "Enabling this setting is not recommended due to the high noise level)"
    )

    #### File Share
    $guid    = "0CCE9224-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### File System
    $guid    = "0CCE921D-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File System",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Connection
    $guid    = "0CCE9226-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Connection",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Packet Drop
    $guid    = "0CCE9225-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Packet Drop",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Kernel Object
    $guid    = "0CCE921F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Kernel Object",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Handle Manipulation
    $guid    = "0CCE9223-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Handle Manipulation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Object Access Events
    $guid    = "0CCE9227-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Other Object Access Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Registry
    $guid    = "0CCE921E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Registry",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Removable Storage
    $guid    = "0CCE9245-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Removable Storage",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### SAM
    $guid    = "0CCE9220-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "SAM",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### Policy Change
    #### Audit Policy Change
    $guid    = "0CCE922F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Audit Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )

    #### Authentication Policy Change
    $guid    = "0CCE9230-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authentication Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "",
            "",
            ""
    )

    #### Authorization Policy Change
    $guid    = "0CCE9231-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authorization Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Policy Change
    $guid    = "0CCE9233-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Filtering Platform Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### MPSSVC Rule-Level Policy Change
    $guid    = "0CCE9232-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "MPSSVC Rule-Level Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Policy Change Events
    $guid    = "0CCE9234-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Other Policy Change Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Privilege Use
    #### Non-Sensitive Privilege Use
    $guid    = "0CCE9229-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Non-Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Sensitive Privilege Use
    $guid    = "0CCE9228-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### System
    #### Other System Events
    $guid    = "0CCE9214-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "",
            "",
            ""
    )

    #### Security State Change
    $guid    = "0CCE9210-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security State Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "",
            "",
            ""
    )

    #### Security System Extension
    $guid    = "0CCE9211-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security System Extension",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### System Integrity
    $guid    = "0CCE9212-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "System Integrity",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    # Security-Mitigations KernelMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations KernelMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security-Mitigations UserMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations UserMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # SMBClient Security
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-SmbClient/Security")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "SMBClient Security",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # System
    $guid    = ""
    $eids     = @()
    $channels = @("System")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "System",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TaskScheduler Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TaskScheduler/Operational")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TaskScheduler Operational",
            "",
            $current,
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TerminalServices-LocalSessionManager Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TerminalServices-LocalSessionManager Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # WMI-Activity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-WMI-Activity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "WMI-Activity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Windows Defender Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Defender/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Windows Defender Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )
    return $auditResult
}

function GuideMSC {
    param (
        [object[]] $all_rules
    )

    $auditResult = @()
    $auditpol = GetAuditpol

    # Application
    $guid    = ""
    $eids     = @()
    $channels = @("Application")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Application",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Applocker
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Applocker",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Bits-Client Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Bits-Client/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # CodeIntegrity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-CodeIntegrity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Crypto-DPAPI Debug
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Crypto-DPAPI/Debug")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Crypto-DPAPI Debug",
            "",
            $current,
            [array]$rules,
            "Disabled",
            "",
            "",
            ""
    )

    # Diagnosis-Scripted Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Diagnosis-Scripted/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Diagnosis-Scripted Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # DriverFrameworks-UserMode Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-DriverFrameworks-UserMode/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "DriverFrameworks-UserMode Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Firewall
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Firewall",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # NTLM Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-NTLM/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Microsoft-Windows-NTLM/Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PowerShell
    ## Classic
    $guid    = ""
    $eids     = @("400")
    $channels = @("pwsh")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Classic",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    ## Module
    $guid    = ""
    $eids     = @("4103")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Module",
            $current,
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ## ScriptBlock
    $guid    = ""
    $eids     = @("4104")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "ScriptBlock",
            $current,
            [array]$rules,
            "Patially",
            "",
            "",
            ""
    )

    # PrintService Admin
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Admin")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Admin",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PrintService Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Operational",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security
    ## Advanced
    ### Account Logon
    #### Credential Validation
    $guid    = "0CCE923F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Credential Validation",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Kerberos Authentication Service
    $guid    = "0CCE9242-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Authentication Service",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    #### Kerberos Service Ticket Operations
    $guid    = "0CCE9240-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Service Ticket Operations",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    ### Account Management
    #### Computer Account Management
    $guid    = "0CCE9236-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Computer Account Management",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success",
            "",
            ""
    )

    #### Other Account Management Events
    $guid    = "0CCE923A-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Other Account Management Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### Security Group Management
    $guid    = "0CCE9237-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Security Group Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### User Account Management
    $guid    = "0CCE9235-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "User Account Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    ### Detailed Tracking
    #### Plug and Play Events
    $guid    = "0CCE9248-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Plug and Play Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Process Creation
    $guid    = "0CCE922B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Creation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            "Include command line in process creation events"
    )

    #### Process Termination
    $guid    = "0CCE922C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Termination",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### RPC Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "RPC Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Token Right Adjusted Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Token Right Adjusted Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### DS (Directory Service) Access
    #### Directory Service Access
    $guid    = "0CCE923B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Access",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    #### Directory Service Changes
    $guid    = "0CCE923C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Changes",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### Logon/Logoff
    #### Account Lockout
    $guid    = "0CCE9217-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Account Lockout",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Failure",
            "",
            ""
    )

    #### Group Membership
    $guid    = "0CCE9249-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### Logoff
    $guid    = "0CCE9216-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logoff",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Logon
    $guid    = "0CCE9215-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logon",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: Success | Server OS: Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    #### Other Logon/Logoff Events
    $guid    = "0CCE921C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Other Logon/Logoff Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Special Logon
    $guid    = "0CCE921B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Special Logon",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )


    ### Object Access
    #### Certification Services
    $guid    = "0CCE9221-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Detailed File Share
    $guid    = "0CCE9244-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Detailed File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            "Enabling this setting is not recommended due to the high noise level)"
    )

    #### File Share
    $guid    = "0CCE9224-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### File System
    $guid    = "0CCE921D-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File System",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Connection
    $guid    = "0CCE9226-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Connection",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Packet Drop
    $guid    = "0CCE9225-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Packet Drop",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Kernel Object
    $guid    = "0CCE921F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Kernel Object",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Handle Manipulation
    $guid    = "0CCE9223-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Handle Manipulation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Object Access Events
    $guid    = "0CCE9227-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Other Object Access Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Registry
    $guid    = "0CCE921E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Registry",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Removable Storage
    $guid    = "0CCE9245-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Removable Storage",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### SAM
    $guid    = "0CCE9220-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "SAM",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### Policy Change
    #### Audit Policy Change
    $guid    = "0CCE922F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Audit Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )

    #### Authentication Policy Change
    $guid    = "0CCE9230-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authentication Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Authorization Policy Change
    $guid    = "0CCE9231-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authorization Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Policy Change
    $guid    = "0CCE9233-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Filtering Platform Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### MPSSVC Rule-Level Policy Change
    $guid    = "0CCE9232-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "MPSSVC Rule-Level Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Policy Change Events
    $guid    = "0CCE9234-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Other Policy Change Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Privilege Use
    #### Non-Sensitive Privilege Use
    $guid    = "0CCE9229-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Non-Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Sensitive Privilege Use
    $guid    = "0CCE9228-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### System
    #### Other System Events
    $guid    = "0CCE9214-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "",
            "",
            ""
    )

    #### Security State Change
    $guid    = "0CCE9210-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security State Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )

    #### Security System Extension
    $guid    = "0CCE9211-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security System Extension",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### System Integrity
    $guid    = "0CCE9212-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "System Integrity",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    # Security-Mitigations KernelMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations KernelMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security-Mitigations UserMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations UserMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # SMBClient Security
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-SmbClient/Security")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "SMBClient Security",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # System
    $guid    = ""
    $eids     = @()
    $channels = @("System")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "System",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TaskScheduler Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TaskScheduler/Operational")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TaskScheduler Operational",
            "",
            $current,
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TerminalServices-LocalSessionManager Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TerminalServices-LocalSessionManager Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # WMI-Activity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-WMI-Activity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "WMI-Activity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Windows Defender Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Defender/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Windows Defender Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )
    return $auditResult
}

function GuideMSS {
    param (
        [object[]] $all_rules
    )

    $auditResult = @()
    $auditpol = GetAuditpol

    # Application
    $guid    = ""
    $eids     = @()
    $channels = @("Application")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Application",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Applocker
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Applocker",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Bits-Client Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Bits-Client/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # CodeIntegrity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-CodeIntegrity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Crypto-DPAPI Debug
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Crypto-DPAPI/Debug")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Crypto-DPAPI Debug",
            "",
            $current,
            [array]$rules,
            "Disabled",
            "",
            "",
            ""
    )

    # Diagnosis-Scripted Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Diagnosis-Scripted/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Diagnosis-Scripted Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # DriverFrameworks-UserMode Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-DriverFrameworks-UserMode/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "DriverFrameworks-UserMode Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Firewall
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Firewall",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # NTLM Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-NTLM/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Microsoft-Windows-NTLM/Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PowerShell
    ## Classic
    $guid    = ""
    $eids     = @("400")
    $channels = @("pwsh")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Classic",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    ## Module
    $guid    = ""
    $eids     = @("4103")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $false }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "Module",
            $current,
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ## ScriptBlock
    $guid    = ""
    $eids     = @("4104")
    $channels = @("pwsh")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $auditResult += [WELA]::New(
            "PowerShell",
            "ScriptBlock",
            $current,
            [array]$rules,
            "Patially",
            "",
            "",
            ""
    )

    # PrintService Admin
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Admin")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Admin",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # PrintService Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Operational",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security
    ## Advanced
    ### Account Logon
    #### Credential Validation
    $guid    = "0CCE923F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Credential Validation",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Kerberos Authentication Service
    $guid    = "0CCE9242-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Authentication Service",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    #### Kerberos Service Ticket Operations
    $guid    = "0CCE9240-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Service Ticket Operations",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "",
            "",
            ""
    )

    ### Account Management
    #### Computer Account Management
    $guid    = "0CCE9236-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Computer Account Management",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Other Account Management Events
    $guid    = "0CCE923A-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Other Account Management Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Security Group Management
    $guid    = "0CCE9237-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Security Group Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### User Account Management
    $guid    = "0CCE9235-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "User Account Management",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Detailed Tracking
    #### Plug and Play Events
    $guid    = "0CCE9248-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Plug and Play Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Process Creation
    $guid    = "0CCE922B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Creation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            "Include command line in process creation events"
    )

    #### Process Termination
    $guid    = "0CCE922C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Termination",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### RPC Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "RPC Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Token Right Adjusted Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Token Right Adjusted Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### DS (Directory Service) Access
    #### Directory Service Access
    $guid    = "0CCE923B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Access",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: No Auditing | Server OS: Success",
            "Success and Failure",
            "",
            ""
    )

    #### Directory Service Changes
    $guid    = "0CCE923C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Changes",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Logon/Logoff
    #### Account Lockout
    $guid    = "0CCE9217-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Account Lockout",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Failure",
            "",
            ""
    )

    #### Group Membership
    $guid    = "0CCE9249-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success",
            "",
            ""
    )

    #### Logoff
    $guid    = "0CCE9216-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logoff",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Logon
    $guid    = "0CCE9215-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logon",
            $auditpol[$guid],
            [array]$rules,
            "Client OS: Success | Server OS: Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    #### Other Logon/Logoff Events
    $guid    = "0CCE921C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Other Logon/Logoff Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Special Logon
    $guid    = "0CCE921B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Special Logon",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )


    ### Object Access
    #### Certification Services
    $guid    = "0CCE9221-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Detailed File Share
    $guid    = "0CCE9244-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Detailed File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            "Enabling this setting is not recommended due to the high noise level)"
    )

    #### File Share
    $guid    = "0CCE9224-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File Share",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### File System
    $guid    = "0CCE921D-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File System",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Connection
    $guid    = "0CCE9226-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Connection",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Packet Drop
    $guid    = "0CCE9225-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Packet Drop",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Kernel Object
    $guid    = "0CCE921F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Kernel Object",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Handle Manipulation
    $guid    = "0CCE9223-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Handle Manipulation",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Object Access Events
    $guid    = "0CCE9227-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Other Object Access Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Registry
    $guid    = "0CCE921E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Registry",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### Removable Storage
    $guid    = "0CCE9245-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Removable Storage",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### SAM
    $guid    = "0CCE9220-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "SAM",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### Policy Change
    #### Audit Policy Change
    $guid    = "0CCE922F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Audit Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )

    #### Authentication Policy Change
    $guid    = "0CCE9230-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authentication Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success",
            "",
            ""
    )

    #### Authorization Policy Change
    $guid    = "0CCE9231-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authorization Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Filtering Platform Policy Change
    $guid    = "0CCE9233-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Filtering Platform Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### MPSSVC Rule-Level Policy Change
    $guid    = "0CCE9232-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "MPSSVC Rule-Level Policy Change",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Other Policy Change Events
    $guid    = "0CCE9234-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Other Policy Change Events",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    ### Privilege Use
    #### Non-Sensitive Privilege Use
    $guid    = "0CCE9229-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Non-Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    #### Sensitive Privilege Use
    $guid    = "0CCE9228-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $false }
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Sensitive Privilege Use",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "",
            "",
            ""
    )

    ### System
    #### Other System Events
    $guid    = "0CCE9214-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "",
            "",
            ""
    )

    #### Security State Change
    $guid    = "0CCE9210-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security State Change",
            $auditpol[$guid],
            [array]$rules,
            "Success",
            "Success and Failure",
            "",
            ""
    )

    #### Security System Extension
    $guid    = "0CCE9211-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security System Extension",
            $auditpol[$guid],
            [array]$rules,
            "No Auditing",
            "Success and Failure",
            "",
            ""
    )

    #### System Integrity
    $guid    = "0CCE9212-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "System Integrity",
            $auditpol[$guid],
            [array]$rules,
            "Success and Failure",
            "Success and Failure",
            "",
            ""
    )

    # Security-Mitigations KernelMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations KernelMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Security-Mitigations UserMode
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Security-Mitigations*")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Security-Mitigations UserMode",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # SMBClient Security
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-SmbClient/Security")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "SMBClient Security",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # System
    $guid    = ""
    $eids     = @()
    $channels = @("System")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "System",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TaskScheduler Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TaskScheduler/Operational")
    $enabled  = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -valueName "Enabled" -expectedValue 1
    $current  = if ($enabled) { "Enabled" } else { "Disabled" }
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TaskScheduler Operational",
            "",
            $current,
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # TerminalServices-LocalSessionManager Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "TerminalServices-LocalSessionManager Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # WMI-Activity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-WMI-Activity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "WMI-Activity Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )

    # Windows Defender Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Windows Defender/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $rules    | ForEach-Object { $_.ideal = $true }
    $auditResult += [WELA]::New(
            "Windows Defender Operational",
            "",
            "Enabled",
            [array]$rules,
            "Enabled",
            "",
            "",
            ""
    )
    return $auditResult
}



function AuditLogSetting {
    param (
        [string] $outType,
        [string] $Baseline,
        [bool] $debug
    )

    $autidpolTxt = "./auditpol.txt"
    if (-not $debug) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $autidpolTxt
    }
    $enabledguid = [System.Collections.Generic.HashSet[string]]::new()
    Get-Content -Path $autidpolTxt | Select-String -NotMatch "No Auditing" | ForEach-Object {
        if ($_ -match '{(.*?)}') {
            [void]$enabledguid.Add($matches[1])
        }
    }
    $all_rules = Get-Content -Path "config/security_rules.json" -Raw | ConvertFrom-Json
    $all_rules | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name "applicable" -Value $false
        $_ | Add-Member -MemberType NoteProperty -Name "ideal" -Value $false
    }
    $auditResult = @()

    if ($Baseline.ToLower() -eq "yamatosecurity") {
        $auditResult = GuideYamatoSecurity $all_rules
    } elseif ($Baseline.ToLower() -eq "asd") {
        $auditResult = GuideASD $all_rules
    } elseif ($Baseline.ToLower() -eq "microsoft_client") {
        $auditResult = GuideMSC $all_rules
    } elseif ($Baseline.ToLower() -eq "microsoft_server") {
        $auditResult = GuideMSS $all_rules
    }

    $auditResult | ForEach-Object {
        $_.SetApplicable($enabledguid)
        $_.CountByLevel()
    }

    $auditResult | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name RuleCount -Value 0
        $_.RuleCount = ($_.Rules | Measure-Object).Count
        $_ | Add-Member -MemberType NoteProperty -Name RuleCountByLevel -Value ""
        $ruleCounts = ""
        foreach ($level in [WELA]::Levels) {
            $count = $_.RulesCount[$level]
            if (-not $count) {
                $count = 0
            }
            if ($level -eq "informational") {
                $ruleCounts += "info:$([string]$count)"
            } else {
                $ruleCounts += "$($level):$($count), "
            }
        }
        $_.RuleCountByLevel = $ruleCounts
    }

    if ($outType -eq "std") {
        $auditResult | Group-Object -Property Category | ForEach-Object {
            $enabledCount = ($_.Group |  Where-Object { $_.CurrentSetting -ne "No Auditing" -and $_.CurrentSetting -ne "Disabled" } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $disabledCount = ($_.Group |  Where-Object { $_.CurrentSetting -eq "No Auditing" -or $_.CurrentSetting -eq "Disabled" } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $out = ""
            $color = ""
            if ($disabledCount -eq 0 -and $enabledCount -ne 0){
                $out = "Enabled"
                $color = "Green"
            }
            elseif ($disabledCount -ne 0 -and $enabledCount -eq 0)
            {
                $out = "Disabled"
                $color = "Red"
            }
            else
            {
                $out = "Partially Enabled"
                $color = "DarkYellow"
            }
            $enabledPercentage = "0.00%"
            if ($enabledCount + $disabledCount -ne 0) {
                $enabledPercentage = "({0:N2}%)" -f (($enabledCount / ($enabledCount + $disabledCount)) * 100)
            }
            if ($_.Name -notmatch "Powershell" -and $_.Name -notmatch "Security Advanced") {
                $enabledPercentage = ""
            }
            Write-Host "$( $_.Name ): $out$($enabledPercentage)" -ForegroundColor $color
            $_.Group | ForEach-Object {
                $_.Output($outType)
            }
            Write-Host ""
        }
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, CurrentSetting, RecommendedSetting, Volume, Note | Export-Csv -Path "WELA-Audit-Result.csv" -NoTypeInformation
        Write-Output "Audit check result saved to: WELA-Audit-Result.csv"
    } elseif ($outType -eq "table") {
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, DefaultSetting, CurrentSetting, RecommendedSetting, Volume | Format-Table
    }

    $usableRules  = $auditResult | Select-Object -ExpandProperty Rules | Where-Object { $_.applicable -eq $true }
    $unUsableRules   = $auditResult | Select-Object -ExpandProperty Rules | Where-Object { $_.applicable -eq $false }
    $usableRules | Select-Object title, level, service, category, description, id | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
    $unusableRules  | Select-Object title, level, service, category, description, id  | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation

    if ($outType -eq "gui") {
        $usableRules | Select-Object title, level, service, category, description, id | Out-GridView -Title "Usable Detection Rules"
        $unUsableRules  | Select-Object title, level, service, category, description, id  | Out-GridView -Title "Unusable Detection Rules"
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, CurrentSetting, RecommendedSetting, Volume, Note | Out-GridView -Title "WELA Audit Result"
        Write-Output "Audit check result saved to: WELA-Audit-Result.csv"
    }

    Write-Output "Usable detection rules list saved to: UsableRules.csv"
    Write-Output "Unusable detection rules list saved to: UnusableRules.csv"

    $sigma_rules = $auditResult | Select-Object -ExpandProperty Rules
    Export-MitreHeatmap -sigmaRules $sigma_rules -OutputPath "mitre-ttp-navigator-current.json"
    Write-Output "MITRE ATT&CK Navigator data(based on current settings) saved to: mitre-ttp-navigator-current.json"
    Export-MitreHeatmap -sigmaRules $sigma_rules -OutputPath "mitre-ttp-navigator-ideal.json" -UseIdealCount $true
    Write-Output "MITRE ATT&CK Navigator data(based on ideal settings) saved to: mitre-ttp-navigator-ideal.json"

    $totalRulesCount = $auditResult | Select-Object -ExpandProperty Rules | Measure-Object | Select-Object -ExpandProperty Count
    $usableRulesCount = $usableRules | Measure-Object | Select-Object -ExpandProperty Count
    $utilizationPercentage = "{0:N2}" -f (($usableRulesCount / $totalRulesCount) * 100)
    $color = "Red"
    if ($utilizationPercentage -ge 10 -and $utilizationPercentage -lt 70) {
        $color = "DarkYellow"
    } elseif ($utilizationPercentage -ge 70) {
        $color = "Green"
    }
    Write-Host ""
    Write-Host "You can utilize $utilizationPercentage% of your detection rules." -ForegroundColor $color
    Write-Host ""
}


function Export-MitreHeatmap {
    param (
        [Parameter(Mandatory = $true)]
        [array]$sigmaRules,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "mitre-ttp-heatmap.json",

        [Parameter(Mandatory=$false)]
        [bool]$UseIdealCount = $false
    )
    $tagMapping = @{}
    $sigmaRules | ForEach-Object {
        $rule = $_
        if ($rule.tags) {
            $rule.tags | ForEach-Object {
                $tag = $_
                if (-not $tagMapping.ContainsKey($tag)) {
                    $tagMapping[$tag] = @{
                        titles = @()
                        idealCount = 0
                        applicableCount = 0
                    }
                }
                $tagMapping[$tag].titles += $rule.title
                if ($rule.applicable -eq $true) {
                    $tagMapping[$tag].applicableCount++
                }
                if ($rule.ideal -eq $true) {
                    $tagMapping[$tag].idealCount++
                }
            }
        }
    }

    $techniques = @()
    $tagMapping.Keys | ForEach-Object {
        $techniqueId = $_
        $info = $tagMapping[$techniqueId]
        $titlesCount = $info.titles.Count
        $score = if ($titlesCount -gt 0) {
            [int][math]::Round(($info.applicableCount / $titlesCount) * 100, 2)
        } else {
            0
        }
        if ($info.idealCount -gt 0 -and $info.applicableCount -eq 0) {
            $score = 0
        }

        if ($UseIdealCount) {
            $score = [int][math]::Round(($info.idealCount / $titlesCount) * 100, 2)
        }

        $techniques += @{
            techniqueID = $techniqueId
            score = $score
            comment = ($info.titles -join ", ")
            showSubtechniques = $true
        }
    }

    $colors = @(
        "#c62828",  # Red
        "#fff176",  # Yellow
        "#ffa726",  # Orange
        "#c8e6c9",  # Light Green
        "#2e7d32"   # Dark Green
    )

    $heatmap = @{
        "name" = "WELA detection heatmap"
        "versions" = @{
            "attack" = "17"
            "navigator" = "5.1.0"
            "layer" = "4.5"
        }
        "domain" = "enterprise-attack"
        "description" = "WELA detection heatmap"
        "techniques" = $techniques
        "gradient" = @{
            "colors" = $colors
            "minValue" = 0
            "maxValue" = 100
        }
        "legendItems" = @()
        "metadata" = @()
        "links" = @()
        "showTacticRowBackground" = $false
        "tacticRowBackground" = "#dddddd"
        "selectTechniquesAcrossTactics" = $true
        "selectSubtechniquesWithParent" = $false
        "selectVisibleTechniques" = $false
    }

    $heatmap | ConvertTo-Json -Depth 10 | Out-File $OutputPath
}



function AuditFileSize {
    param (
        [string] $Baseline = "YamatoSecurity"
    )

    # 対象のイベントログ名をハッシュテーブル化
    $logNames = @{
        "Application" = @("20 MB", "128 MB+")
        "Microsoft-Windows-AppLocker/EXE and DLL" = @("1 MB", "256 MB+")
        "Microsoft-Windows-AppLocker/MSI and Script" = @("1 MB", "256 MB+")
        "Microsoft-Windows-AppLocker/Packaged app-Deployment" = @("1 MB", "256 MB+")
        "Microsoft-Windows-AppLocker/Packaged app-Execution" = @("1 MB", "256 MB+")
        "Microsoft-Windows-Bits-Client/Analytic" = @("1 MB", "128 MB+")
        "Microsoft-Windows-Bits-Client/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-CodeIntegrity/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-Crypto-DPAPI/Debug" = @("1 MB", "128 MB+")
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-NTLM/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-PowerShell/Operational" = @("20 MB", "256 MB+")
        "Microsoft-Windows-PrintService/Admin" = @("1 MB", "128 MB+")
        "Microsoft-Windows-PrintService/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-Security-Mitigations/KernelMode" = @("1 MB", "128 MB+")
        "Microsoft-Windows-Security-Mitigations/UserMode" = @("1 MB", "128 MB+")
        "Microsoft-Windows-SmbClient/Security" = @("8 MB", "128 MB+")
        "Microsoft-Windows-TaskScheduler/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-Windows Defender/Operational" = @("16MB", "128 MB+")
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = @("1 MB", "256 MB+")
        "Microsoft-Windows-WMI-Activity/Operational" = @("1 MB", "128 MB+")
        "Security" = @("20 MB", "256 MB+")
        "System" = @("20 MB", "128 MB+")
        "Windows PowerShell" = @("15 MB", "256 MB+")
    }

    $results = @()

    foreach ($logName in $logNames.Keys | Sort-Object) {
        $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $maxLogSize = [math]::Floor($logInfo.MaximumSizeInBytes / 1MB)
        $recommendedSize = [int]($logNames[$logName][1] -replace " MB\+?", "")
        $logIsFull = $logInfo.FileSize -gt $logInfo.MaximumSizeInBytes
        $logMode = if ($logInfo.LogMode -eq "Retain") { "NoOverwrite" } else { $logInfo.LogMode }
        $correctSetting = if ($maxLogSize -ge $recommendedSize -and $logMode -ne "NoOverwrite") { "Y" } else { "N" }

        $results += [PSCustomObject]@{
            LogFile         = Split-Path $logInfo.LogFilePath -Leaf
            CurrentLogSize  = "{0:N2} MB" -f ($logInfo.FileSize / 1MB)
            MaxLogSize      = "$maxLogSize MB"
            Default         = $logNames[$logName][0]
            Recommended     = $logNames[$logName][1]
            IsLogFull       = $logIsFull
            LogMode         = $logMode
            CorrectSetting  = $correctSetting
        }
    }

    # Format-Tableには色つき出力の機能はないので、Write-Hostで色をつける
    $tableLayout = "{0,-75} {1,-15} {2,-10} {3,-10} {4,-15} {5,-10} {6,-15} {7,-10}"
    Write-Host ($tableLayout -f `
        "Log File", `
        "Current Size", `
        "Max Size", `
        "Default", `
        "Recommended", `
        "Is Full", `
        "Log Mode", `
        "Correct Setting" `
        )
    Write-Host ($tableLayout -f `
        "--------", `
        "------------", `
        "--------", `
        "------", `
        "-----------", `
        "-------", `
        "--------", `
        "--------------" `
        )
    foreach ($result in $results) {
        $color = if ($result.CorrectSetting -eq "Y") { "Green" } else { "Red" }
        Write-Host ($tableLayout -f `
        $result.LogFile, `
        $result.CurrentLogSize, `
        $result.MaxLogSize, `
        $result.Default, `
        $result.Recommended, `
        $result.IsLogFull, `
        $result.LogMode, `
        $result.CorrectSetting `
        ) -ForegroundColor $color
    }

    $results | Export-Csv -Path "WELA-FileSize-Result.csv" -NoTypeInformation
    Write-Host ""
    Write-Host "Audit file size result saved to: WELA-FileSize-Result.csv"
}


function UpdateRules {
    $urls = @(
        "https://raw.githubusercontent.com/Yamato-Security/WELA/main/config/eid_subcategory_mapping.csv",
        "https://raw.githubusercontent.com/Yamato-Security/WELA/main/config/security_rules.json"
    )
    $outputPaths = @(
        "./config/eid_subcategory_mapping.csv",
        "./config/security_rules.json"
    )

    for ($i = 0; $i -lt $urls.Count; $i++) {
        Write-Host "Downloading $($urls[$i])"
        Invoke-WebRequest -Uri $urls[$i] -OutFile $outputPaths[$i] -UseBasicParsing
        Write-Host "Saved to $($outputPaths[$i])"
        Write-Host ""
    }
}

function ConfigureAuditSettings {
    param (
        [string] $Baseline = "YamatoSecurity",
        [switch] $Auto
    )

    # 管理者権限の確認
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script requires Administrator privileges"
        exit 1
    }

    $autidpolTxt = "./auditpol.txt"
    if (-not $debug) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $autidpolTxt
    }

    # ログサイズ定数
    $oneGB = 1073741824
    $oneTwentyEightMB = 134217728

    # セキュリティおよびPowerShellログを1GBに設定
    Write-Host "Configuring Event Logs..."
    Write-Host ""
    $largeLogs = @(
        "Security",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    )

    foreach ($log in $largeLogs) {
        try {
            $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop
            $currentSize = [math]::Floor($logInfo.MaximumSizeInBytes / 1MB)
            $newSize = 1024
            Write-Host "Log: $log"
            if ($currentSize -ge $newSize) {
                Write-Host "[SKIPPED] $log : Current size ($currentSize MB) is already greater than or equal to $newSize MB." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
            if ($Auto) {
                $response = "Y"
            } else {
                $response = Read-Host "Your current setting is $currentSize MB. Do you want to change it to 1024 MB? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                wevtutil sl $log /ms:$oneGB 2>&1 | Out-Null
                Write-Host "[OK] $log : 1024 MB" -ForegroundColor Green
            } else {
                Write-Host "[SKIPPED] $log" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] $log : $_" -ForegroundColor Red
        }
        Write-Host ""
    }

    # その他の重要なログを128MBに設定
    $mediumLogs = @(
        "System",
        "Application",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-NTLM/Operational",
        "Microsoft-Windows-Security-Mitigations/KernelMode",
        "Microsoft-Windows-Security-Mitigations/UserMode",
        "Microsoft-Windows-PrintService/Admin",
        "Microsoft-Windows-PrintService/Operational",
        "Microsoft-Windows-SmbClient/Security",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-Crypto-DPAPI/Debug",
        "Microsoft-Windows-Diagnosis-Scripted/Operational",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational"
    )

    foreach ($log in $mediumLogs) {
        try {
            $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop
            $currentSize = [math]::Floor($logInfo.MaximumSizeInBytes / 1MB)
            $newSize = 128
            Write-Host "Log: $log"
            if ($currentSize -ge $newSize) {
                Write-Host "[SKIPPED] $log : Current size ($currentSize MB) is already greater than or equal to $newSize MB." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
            if ($Auto) {
                $response = "Y"
            } else {
                $response = Read-Host "Your current setting is $currentSize MB. Do you want to change it to 128 MB? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                wevtutil sl $log /ms:$oneTwentyEightMB 2>&1 | Out-Null
                Write-Host "[OK] $log : 128 MB" -ForegroundColor Green
            } else {
                Write-Host "[SKIPPED] $log" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] $log : $_" -ForegroundColor Red
        }
        Write-Host ""
    }

    # 特定のログの有効化
    Write-Host "Enabling Event Logs..."
    Write-Host ""
    foreach ($log in @("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-Crypto-DPAPI/Debug")) {
        try {
            $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop
            $currentState = if ($logInfo.IsEnabled) { "Enabled" } else { "Disabled" }
            $newState = "Enabled"
            Write-Host "Log: $log"
            if ($currentState -eq $newState) {
                Write-Host "[SKIPPED] $log : Already Enabled." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
            if ($Auto) {
                $response = "Y"
            } else {
                $response = Read-Host "Your current setting is $currentState. Do you want to change it to Enabled? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                wevtutil sl $log /e:true 2>&1 | Out-Null
                Write-Host "[OK] Enabled: $log" -ForegroundColor Green
            } else {
                Write-Host "[SKIPPED] $log" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] Failed to enable $log : $_" -ForegroundColor Red
        }
        Write-Host ""
    }

    # PowerShell ロギングの設定
    Write-Host "Configuring PowerShell Logging..."
    Write-Host ""
    $regPaths = @(
        @{Path = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Value = 1}
    )

    foreach ($reg in $regPaths) {
        try {
            $currentValue = "Not Set"
            if (Test-Path $reg.Path) {
                $prop = Get-ItemProperty -Path $reg.Path -Name $reg.Name -ErrorAction SilentlyContinue
                if ($prop) {
                    $currentValue = $prop.$($reg.Name)
                }
            }
            Write-Host "Registry: $($reg.Path) Value: $($reg.Name)"
            if ($currentValue -eq $reg.Value) {
                Write-Host "[SKIPPED] $($reg.Name) : Already set to $($reg.Value)." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
            if ($Auto) {
                $response = "Y"
            } else {
                $response = Read-Host "Your current setting is $currentValue. Do you want to change it to $( $reg.Value )? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
                New-Item -Path $reg.Path -Force | Out-Null
                Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord
                Write-Host "[OK] Set $($reg.Name)" -ForegroundColor Green
            } else {
                Write-Host "[SKIPPED] $($reg.Name)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] Failed to set registry: $_" -ForegroundColor Red
        }
        Write-Host ""
    }

    # モジュール名レジストリの設定
    try {
        $moduleLoggingPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
        $currentValue = "Not Set"
        if (Test-Path $moduleLoggingPath) {
            $prop = Get-ItemProperty -Path $moduleLoggingPath -Name "*" -ErrorAction SilentlyContinue
            if ($prop) {
                $currentValue = $prop."*"
            }
        }
        Write-Host "Registry: $moduleLoggingPath"
        if ($currentValue -eq "*") {
            Write-Host "[SKIPPED] Module logging : Already set to * (all modules)." -ForegroundColor Yellow
            Write-Host ""
        } else
        {
            if ($Auto)
            {
                $response = "Y"
            }
            else
            {
                $response = Read-Host "Your current setting is $currentValue. Do you want to change it to * (all modules)? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y")
            {
                New-Item -Path $moduleLoggingPath -Force | Out-Null
                Set-ItemProperty -Path $moduleLoggingPath -Name "*" -Value "*" -Type String
                Write-Host "[OK] Module logging enabled for all modules" -ForegroundColor Green
            }
            else
            {
                Write-Host "[SKIPPED] Module logging" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to configure module names: $_" -ForegroundColor Red
    }
    Write-Host ""

    # コマンドライン監査の有効化
    Write-Host "Enabling Command Line Auditing..."
    Write-Host ""
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $valueName = "ProcessCreationIncludeCmdLine_Enabled"
    try {
        $currentValue = "Not Set"
        if (Test-Path $regPath) {
            $prop = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
            $currentValue = $prop.$valueName
        }
        Write-Host "Registry: $regPath"
        if ($currentValue -eq 1) {
            Write-Host "[SKIPPED] Command Line Auditing : Already Enabled." -ForegroundColor Yellow
            Write-Host ""
        } else
        {
            if ($Auto)
            {
                $response = "Y"
            }
            else
            {
                $response = Read-Host "Your current setting is $currentValue. Do you want to change it to 1 (Enabled)? (Y/n)"
            }
            if ($response -eq "" -or $response -eq "Y" -or $response -eq "y")
            {
                $regPath = $regPath -replace "HKLM:", "HKLM"
                $arguments = "add $regPath /v $valueName /f /t REG_DWORD /d 1"
                $process = Start-Process -FilePath "reg.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput "NUL"
                if ($process.ExitCode -eq 0)
                {
                    Write-Host "[OK] Command line auditing enabled" -ForegroundColor Green
                }
                else
                {
                    Write-Host "[ERROR] Command line auditing failed (ExitCode: $( $process.ExitCode ))" -ForegroundColor Red
                }
            }
            else
            {
                Write-Host "[SKIPPED] Command line auditing" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to check command line auditing: $_" -ForegroundColor Red
    }
    Write-Host ""

    # 監査ポリシーの設定
    Write-Host "Configuring Audit Policies..."
    Write-Host ""
    $auditPolicies = @(
        @{Category = "Account Logon"; Name = "Credential Validation"; GUID = "0CCE923F-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Logon"; Name = "Kerberos Authentication Service"; GUID = "0CCE9242-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Logon"; Name = "Kerberos Service Ticket Operations"; GUID = "0CCE9240-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "Computer Account Management"; GUID = "0CCE9236-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "Other Account Management Events"; GUID = "0CCE923A-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "Security Group Management"; GUID = "0CCE9237-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "User Account Management"; GUID = "0CCE9235-69AE-11D9-BED3-505054503030"},
        @{Category = "Detailed Tracking"; Name = "Plug and Play"; GUID = "0cce9248-69ae-11d9-bed3-505054503030"},
        @{Category = "Detailed Tracking"; Name = "Process Creation"; GUID = "0CCE922B-69AE-11D9-BED3-505054503030"},
        @{Category = "Detailed Tracking"; Name = "RPC Events"; GUID = "0CCE922E-69AE-11D9-BED3-505054503030"},
        @{Category = "DS Access"; Name = "Directory Service Access"; GUID = "0CCE923B-69AE-11D9-BED3-505054503030"},
        @{Category = "DS Access"; Name = "Directory Service Changes"; GUID = "0CCE923C-69AE-11D9-BED3-505054503030"},
        @{Category = "Logon/Logoff"; Name = "Account Lockout"; GUID = "0CCE9217-69AE-11D9-BED3-505054503030"},
        @{Category = "Logon/Logoff"; Name = "Logoff"; GUID = "0CCE9216-69AE-11D9-BED3-505054503030"},
        @{Category = "Logon/Logoff"; Name = "Logon"; GUID = "0CCE9215-69AE-11D9-BED3-505054503030"},
        @{Category = "Logon/Logoff"; Name = "Other Logon/Logoff Events"; GUID = "0CCE921C-69AE-11D9-BED3-505054503030"},
        @{Category = "Logon/Logoff"; Name = "Special Logon"; GUID = "0CCE921B-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "Certification Services"; GUID = "0CCE9221-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "File Share"; GUID = "0CCE9224-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "Filtering Platform Connection"; GUID = "0CCE9226-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "Other Object Access Events"; GUID = "0CCE9227-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "Removable Storage"; GUID = "0CCE9245-69AE-11D9-BED3-505054503030"},
        @{Category = "Object Access"; Name = "SAM"; GUID = "0CCE9220-69AE-11D9-BED3-505054503030"},
        @{Category = "Policy Change"; Name = "Audit Policy Change"; GUID = "0CCE922F-69AE-11D9-BED3-505054503030"},
        @{Category = "Policy Change"; Name = "Authentication Policy Change"; GUID = "0CCE9230-69AE-11D9-BED3-505054503030"},
        @{Category = "Policy Change"; Name = "Other Policy Change Events"; GUID = "0CCE9234-69AE-11D9-BED3-505054503030"},
        @{Category = "Privilege Use"; Name = "Sensitive Privilege Use"; GUID = "0CCE9228-69AE-11D9-BED3-505054503030"},
        @{Category = "System"; Name = "Security State Change"; GUID = "0CCE9210-69AE-11D9-BED3-505054503030"},
        @{Category = "System"; Name = "Security System Extension"; GUID = "0CCE9211-69AE-11D9-BED3-505054503030"},
        @{Category = "System"; Name = "System Integrity"; GUID = "0CCE9212-69AE-11D9-BED3-505054503030"},
        @{Category = "System"; Name = "Other System Events"; GUID = "0CCE9214-69AE-11D9-BED3-505054503030"}
    )

    $currentAuditPol = GetAuditpol

    foreach ($policy in $auditPolicies)
    {
        $newSetting = "Success and Failure"
        $currentSetting = if ($currentAuditPol.ContainsKey($policy.GUID))
        {
            $currentAuditPol[$policy.GUID]
        }
        else
        {
            "Unknown"
        }

        Write-Host "Audit Policy: $( $policy.Category ) - $( $policy.Name )"
        if ($currentSetting -eq $newSetting)
        {
            Write-Host "[SKIPPED] $( $policy.Category ) - $( $policy.Name ) : Already set to $newSetting." -ForegroundColor Yellow
            Write-Host ""
            continue
        }
        if ($Auto) {
            $response = "Y"
        } else {
            $response = Read-Host "Your current setting is $currentSetting. Do you want to change it to $newSetting? (Y/n)"
        }
        if ($response -eq "" -or $response -eq "Y" -or $response -eq "y") {
            $arguments = "/set /subcategory:{$($policy.GUID)} /success:enable /failure:enable"
            $process = Start-Process -FilePath "auditpol.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput "NUL"

            if ($process.ExitCode -eq 0) {
                Write-Host "[OK] $($policy.Category) - $($policy.Name)" -ForegroundColor Green
            }
            else {
                Write-Host "[ERROR] $($policy.Category) - $($policy.Name) (ExitCode: $($process.ExitCode))" -ForegroundColor Red
            }
        } else {
            Write-Host "[SKIPPED] $($policy.Category) - $($policy.Name)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    Write-Host "Configuration completed successfully" -ForegroundColor Green
}

$logo = @"
┏┓┏┓┏┳━━━┳┓  ┏━━━┓
┃┃┃┃┃┃┏━━┫┃  ┃┏━┓┃
┃┃┃┃┃┃┗━━┫┃  ┃┃ ┃┃
┃┗┛┗┛┃┏━━┫┃ ┏┫┗━┛┃
┗┓┏┓┏┫┗━━┫┗━┛┃┏━┓┃
 ┗┛┗┛┗━━━┻━━━┻┛ ┗┛
  by Yamato Security

"@

$usage = @"
Usage:
  ./WELA.ps1 audit-settings -Baseline YamatoSecurity     # Audit current setting and show in stdout, save to csv
  ./WELA.ps1 audit-settings -Baseline ASD -OutType gui   # Audit current setting and show in gui, save to csv
  ./WELA.ps1 audit-filesize -Baseline YamatoSecurity     # Audit current file size and show in stdout, save to csv
  ./WELA.ps1 configure -Baseline YamatoSecurity          # Configure audit settings based on the specified baseline
  ./WELA.ps1 configure -Baseline YamatoSecurity -Auto    # Configure audit settings automatically without prompts
  ./WELA.ps1 update-rules         # Update rule config files from https://github.com/Yamato-Security/WELA
  ./WELA.ps1 help        # Show this help
"@


[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host $logo -ForegroundColor Green

switch ($Cmd.ToLower()) {
    "audit-settings"  {
        if ($Help -or [string]::IsNullOrEmpty($Baseline)){
            Write-Host "Audit current Windows Event Log settings and compare with baseline"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 audit-settings -Baseline <YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server> [-OutType <std|gui|table>]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Baseline    Specify the baseline (YamatoSecurity, ASD, Microsoft_Client, Microsoft_Server)"
            Write-Host "  -OutType     Output type: std (default) or gui or table"
            Write-Host ""
            return
        }
        $validGuides = @("YamatoSecurity", "ASD", "Microsoft_Client", "Microsoft_Server")
        if (-not ($validGuides -contains $Baseline.ToLower())) {
            Write-Host "Invalid Guide specified. Valid options are: YamatoSecurity, ASD, Microsoft_Client, Microsoft_Server."
            break
        }
        AuditLogSetting $OutType $Baseline $Debug
    }
    "audit-filesize" {
        if ($Help -or [string]::IsNullOrEmpty($Baseline)){
            Write-Host "Audit current Windows Event Log file sizes"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 audit-filesize -Baseline <YamatoSecurity>"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Baseline    Specify the baseline (YamatoSecurity)"
            Write-Host ""
            return
        }
        AuditFileSize $Baseline
    }

    "configure" {
        if ($Help -or [string]::IsNullOrEmpty($Baseline)){
            Write-Host "Configure Windows Event Log audit settings based on specified baseline"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 configure -Baseline <YamatoSecurity> [-Auto]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Baseline    Specify the baseline (YamatoSecurity)"
            Write-Host "  -Auto        Automatically configure without prompts"
            Write-Host ""
            return
        }
        if ([string]::IsNullOrEmpty($Baseline)) {
            Write-Host "You need to specify a baseline. The following baselines are available:"
            Write-Host "  * YamatoSecurity"
            Write-Host ""
            Write-Host "Examples: "
            Write-Host "./WELA.ps1 configure -Baseline YamatoSecurity"
            Write-Host "./WELA.ps1 configure -Baseline YamatoSecurity -Auto"
            Write-Host ""
            break
        }
        ConfigureAuditSettings -Baseline $Baseline -Auto:$Auto
    }

    "update-rules" {
        if ($Help) {
            Write-Host "Update detection rule configuration files from GitHub repository"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 update-rules"
            Write-Host ""
            Write-Host "Download and update rule configuration files from GitHub repository"
            Write-Host ""
            return
        }
        UpdateRules
    }
    "help" {
        Write-Host $usage
    }
    default {
        Write-Host "Invalid command. Use 'help' to see available commands."
        Write-Host $usage
    }
}