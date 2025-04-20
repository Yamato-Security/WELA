class WELA {
    static [array] $Levels = @('critical', 'high', 'medium', 'low', 'informational')
    [string] $Category
    [string] $SubCategory
    [bool] $Enabled
    [array] $Rules
    [hashtable] $RulesCount
    [string] $DefaultSetting = ""
    [string] $RecommendedSetting = ""
    [string] $Volume = ""
    [string] $Note = ""

    WELA([string] $Category, [string] $SubCategory, [bool] $Enabled, [array] $Rules) {
        $this.Category = $Category
        $this.SubCategory = $SubCategory
        $this.Enabled = $Enabled
        $this.Rules = $Rules
        $this.RulesCount = @{'critical' = 0; 'high' = 0; 'medium' = 0; 'low' = 0; 'informational' = 0}
    }


    WELA([string] $Category, [string] $SubCategory, [bool] $Enabled, [array] $Rules, [string] $DefaultSetting, [string] $RecommendedSetting, [string] $Volume, [string] $Note) {
        $this.Category = $Category
        $this.SubCategory = $SubCategory
        $this.Enabled = $Enabled
        $this.Rules = $Rules
        $this.DefaultSetting = $DefaultSetting
        $this.RecommendedSetting = $RecommendedSetting
        $this.Volume = $Volume
        $this.Note = $Note
        $this.RulesCount = @{'critical' = 0; 'high' = 0; 'medium' = 0; 'low' = 0; 'informational' = 0}
    }

    [void] SetApplicable([array] $Enabledguid) {
        if ($this.Enabled) {
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
            $this.RulesCount[$level] = ($this.Rules | Where-Object { $_.level -eq $level }).Count
        }
    }

    [void] Output([string] $Format) {
        switch ($Format.ToLower()) {
            "std" {
                $color = if ($this.Enabled) { "Green" } else { "Red" }
                $ruleCounts = ""
                $logEnabled = if ($this.Enabled) { "Enabled" } else { "Disabled" }
                $allZero = $this.RulesCount.Values | Where-Object { $_ -ne 0 } | Measure-Object | Select-Object -ExpandProperty Count
                if ($allZero -eq 0) {
                    $ruleCounts = "(no rules)"
                    $color = "DarkYellow"
                } else {
                    $ruleCounts = "$($logEnabled) ("
                    foreach ($level in [WELA]::Levels) {
                        $count = $this.RulesCount[$level]
                        if ($level -eq "informational") {
                            if (-not $count) {
                                $count = 0 # 明示的に0を設定しないと空文字列に変換されるため
                            }
                            $ruleCounts += "info:$([string]$count)"
                        } else {
                            $ruleCounts += "$($level):$($count), "
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

function AuditLogSetting {
    param (
        [string] $outType,
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
    }
    $auditResult = @()

    # Application
    $guid    = ""
    $eids     = @()
    $channels = @("Application")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $auditResult += [WELA]::New(
            "Application",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 20 MB",
            "Enabled. 128 MB+",
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
    $auditResult += [WELA]::New(
            "Applocker",
            "",
            $enabled,
            [array]$rules,
            "Enabled if AppLocker is enabled? 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "Diagnosis-Scripted Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "DriverFrameworks-UserMode Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "Firewall",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
            "",
            ""
    )

    # NTLM Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-Diagnosis-Scripted/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $auditResult += [WELA]::New(
            "Microsoft-Windows-NTLM/Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "This log is recommended to enable if you want to disable NTLM authentication",
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
    $auditResult += [WELA]::New(
            "PowerShell",
            "Classic",
            $enabled,
            [array]$rules,
            "Enabled. 15 MB",
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
    $auditResult += [WELA]::New(
            "PowerShell",
            "Module",
            $enabled,
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
    $auditResult += [WELA]::New(
            "PowerShell",
            "ScriptBlock",
            $enabled,
            [array]$rules,
            "On Win 10/2016+, if a PowerShell script is flagged as suspicious by AMSI, it will be logged with a level of Warning",
            "Enabled",
            "High",
            ""
    )

    # PrintService Admin
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-PrintService/Admin")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Admin",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "PrintService",
            "PrintService Operational",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Credential Validation",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Authentication Service",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Logon)",
            "Kerberos Service Ticket Operations",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Computer Account Management",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Other Account Management Events",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "Security Group Management",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Account Management)",
            "User Account Management",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Plug and Play Events",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Creation",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure if sysmon is not configured",
            "High",
            ""
    )

    #### Process Termination
    $guid    = "0CCE922C-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Process Termination",
            $enabled,
            [array]$rules,
            "No Auditing",
            "No Auditing unless you want to track the lifespan of processes",
            "High",
            ""
    )

    #### RPC Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "RPC Events",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Unknown. Needs testing",
            "High on RPC servers (According to Microsoft)",
            ""
    )

    #### Token Right Adjusted Events
    $guid    = "0CCE922E-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Detailed Tracking)",
            "Token Right Adjusted Events",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Unknown. Needs testing",
            "Unknown",
            ""
    )

    ### DS (Directory Service) Access
    #### Directory Service Access
    $guid    = "0CCE923B-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Access",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (DS Access)",
            "Directory Service Changes",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Account Lockout",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Group Membership",
            $enabled,
            [array]$rules,
            "No Auditing",
            "No Auditing",
            "Adds an extra 4627 event to every logon",
            ""
    )

    #### Logon
    $guid    = "0CCE9215-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Logon",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Other Logon/Logoff Events",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Logon/Logoff)",
            "Special Logon",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Certification Services",
            $enabled,
            [array]$rules,
            "No Auditing",
            "No Auditing due to the high noise level. Enable if you can though",
            "Very high for file servers and DCs, however, may be necessary if you want to track who is accessing what files as well as detect various lateral movement",
            ""
    )

    #### File Share
    $guid    = "0CCE9224-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File Share",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "File System",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Enable SACLs just for sensitive files",
            "Depends on SACL rules",
            ""
    )

    #### Filtering Platform Connection
    $guid    = "0CCE9226-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Connection",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though",
            "High",
            ""
    )

    #### Filtering Platform Packet Drop
    $guid    = "0CCE9225-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Filtering Platform Packet Drop",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure for AD CS role servers",
            "High",
            ""
    )

    #### Kernel Object
    $guid    = "0CCE921F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Kernel Object",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure but do not enable Audit the access of global system objects as you will generate too many 4663: Object Access events",
            "High if auditing access of global object access is enabled",
            ""
    )

    #### Handle Manipulation
    $guid    = "0CCE9223-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Handle Manipulation",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Other Object Access Events",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Registry",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Set SACLs for only the registry keys that you want to monitor",
            "Depends on SACLs",
            ""
    )

    #### Removable Storage
    $guid    = "0CCE9245-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "Removable Storage",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure if you want to monitor external device usage",
            "Depends on how much removable storage is used",
            ""
    )

    #### SAM
    $guid    = "0CCE9220-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Object Access)",
            "SAM",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure for AD CS role servers",
            "Success and Failure if you can but may cause too high volume of noise so should be tested beforehand",
            ""
    )

    ### Policy Change
    #### Audit Policy Change
    $guid    = "0CCE922F-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Audit Policy Change",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authentication Policy Change",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Authorization Policy Change",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Unknown. Needs testing",
            "Medium to High",
            ""
    )

    #### Filtering Platform Policy Change
    $guid    = "0CCE9233-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Filtering Platform Policy Change",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Unknown, Needs testing",
            "Low",
            ""
    )

    #### MPSSVC Rule-Level Policy Change
    $guid    = "0CCE9232-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "MPSSVC Rule-Level Policy Change",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Unknown, Needs testing",
            "Low",
            ""
    )

    #### Other Policy Change Events
    $guid    = "0CCE9234-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Policy Change)",
            "Other Policy Change Events",
            $enabled,
            [array]$rules,
            "No Auditing",
            "No Auditing (Note: ACSC recommends Success and Failure, however, this results in a lot of noise of 5447 (A Windows Filtering Platform filter has been changed) events being generated.)",
            "Low",
            ""
    )

    ### Privilege Use
    #### Non-Sensitive Privilege Use
    $guid    = "0CCE9229-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Non-Sensitive Privilege Use",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (Privilege Use)",
            "Sensitive Privilege Use",
            $enabled,
            [array]$rules,
            "No Auditing",
            "Success and Failure However, this may be too noisy",
            "High",
            ""
    )

    ### System
    #### Other System Events
    $guid    = "0CCE9214-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $enabled,
            [array]$rules,
            "Success and Failure",
            "Unknown. Needs testing",
            "Low",
            ""
    )

    #### Security State Change
    $guid    = "0CCE9210-69AE-11D9-BED3-505054503030"
    $eids     = @()
    $channels = @("sec")
    $enabled  = $enabledguid -contains $guid
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Other System Events",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "Security System Extension",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security Advanced (System)",
            "System Integrity",
            $enabled,
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
    $auditResult += [WELA]::New(
            "Security-Mitigations KernelMode",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "Security-Mitigations UserMode",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 256 MB+",
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
    $auditResult += [WELA]::New(
            "SMBClient Security",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 8 MB",
            "Enabled. 128 MB+",
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
    $auditResult += [WELA]::New(
            "System",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 20 MB",
            "Enabled. 128 MB+",
            "",
            ""
    )

    # TaskScheduler Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-TaskScheduler/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    | ForEach-Object { $_.applicable = $enabled }
    $auditResult += [WELA]::New(
            "TaskScheduler Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
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
    $auditResult += [WELA]::New(
            "TerminalServices-LocalSessionManager Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
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
    $auditResult += [WELA]::New(
            "WMI-Activity Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
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
    $auditResult += [WELA]::New(
            "Windows Defender Operational",
            "",
            $enabled,
            [array]$rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
            "",
            ""
    )

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
            if ($level -eq "informational") {
                if (-not $count) {
                    $count = 0
                }
                $ruleCounts += "info:$([string]$count)"
            } else {
                $ruleCounts += "$($level):$($count), "
            }
        }
        $_.RuleCountByLevel = $ruleCounts
    }

    if ($outType -eq "std") {
        $auditResult | Group-Object -Property Category | ForEach-Object {
            $enabledCount = ($_.Group | Where-Object { $_.Enabled -eq $true } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $disabledCount = ($_.Group | Where-Object { $_.Enabled -eq $false } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
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
            if ($_.Name -notmatch "Powershell" -and $_.Name -notmatch "Security") {
                $enabledPercentage = ""
            }
            Write-Host "$( $_.Name ): $out$($enabledPercentage)" -ForegroundColor $color
            $_.Group | ForEach-Object {
                $_.Output($outType)
            }
            Write-Host ""
        }
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, Enabled, DefaultSetting, RecommendedSetting, Volume, Note | Export-Csv -Path "WELA-Audit-Result.csv" -NoTypeInformation
        Write-Output "Audit check result saved to: WELA-Audit-Result.csv"
    } elseif ($outType -eq "gui") {
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, Enabled, DefaultSetting, RecommendedSetting, Volume, Note | Out-GridView -Title "WELA Audit Result"
    } elseif ($outType -eq "table") {
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, Enabled, DefaultSetting, RecommendedSetting, Volume | Format-Table
    }
    $usableRules     = $auditResult | Select-Object -ExpandProperty Rules | Where-Object { $_.applicable -eq $true }
    $unUsableRules   = $auditResult | Select-Object -ExpandProperty Rules | Where-Object { $_.applicable -eq $false }
    $usableules | Select-Object title, level, id | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
    $unusableRules  | Select-Object title, level, id | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation
    Write-Output "Usable detection rules list saved to: UsableRules.csv"
    Write-Output "Unusable detection rules list saved to: UnusableRules.csv"

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


function AuditFileSize {
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
        $correctSetting = if ($maxLogSize -ge $recommendedSize) { "Y" } else { "N" }

        $results += [PSCustomObject]@{
            LogFile         = Split-Path $logInfo.LogFilePath -Leaf
            CurrentLogSize  = "{0:N2} MB" -f ($logInfo.FileSize / 1MB)
            MaxLogSize      = "$maxLogSize MB"
            Default         = $logNames[$logName][0]
            Recommended     = $logNames[$logName][1]
            CorrectSetting  = $correctSetting
            IsLogFull       = $logInfo.IsLogFull
            LogMode         = $logInfo.LogMode
        }
    }

    # Format-Tableには色つき出力の機能はないので、Write-Hostで色をつける
    $tableLayout = "{0,-75} {1,-15} {2,-15} {3,-15} {4,-15} {5,-10}"
    Write-Host ($tableLayout -f `
        "Log File", `
        "Current Size", `
        "Max Size", `
        "Default", `
        "Recommended", `
        "Correct Setting", `
        "Is Log Full", `
        "Log Mode" `
        )
    Write-Host ($tableLayout -f `
        "--------", `
        "------------", `
        "--------", `
        "------", `
        "-----------", `
        "--------------")
    foreach ($result in $results) {
        $color = if ($result.CorrectSetting -eq "Y") { "Green" } else { "Red" }
        Write-Host ($tableLayout -f `
        $result.LogFile, `
        $result.CurrentLogSize, `
        $result.MaxLogSize, `
        $result.Default, `
        $result.Recommended, `
        $result.CorrectSetting, `
        $result.IsLogFull, `
        $result.LogMode `
        ) -ForegroundColor $color
    }

    $results | Export-Csv -Path "WELA-FileSize-Result.csv" -NoTypeInformation
    Write-Host ""
    Write-Host "Audit file size result saved to: WELA-FileSize-Result.csv"
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

$help = @"
Usage:
  ./WELA.ps1 audit-settings       # Audit current setting and show in stdout, save to csv
  ./WELA.ps1 audit-settings gui   # Audit current setting and show in gui, save to csv
  ./WELA.ps1 audit-settings table # Audit current setting and show in table layout, save to csv
  ./WELA.ps1 audit-filesize       # Audit current file size and show in stdout, save to csv
  ./WELA.ps1 help        # Show this help
"@

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host $logo -ForegroundColor Green

if ($args.Count -eq 0) {
    Write-Host $help
    exit 1
}

$command = $args[0].ToLower()

switch ($command) {
    "audit-settings"  {
        $outType = "std"
        $debug = $false
        if ($args.Count -eq 2) {
            $outType = $args[1].ToLower()
        }
        if ($args.Count -eq 3) {
            $outType = $args[1].ToLower()
            $debug = $args[2].ToLower() -eq "debug"
        }
        AuditLogSetting $outType $debug
    }
    "audit-filesize" {
        AuditFileSize
    }

    "help" {
        Write-Host $help
    }
    default {
        Write-Host $help
    }
}