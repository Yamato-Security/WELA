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
                $logEnabled = if ($this.Enabled) { "Enabled" } else { "Disabled" }
                $ruleCounts = ""
                $allZero = $this.RulesCount.Values | Where-Object { $_ -ne 0 } | Measure-Object | Select-Object -ExpandProperty Count
                if ($allZero -eq 0) {
                    $ruleCounts = "no rules"
                    $color = "DarkYellow"
                } else {
                    $ruleCounts = "$($logEnabled) ("
                    foreach ($level in [WELA]::Levels) {
                        $count = $this.RulesCount[$level]
                        if ($level -eq "informational") {
                            if (-not $count) {
                                $count = 0
                            }
                            $ruleCounts += "info:$([string]$count)"
                        } else {
                            $ruleCounts += "$($level):$($count), "
                        }
                    }
                    $ruleCounts += ")"
                }
                if ($this.Category -ne "PowerShell" -and $this.Category -notcontains "Security") {
                    Write-Host "$($this.Category): $ruleCounts" -ForegroundColor $color

                }
                if ($this.SubCategory) {
                    Write-Host "  - $($this.SubCategory): $ruleCounts" -ForegroundColor $color
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
        if ($category_channels -contains $rule.channel) {
            $result = $true
        } else {
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
        [string] $outType
    )
    $autidpolTxt = "./auditpol.txt"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $autidpolTxt
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
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Application",
            "",
            $enabled,
            $rules,
            "Enabled. 20 MB",
            "Enabled. 128 MB+",
            "",
            ""
    )

    # Applocker
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-AppLocker/MSI and Script")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "AppLocker",
            "",
            $enabled,
            $rules,
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
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "Bits-Client Operational",
            "",
            $enabled,
            $rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
            "",
            ""
    )

    # CodeIntegrity Operational
    $guid    = ""
    $eids     = @()
    $channels = @("Microsoft-Windows-CodeIntegrity/Operational")
    $enabled  = $true
    $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
    $rules    = ApplyRules -enabled $enabled -rules $all_rules -guid $guid
    $auditResult += [WELA]::New(
            "CodeIntegrity Operational",
            "",
            $enabled,
            $rules,
            "Enabled. 1 MB",
            "Enabled. 128 MB+",
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
            $rules,
            "Client OS: No Auditing | Server OS: Success",
            "Client and Server OSes: Success and Failure",
            "Depends on NTLM usage. Could be high on DCs and low on clients and servers.",
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
            $rules
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
            $rules
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
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
            $rules,
            "Success and Failure",
            "Success and Failure",
            "Low",
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
            $enabledCount = ($_.Group | Where-Object { $_.Enabled -eq $false }).Count -eq 0
            $disabledCount = ($_.Group | Where-Object { $_.Enabled -eq $true }).Count -eq 0
            $out = ""
            $color = ""
            if ($enabledCount)
            {
                $out = "Enabled"
                $color = "Green"
            }
            elseif ($disabledCount)
            {
                $out = "Disabled"
                $color = "Red"
            }
            else
            {
                $out = "Partially Enabled"
                $color = "DarkYellow"
            }
            Write-Host "$( $_.Name ): $out" -ForegroundColor $color
            $_.Group | ForEach-Object {
                $_.Output($outType)
            }
            Write-Host ""
        }
        $auditResult | Select-Object -Property Category, SubCategory, TotalRules, TotalRuleByLevel, Enabled, DefaultSetting, RecommendedSetting, Volume, Note | Export-Csv -Path "WELA-Audit-Result.csv" -NoTypeInformation
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
  ./WELA.ps1 audit       # Audit current setting and show in stdout, save to csv
  ./WELA.ps1 audit gui   # Audit current setting and show in gui, save to csv
  ./WELA.ps1 audit table # Audit current setting and show in table layout, save to csv
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
    "audit"  {
        $outType = "std"
        if ($args.Count -eq 2) {
            $outType = $args[1].ToLower()
        }
        AuditLogSetting $outType
    }
    "help" {
        Write-Host $help
    }
    default {
        Write-Host $help
    }
}