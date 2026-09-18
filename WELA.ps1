param (
    [string]$Cmd,
    [string]$OutType = "std",
    [switch]$Debug,
    [string]$Baseline,
    [string]$Profile,
    [ValidateSet("Client", "MemberServer", "DomainController", "ADCS")][string]$Role,
    [int]$Build,
    [string]$PlanPath,
    [switch]$IncludeOptional,
    [switch]$Auto,
    [ValidateSet("PreserveOrAudit", "Audit", "Deny")]
    [string]$OutgoingNtlmMode = "PreserveOrAudit",
    [switch]$DryRun,
    [string]$BackupPath,
    [string]$ResultsPath,
    [switch]$Help
)

$WELAVersion     = "2.2.0"
$WELAReleaseName = "Dev Release"

# 実行時のカレントディレクトリに依存しないよう、すべてスクリプトの場所を基準にする
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$BaselineConfigPath = Join-Path $ScriptRoot "config/baselines.json"
$SecurityRulesPath  = Join-Path $ScriptRoot "config/security_rules.json"
$EidMappingPath     = Join-Path $ScriptRoot "config/eid_subcategory_mapping.csv"
$AuditpolTxtPath    = Join-Path $ScriptRoot "auditpol.txt"
$SaclTargetsPath    = Join-Path $ScriptRoot "config/audit_sacl_targets.json"
. (Join-Path $ScriptRoot "scripts/Configuration.ps1")
Import-Module (Join-Path $ScriptRoot "modules/AuditProfiles.psm1") -ErrorAction Stop

# 64bit の PowerShell と GPO が読むのは Wow6432Node の無いパス。32bit 用に両方を扱う。
$PowerShellPolicyRoots = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
    "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell"
)

class WELA {
    static [array] $Levels = @('critical', 'high', 'medium', 'low', 'informational')
    [string] $Category
    [string] $SubCategory
    [string] $CurrentSetting = ""
    [string] $AuditPolicyGuid = ""
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

    [void] CountByLevel() {
        $this.RulesCount = @{}
        foreach ($level in [WELA]::Levels) {
            $this.RulesCount[$level] = @($this.Rules | Where-Object { $_.level -eq $level }).Count
        }
    }

    [void] Output([string] $Format) {
        switch ($Format.ToLower()) {
            "std" {
                # -contains は文字列に対しては完全一致なので、部分一致には -like を使う
                $color = if ($this.CurrentSetting -eq "Enabled" -or $this.CurrentSetting -like "*Success*" -or $this.CurrentSetting -like "*Failure*") { "Green" }
                         elseif ($this.CurrentSetting -eq "Unknown") { "DarkYellow" }
                         else { "Red" }
                $ruleCounts = ""
                $logEnabled = $this.CurrentSetting
                $nonZeroLevels = ($this.RulesCount.Values | Where-Object { $_ -ne 0 }).Count
                if ($nonZeroLevels -eq 0) {
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
    # 指定されたサブカテゴリGUIDを持つルールを抜き出すだけの関数。
    # applicable の更新は BuildAuditResult 側でカテゴリ横断のORとして行う。
    param (
        [array] $rules,
        [string] $guid
    )
    return ,@($rules | Where-Object { $_.subcategory_guids -contains $guid }) # 暗黙の型変換でPSCustomObjectに変換されてしまうため、型を明示
}


function RuleFilter {
    # 指定された条件をすべて満たすルールだけを通す(AND)。
    # 空の条件は「指定なし」として無視するが、条件が1つも無い場合は何も通さない。
    [OutputType([bool])]
    param (
        [pscustomobject] $rule,
        [array] $category_eids,
        [array] $category_channels,
        [string] $category_guid
    )
    $hasCriteria = $false

    if ($category_channels.Count -gt 0) {
        $hasCriteria = $true
        if (-not ($rule.channel | Where-Object { $category_channels -contains $_ })) {
            return $false
        }
    }
    if ($category_eids.Count -gt 0) {
        $hasCriteria = $true
        # event_ids を持たないルールは、EIDで絞られたカテゴリには属さない
        if (-not ($rule.event_ids | Where-Object { $category_eids -contains $_ })) {
            return $false
        }
    }
    if ($category_guid) {
        $hasCriteria = $true
        if (-not ($rule.subcategory_guids | Where-Object { $category_guid -eq $_ })) {
            return $false
        }
    }
    return $hasCriteria
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
    # auditpol /r の出力は CRCRLF や chcp の行が混ざるため、行数の決め打ちはせず
    # 「GUIDらしき列を持つ行」だけを拾う。権限不足時のエラー行なども自然に無視される。
    $mapping = @{}
    if (-not (Test-Path -Path $script:AuditpolTxtPath)) {
        Write-Host "[ERROR] Audit policy output not found: $script:AuditpolTxtPath" -ForegroundColor Red
        return $mapping
    }
    Get-Content -Path $script:AuditpolTxtPath | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            return
        }
        $columns = $_ -split ','
        if ($columns.Count -lt 5) {
            return  # ヘッダ行や "Active code page: 437"、エラーメッセージなど
        }
        $guid = $columns[3].Trim() -replace '^\{|\}$', ''  # 波括弧を削除
        if ($guid -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') {
            return
        }
        $inclusionSetting = $columns[4].Trim()
        if ($inclusionSetting) {
            $mapping[$guid] = $inclusionSetting
        }
    }
    return $mapping
}

function TestWindows {
    # Windows PowerShell 5.1 には $IsWindows が無いが、その場合は必ず Windows
    return ($null -eq $IsWindows) -or $IsWindows
}

function TestAdministrator {
    if (-not (TestWindows)) {
        return $true  # 非Windows(検証用)ではチェックしない
    }
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function CollectAuditpol {
    # auditpol の出力を取得する。取得できたかどうかを返す。
    param ([switch] $UseCached)

    if ($UseCached) {
        return (Test-Path -Path $script:AuditpolTxtPath)
    }
    try {
        Start-Process -FilePath "cmd.exe" `
                      -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" `
                      -NoNewWindow -Wait -RedirectStandardOutput $script:AuditpolTxtPath -ErrorAction Stop
    } catch {
        Write-Host "[ERROR] Failed to run auditpol: $_" -ForegroundColor Red
        return $false
    }
    if (-not (Test-Path -Path $script:AuditpolTxtPath)) {
        return $false
    }
    # 権限不足などで1件も取得できていないケースを検出する
    if ((GetAuditpol).Count -eq 0) {
        Write-Host "[ERROR] auditpol returned no subcategories. Administrator privileges are required." -ForegroundColor Red
        return $false
    }
    return $true
}

function AsArray {
    # ConvertFrom-Json returns $null for an absent property and a bare scalar for
    # a single-element array, so normalise before handing anything to RuleFilter.
    param ($value)
    if ($null -eq $value) {
        return @()
    }
    return , @($value)
}

function GetBaselineConfig {
    if (-not (Test-Path -Path $script:BaselineConfigPath)) {
        throw "Baseline config not found: $script:BaselineConfigPath"
    }
    return Get-Content -Path $script:BaselineConfigPath -Raw | ConvertFrom-Json
}

function GetBaselineNames {
    return @((GetBaselineConfig).baselines.PSObject.Properties.Name)
}

function Get-WelaSelectedContext {
    if (($script:Role -and -not $script:Build) -or ($script:Build -and -not $script:Role)) {
        throw "Specify both -Role and -Build, or neither to detect this Windows host."
    }
    if ($script:Role -and $script:Build) {
        return [pscustomobject]@{ Role = $script:Role; Build = $script:Build }
    }
    Get-WelaHostContext
}

function Show-WelaAuditProfilePrerequisites {
    param($Plan)
    foreach ($policy in $Plan.policies) {
        if ($policy.prerequisites -and ($policy.mode -in @('exact', 'minimum') -or ($policy.mode -eq 'optional' -and $Plan.includeOptional))) {
            Write-Host "Prerequisite - $($policy.id): $($policy.prerequisites)" -ForegroundColor DarkYellow
        }
    }
}

function Invoke-WelaProfileCommand {
    param([string]$Command)
    if ($script:Baseline) { throw "Use -Profile or -Baseline, not both. Versioned profiles cover advanced audit policy and its precedence prerequisite." }
    if (-not $script:Profile) { throw "Specify -Profile. Use './WELA.ps1 profiles' to list versioned profiles." }
    $context = Get-WelaSelectedContext
    $current = @{}
    if (TestWindows) {
        $actual = Get-WelaHostContext
        if ($actual.Role -eq $context.Role -and $actual.Build -eq $context.Build) { $current = Get-WelaEffectiveAuditPolicy }
        elseif ($Command -ne 'plan') { throw "Requested role/build does not match this Windows host." }
        else { Write-Host "Planning for another role/build: effective state remains Unknown." }
    }
    elseif ($Command -ne 'plan') { throw "Audit and configure require Windows. Offline planning requires explicit -Role and -Build." }
    $plan = Get-WelaAuditProfilePlan -Profile $script:Profile -Role $context.Role -Build $context.Build -Current $current -IncludeOptional:$script:IncludeOptional
    $precedence = Get-WelaAuditPrecedenceState -Offline:($current.Count -eq 0)
    $plan | Add-Member NoteProperty AuditPrecedence $precedence
    Write-Host "Profile: $($plan.profile); role: $($plan.role); build: $($plan.build)"
    Write-Host "Scope: advanced audit policy and its subcategory-precedence prerequisite. Channels, command-line capture, PowerShell, NTLM, SACLs, CA AuditFilter and forwarding are separate."
    Write-Host "Audit precedence: $($precedence.State); required SCENoApplyLegacyAuditPolicy=1 (DWORD). $($precedence.Diagnostic)"
    if ($precedence.PolicySource) { Write-Host $precedence.PolicySource.Description }
    Show-WelaAuditProfilePrerequisites -Plan $plan
    $result = $plan
    if ($Command -eq 'configure') {
        if (-not (TestAdministrator)) { throw "Configuring advanced audit policy requires Administrator privileges." }
        Assert-WelaAuditProfileTarget -Plan $plan -Context $actual -Current $current
        $configurationContext = New-WelaConfigurationContext -Auto:$script:Auto -DryRun:$script:DryRun -BackupPath $script:BackupPath
        Set-WelaProfileAuditControls -Context $configurationContext -Plan $plan
        $result = Complete-WelaConfiguration -Context $configurationContext -ResultsPath $script:ResultsPath -Plan $plan -Scope advanced-audit-policy-and-precedence
        $result.Results | Format-Table Id, Before, Desired, After, Status -AutoSize
    } else {
        $plan.policies | Format-Table id, mode, currentMask, requiredMask, action -AutoSize
    }
    if ($script:PlanPath) {
        $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:PlanPath -Encoding UTF8 -ErrorAction Stop
        Write-Host "Machine-readable result: $($script:PlanPath)"
    }
    if ($Command -eq 'configure' -and $result.ExitCode -ne 0) { throw "One or more advanced audit policies failed. See the effective-state results." }
}

function BuildAuditResult {
    param (
        [object[]] $all_rules,
        [string]   $Baseline,
        [array]    $enabledguid
    )

    $config = GetBaselineConfig

    # ベースライン名は大文字小文字を無視して解決する
    $baselineName = $config.baselines.PSObject.Properties.Name |
            Where-Object { $_ -eq $Baseline } |
            Select-Object -First 1
    if (-not $baselineName) {
        throw "Unknown baseline '$Baseline'. Available: $($config.baselines.PSObject.Properties.Name -join ', ')"
    }
    $settings = $config.baselines.$baselineName

    $auditpol = GetAuditpol
    $auditResult = @()
    $sharedPlan = $null
    if ($baselineName -eq 'YamatoSecurity') {
        $context = Get-WelaSelectedContext
        $sharedPlan = Get-WelaAuditProfilePlan -Profile 'wela-2.2.0' -Role $context.Role -Build $context.Build -IncludeOptional:$script:IncludeOptional
        Write-Host "Advanced audit recommendations: $($sharedPlan.profile), role $($sharedPlan.role), build $($sharedPlan.build). Other controls use the existing baseline metadata."
    }

    foreach ($item in $config.catalog) {
        # The versioned profile owns all advanced-audit recommendations and canonical GUIDs.
        if ($sharedPlan -and $item.currentSetting.type -eq 'auditpol') { continue }
        $setting = $settings.($item.id)
        if (-not $setting) {
            throw "Baseline '$baselineName' has no entry for catalog id '$($item.id)'."
        }

        # 現在の設定と、そのサブカテゴリ/チャネルが有効かどうかを決める
        switch ($item.currentSetting.type) {
            "static" {
                $enabled = $true
                $current = $item.currentSetting.value
            }
            "auditpol" {
                $enabled = $enabledguid -contains $item.select.guid
                $current = $auditpol[$item.select.guid]
            }
            "channel" {
                # レジストリの Enabled 値はマニフェストの既定値のままだと存在しないことがあり、
                # 「値が無い」を無効と解釈すると既定で有効なチャネルを誤判定する。
                # また役割未導入でチャネル自体が無い場合と無効化されている場合も区別できないため、
                # 実際のチャネル状態を Get-WinEvent から取得する。
                $logInfo = $null
                try {
                    # Windows 以外や役割未導入の環境では取得できないので、その場合は判定不能とする
                    $logInfo = Get-WinEvent -ListLog $item.currentSetting.channel -ErrorAction Stop
                } catch {
                    $logInfo = $null
                }
                if ($null -eq $logInfo) {
                    $enabled = $false
                    $current = "Unknown"
                } else {
                    $enabled = [bool]$logInfo.IsEnabled
                    $current = if ($enabled) { "Enabled" } else { "Disabled" }
                }
            }
            "registry" {
                # 64bit/32bit でレジストリビューが分かれる設定があるため、いずれかで有効なら有効とみなす
                $enabled = $false
                foreach ($path in (AsArray $item.currentSetting.paths)) {
                    if (CheckRegistryValue -registryPath $path `
                                           -valueName $item.currentSetting.name `
                                           -expectedValue $item.currentSetting.value) {
                        $enabled = $true
                        break
                    }
                }
                $current = if ($enabled) { "Enabled" } else { "Disabled" }
            }
            default {
                throw "Unknown currentSetting type '$($item.currentSetting.type)' for catalog id '$($item.id)'."
            }
        }

        # 該当するルールを抽出する
        if ($item.select.type -eq "guid") {
            $rules = ApplyRules -rules $all_rules -guid $item.select.guid
        } else {
            $eids     = AsArray $item.select.eventIds
            $channels = AsArray $item.select.channels
            $guid     = $item.select.guid
            $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
        }

        # 1つのルールは複数カテゴリに属しうるので、有効なカテゴリが1つでもあれば
        # 利用可能とする(OR)。カテゴリごとに上書きすると最後のカテゴリで結果が決まってしまう。
        if ($enabled) {
            $rules | ForEach-Object { $_.applicable = $true }
        }
        if ($setting.ideal) {
            $rules | ForEach-Object { $_.ideal = $true }
        }

        $auditResult += [WELA]::New(
                $item.category,
                $item.subCategory,
                $current,
                [array]$rules,
                $setting.defaultSetting,
                $setting.recommendedSetting,
                $setting.volume,
                $setting.note
        )
    }

    if ($sharedPlan) {
        foreach ($policy in $sharedPlan.policies) {
            $rules = ApplyRules -rules $all_rules -guid $policy.guid
            $current = if ($policy.mode -eq 'not-applicable') { 'Not applicable' }
                       elseif ($auditpol.ContainsKey($policy.guid)) { $auditpol[$policy.guid] }
                       else { 'Unknown' }
            if ($policy.mode -ne 'not-applicable' -and $enabledguid -contains $policy.guid) {
                $rules | ForEach-Object { $_.applicable = $true }
            }
            if ($policy.mode -in @('exact', 'minimum') -and $policy.requiredMask -ne 0) {
                $rules | ForEach-Object { $_.ideal = $true }
            }
            $legacyItem = $config.catalog | Where-Object { $_.subCategory -eq $policy.id -and $_.currentSetting.type -eq 'auditpol' } | Select-Object -First 1
            $legacy = if ($legacyItem) { $settings.($legacyItem.id) } else { $null }
            $defaultSetting = if ($legacy) { $legacy.defaultSetting } else { '' }
            $volume = if ($legacy) { $legacy.volume } else { '' }
            $note = (@($policy.prerequisites, $policy.note) | Where-Object { $_ }) -join ' '
            $entry = [WELA]::New("Security Advanced ($($policy.category))", $policy.id, $current, [array]$rules,
                $defaultSetting, $policy.recommendation, $volume, $note)
            $entry.AuditPolicyGuid = $policy.guid
            $auditResult += $entry
        }
    }

    # どのカテゴリにも該当しなかったルールを取りこぼさない。
    # 集計対象から黙って消えると、利用率の分母がルール総数と合わなくなる。
    $covered = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($entry in $auditResult) {
        foreach ($rule in $entry.Rules) {
            [void]$covered.Add($rule.id)
        }
    }
    $uncovered = @($all_rules | Where-Object { -not $covered.Contains($_.id) })
    if ($uncovered.Count -gt 0) {
        $auditResult += [WELA]::New(
                "Uncategorized",
                "",
                "Unknown",
                $uncovered,
                "",
                "",
                "",
                "Rules whose channel or subcategory is not covered by this baseline. WELA cannot tell whether these logs are enabled."
        )
    }

    return $auditResult
}



function AuditLogSetting {
    param (
        [string] $outType,
        [string] $Baseline,
        [switch] $debug
    )

    if (-not $debug -and -not (TestAdministrator)) {
        Write-Host "[ERROR] 'audit-settings' needs Administrator privileges to read the audit policy." -ForegroundColor Red
        return
    }
    if (-not (CollectAuditpol -UseCached:$debug)) {
        return
    }

    $enabledguid = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($guid in (GetAuditpol).GetEnumerator()) {
        if ($guid.Value -ne "No Auditing") {
            [void]$enabledguid.Add($guid.Key)
        }
    }
    if (-not (Test-Path -Path $script:SecurityRulesPath)) {
        Write-Host "[ERROR] Detection rules not found: $script:SecurityRulesPath" -ForegroundColor Red
        return
    }
    $all_rules = Get-Content -Path $script:SecurityRulesPath -Raw | ConvertFrom-Json
    $all_rules | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name "applicable" -Value $false
        $_ | Add-Member -MemberType NoteProperty -Name "ideal" -Value $false
    }
    $auditResult = BuildAuditResult -all_rules $all_rules -Baseline $Baseline -enabledguid $enabledguid
    $outgoingNtlm = Get-WelaOutgoingNtlmState
    $auditResult += [WELA]::new(
        "NTLM Authentication", "Outgoing NTLM policy", $outgoingNtlm.Description, @(),
        "Not configured (Allow all)", "Audit all (1); preserve intentional Deny all (2)", "",
        "RestrictSendingNTLMTraffic. Policy source: $($outgoingNtlm.PolicySource)"
    )

    # ベースラインが扱っていないサブカテゴリでも、そのサブカテゴリが有効ならルールは動く。
    # ルール自身が持つ subcategory_guids を見て救済する。
    # A live audit mask cannot make a role-inapplicable policy produce its events.
    $notApplicableGuids = @($auditResult | Where-Object {
        $_.CurrentSetting -eq 'Not applicable' -and $_.AuditPolicyGuid
    } | Select-Object -ExpandProperty AuditPolicyGuid)
    $all_rules | ForEach-Object {
        if (-not $_.applicable) {
            foreach ($guid in $_.subcategory_guids) {
                if ($enabledguid -contains $guid -and $notApplicableGuids -notcontains $guid) {
                    $_.applicable = $true
                    break
                }
            }
        }
    }

    $domainNtlm = Get-WelaDomainNtlmState
    $auditResult += [WELA]::new(
        "NTLM Authentication", "Domain NTLM auditing", $domainNtlm.Description, @(),
        "Not configured", "Enable all (7) on domain controllers only", "",
        "AuditNTLMInDomain; applicability is determined from Win32_OperatingSystem.ProductType."
    )
    $auditResult | ForEach-Object { $_.CountByLevel() }

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
            $notEnabled = @("No Auditing", "Disabled", "Unknown")
            $summaryRows = @($_.Group | Where-Object { $_.CurrentSetting -ne 'Not applicable' })
            $enabledCount = ($summaryRows | Where-Object { $notEnabled -notcontains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $disabledCount = ($summaryRows | Where-Object { $notEnabled -contains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $out = ""
            $color = ""
            if ($summaryRows.Count -eq 0) {
                $out = 'Not applicable'
                $color = 'DarkYellow'
            }
            elseif (@($summaryRows | Where-Object { $_.Rules.Count -gt 0 }).Count -eq 0) {
                # Configuration-only rows have no rule coverage to aggregate.
                # Preserve their observed state, including applicability and errors.
                $out = ($summaryRows | Select-Object -ExpandProperty CurrentSetting -Unique) -join '; '
                if (-not $out) { $out = 'Unknown' }
                $color = 'DarkYellow'
            }
            elseif (@($summaryRows | Where-Object { $_.CurrentSetting -ne "Unknown" }).Count -eq 0) {
                # 設定を確認できないカテゴリ。無効と断定はできない
                $out = "Unknown"
                $color = "DarkYellow"
            }
            elseif ($disabledCount -eq 0 -and $enabledCount -ne 0){
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
            $enabledPercentage = ""
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
    } elseif ($outType -eq "table") {
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, DefaultSetting, CurrentSetting, RecommendedSetting, Volume | Format-Table
    }

    # 1つのルールが複数カテゴリに属するため、集計とCSVはルールID単位で重複排除する
    $uniqueRules = $auditResult | Select-Object -ExpandProperty Rules | Sort-Object -Property id -Unique
    $usableRules   = @($uniqueRules | Where-Object { $_.applicable -eq $true })
    $unUsableRules = @($uniqueRules | Where-Object { $_.applicable -eq $false })

    $auditCsv    = Join-Path $script:ScriptRoot "WELA-Audit-Result.csv"
    $usableCsv   = Join-Path $script:ScriptRoot "UsableRules.csv"
    $unusableCsv = Join-Path $script:ScriptRoot "UnusableRules.csv"
    $currentJson = Join-Path $script:ScriptRoot "mitre-ttp-navigator-current.json"
    $idealJson   = Join-Path $script:ScriptRoot "mitre-ttp-navigator-ideal.json"

    $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, CurrentSetting, RecommendedSetting, Volume, Note | Export-Csv -Path $auditCsv -NoTypeInformation
    $usableRules   | Select-Object title, level, service, category, description, id | Export-Csv -Path $usableCsv -NoTypeInformation
    $unUsableRules | Select-Object title, level, service, category, description, id | Export-Csv -Path $unusableCsv -NoTypeInformation

    if ($outType -eq "gui") {
        $usableRules   | Select-Object title, level, service, category, description, id | Out-GridView -Title "Usable Detection Rules"
        $unUsableRules | Select-Object title, level, service, category, description, id | Out-GridView -Title "Unusable Detection Rules"
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, CurrentSetting, RecommendedSetting, Volume, Note | Out-GridView -Title "WELA Audit Result"
    }

    Write-Output "Audit check result saved to: $auditCsv"
    Write-Output "Usable detection rules list saved to: $usableCsv"
    Write-Output "Unusable detection rules list saved to: $unusableCsv"

    Export-MitreHeatmap -sigmaRules $uniqueRules -OutputPath $currentJson
    Write-Output "MITRE ATT&CK Navigator data(based on current settings) saved to: $currentJson"
    Export-MitreHeatmap -sigmaRules $uniqueRules -OutputPath $idealJson -UseIdealCount $true
    Write-Output "MITRE ATT&CK Navigator data(based on ideal settings) saved to: $idealJson"

    $totalRulesCount  = @($uniqueRules).Count
    $usableRulesCount = $usableRules.Count
    Write-Host ""
    if ($totalRulesCount -eq 0) {
        Write-Host "No detection rules were loaded, so utilization cannot be calculated." -ForegroundColor Red
    } else {
        # 数値のまま閾値判定する。書式化した文字列で比較すると辞書順比較になる
        $utilization = ($usableRulesCount / $totalRulesCount) * 100
        $color = if ($utilization -ge 70) { "Green" } elseif ($utilization -ge 10) { "DarkYellow" } else { "Red" }
        Write-Host ("You can utilize {0:N2}% of your detection rules." -f $utilization) -ForegroundColor $color
    }
    Write-Host ""
}


# BEGIN ATTACK-REMAP (auto-generated by tools/update_attack_remap.py - do not edit by hand)
# Source: MITRE ATT&CK Enterprise v19.2 (revoked-by relationships, chains collapsed)
$script:AttackVersion = "19"
$script:AttackTechniqueRemap = @{
    "T1002"     = "T1560"
    "T1004"     = "T1547.004"
    "T1009"     = "T1027.001"
    "T1013"     = "T1547.010"
    "T1015"     = "T1546.008"
    "T1017"     = "T1072"
    "T1019"     = "T1542.001"
    "T1022"     = "T1560"
    "T1023"     = "T1547.009"
    "T1024"     = "T1573"
    "T1028"     = "T1021.006"
    "T1031"     = "T1543.003"
    "T1032"     = "T1573"
    "T1035"     = "T1569.002"
    "T1038"     = "T1574.001"
    "T1042"     = "T1546.001"
    "T1044"     = "T1574.010"
    "T1045"     = "T1027.002"
    "T1050"     = "T1543.003"
    "T1053.001" = "T1053.002"
    "T1054"     = "T1685"
    "T1058"     = "T1574.011"
    "T1060"     = "T1547.001"
    "T1063"     = "T1518.001"
    "T1065"     = "T1571"
    "T1066"     = "T1027.005"
    "T1067"     = "T1542.003"
    "T1070.001" = "T1685.005"
    "T1070.002" = "T1685.006"
    "T1073"     = "T1574.001"
    "T1075"     = "T1550.002"
    "T1076"     = "T1021.001"
    "T1077"     = "T1021.002"
    "T1079"     = "T1573"
    "T1081"     = "T1552.001"
    "T1084"     = "T1546.003"
    "T1085"     = "T1218.011"
    "T1086"     = "T1059.001"
    "T1088"     = "T1548.002"
    "T1089"     = "T1685"
    "T1093"     = "T1055.012"
    "T1094"     = "T1095"
    "T1096"     = "T1564.004"
    "T1097"     = "T1550.003"
    "T1099"     = "T1070.006"
    "T1100"     = "T1505.003"
    "T1101"     = "T1547.005"
    "T1103"     = "T1546.010"
    "T1107"     = "T1070.004"
    "T1109"     = "T1542.002"
    "T1116"     = "T1553.002"
    "T1117"     = "T1218.010"
    "T1118"     = "T1218.004"
    "T1121"     = "T1218.009"
    "T1122"     = "T1546.015"
    "T1126"     = "T1070.005"
    "T1128"     = "T1546.007"
    "T1130"     = "T1553.004"
    "T1131"     = "T1547.002"
    "T1138"     = "T1546.011"
    "T1139"     = "T1552.003"
    "T1141"     = "T1056.002"
    "T1142"     = "T1555.001"
    "T1143"     = "T1564.003"
    "T1144"     = "T1553.001"
    "T1145"     = "T1552.004"
    "T1146"     = "T1070.003"
    "T1147"     = "T1564.002"
    "T1148"     = "T1690"
    "T1150"     = "T1647"
    "T1151"     = "T1036.006"
    "T1152"     = "T1569.001"
    "T1154"     = "T1546.005"
    "T1155"     = "T1059.002"
    "T1156"     = "T1546.004"
    "T1157"     = "T1574.004"
    "T1158"     = "T1564.001"
    "T1159"     = "T1543.001"
    "T1160"     = "T1543.004"
    "T1161"     = "T1546.006"
    "T1162"     = "T1647"
    "T1163"     = "T1037.004"
    "T1164"     = "T1547.007"
    "T1165"     = "T1037.005"
    "T1166"     = "T1548.001"
    "T1167"     = "T1555.002"
    "T1168"     = "T1053"
    "T1169"     = "T1548.003"
    "T1170"     = "T1218.005"
    "T1171"     = "T1557.001"
    "T1172"     = "T1090.004"
    "T1173"     = "T1559.002"
    "T1174"     = "T1556.002"
    "T1177"     = "T1547.008"
    "T1178"     = "T1134.005"
    "T1179"     = "T1056.004"
    "T1180"     = "T1546.002"
    "T1181"     = "T1055.011"
    "T1182"     = "T1546.009"
    "T1183"     = "T1546.012"
    "T1184"     = "T1563.001"
    "T1186"     = "T1055.013"
    "T1188"     = "T1090.003"
    "T1191"     = "T1218.003"
    "T1192"     = "T1566.002"
    "T1193"     = "T1566.001"
    "T1194"     = "T1566.003"
    "T1196"     = "T1218.002"
    "T1198"     = "T1553.003"
    "T1206"     = "T1548.003"
    "T1208"     = "T1558.003"
    "T1209"     = "T1547.003"
    "T1214"     = "T1552.002"
    "T1215"     = "T1547.006"
    "T1223"     = "T1218.001"
    "T1483"     = "T1568.002"
    "T1487"     = "T1561.002"
    "T1488"     = "T1561.001"
    "T1492"     = "T1565.001"
    "T1493"     = "T1565.002"
    "T1494"     = "T1565.003"
    "T1500"     = "T1027.004"
    "T1501"     = "T1543.002"
    "T1502"     = "T1134.004"
    "T1503"     = "T1555.003"
    "T1504"     = "T1546.013"
    "T1506"     = "T1550.004"
    "T1514"     = "T1548.004"
    "T1519"     = "T1546.014"
    "T1522"     = "T1552.005"
    "T1527"     = "T1550.001"
    "T1536"     = "T1578.004"
    "T1547.011" = "T1647"
    "T1562"     = "T1685"
    "T1562.001" = "T1685"
    "T1562.002" = "T1685.001"
    "T1562.003" = "T1690"
    "T1562.004" = "T1686"
    "T1562.006" = "T1685"
    "T1562.007" = "T1686.001"
    "T1562.008" = "T1685.002"
    "T1562.009" = "T1688"
    "T1562.010" = "T1689"
    "T1562.011" = "T1685.003"
    "T1562.012" = "T1685.004"
    "T1562.013" = "T1686.002"
    "T1574.002" = "T1574.001"
    "T1656"     = "T1684.001"
    "T1672"     = "T1684.002"
}
# END ATTACK-REMAP

function Export-MitreHeatmap {
    param (
        [Parameter(Mandatory = $true)]
        [array]$sigmaRules,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "mitre-ttp-heatmap.json",

        [Parameter(Mandatory=$false)]
        [bool]$UseIdealCount = $false
    )
    # ATT&CK Navigator のレイヤに載るのはテクニックIDのみ。
    # tactic(TA....)や cve./car./attack.g.... といったタグは対象外。
    # さらに ATT&CK が revoked にしたIDは置換先に書き換える。Navigator は revoked の
    # エントリを黙って捨てるため、書き換えないとカバレッジが欠落する。
    $tagMapping = @{}
    foreach ($rule in $sigmaRules) {
        if (-not $rule.tags) {
            continue
        }
        # Two tags on one rule can collapse onto the same technique (T1562 and T1562.001
        # both become T1685), so de-duplicate per rule before counting.
        $techniqueIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($tag in $rule.tags) {
            if ($tag -cnotmatch '^T\d{4}(\.\d{3})?$') {
                continue
            }
            $techniqueId = $tag
            if ($script:AttackTechniqueRemap.ContainsKey($tag)) {
                $techniqueId = $script:AttackTechniqueRemap[$tag]
            }
            [void]$techniqueIds.Add($techniqueId)
        }
        foreach ($techniqueId in $techniqueIds) {
            if (-not $tagMapping.ContainsKey($techniqueId)) {
                $tagMapping[$techniqueId] = @{
                    titles = @()
                    idealCount = 0
                    applicableCount = 0
                }
            }
            $tagMapping[$techniqueId].titles += $rule.title
            if ($rule.applicable -eq $true) {
                $tagMapping[$techniqueId].applicableCount++
            }
            if ($rule.ideal -eq $true) {
                $tagMapping[$techniqueId].idealCount++
            }
        }
    }

    $techniques = @()
    $tagMapping.Keys | ForEach-Object {
        $techniqueId = $_
        $info = $tagMapping[$techniqueId]
        $titlesCount = $info.titles.Count
        $matched = if ($UseIdealCount) { $info.idealCount } else { $info.applicableCount }
        $score = if ($titlesCount -gt 0) {
            [int][math]::Round(($matched / $titlesCount) * 100, 2)
        } else {
            0
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
            "attack" = $script:AttackVersion
            "navigator" = "5.3.2"
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

    # PowerShell 5.1 の Out-File 既定は UTF-16LE で、ATT&CK Navigator が読めないため UTF-8 で書く
    $heatmap | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
}



function AuditFileSize {
    # 推奨サイズはベースラインによらず共通のため、パラメータは取らない
    if (-not (TestWindows)) {
        Write-Host "[ERROR] 'audit-filesize' reads Windows event logs and can only run on Windows." -ForegroundColor Red
        return
    }

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
        "Microsoft-Windows-DFSN-Server/Admin" = @("1 MB", "128 MB+")
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-NTLM/Operational" = @("1 MB", "128 MB+")
        "Microsoft-Windows-PowerShell/Operational" = @("15 MB", "256 MB+")
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

    $missingLogs = @()

    foreach ($logName in $logNames.Keys | Sort-Object) {
        # 存在しないログ(役割やOSエディションによる)で全体を止めない
        $logInfo = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if (-not $logInfo) {
            $missingLogs += $logName
            continue
        }
        $maxLogSize = [math]::Floor($logInfo.MaximumSizeInBytes / 1MB)
        $recommendedSize = [int]($logNames[$logName][1] -replace " MB\+?", "")
        # ローテーション直前までファイルは上限まで育つので、95%以上を「ほぼ満杯」とみなす
        $logIsFull = $logInfo.MaximumSizeInBytes -gt 0 -and
                     $logInfo.FileSize -ge ($logInfo.MaximumSizeInBytes * 0.95)
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

    if ($missingLogs.Count -gt 0) {
        Write-Host ""
        Write-Host "Skipped $($missingLogs.Count) log(s) that do not exist on this machine:" -ForegroundColor DarkYellow
        $missingLogs | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkYellow }
    }

    $fileSizeCsv = Join-Path $script:ScriptRoot "WELA-FileSize-Result.csv"
    $results | Export-Csv -Path $fileSizeCsv -NoTypeInformation
    Write-Host ""
    Write-Host "Audit file size result saved to: $fileSizeCsv"
}


function UpdateRules {
    $baseUrl = "https://raw.githubusercontent.com/Yamato-Security/WELA/main/config"
    $downloads = @(
        @{ Url = "$baseUrl/eid_subcategory_mapping.csv"; Path = $script:EidMappingPath },
        @{ Url = "$baseUrl/security_rules.json";         Path = $script:SecurityRulesPath },
        @{ Url = "$baseUrl/audit_sacl_targets.json";     Path = $script:SaclTargetsPath }
    )

    $failed = 0
    foreach ($item in $downloads) {
        Write-Host "Downloading $($item.Url)"
        # 途中で失敗しても既存の設定ファイルを壊さないよう、一時ファイルに落としてから差し替える
        $tempPath = "$($item.Path).download"
        try {
            Invoke-WebRequest -Uri $item.Url -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
            Move-Item -Path $tempPath -Destination $item.Path -Force
            Write-Host "Saved to $($item.Path)" -ForegroundColor Green
        }
        catch {
            $failed++
            Write-Host "[ERROR] Failed to download $($item.Url): $_" -ForegroundColor Red
            Write-Host "        $($item.Path) was left unchanged." -ForegroundColor Red
        }
        finally {
            if (Test-Path -Path $tempPath) {
                Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host ""
    }
    if ($failed -gt 0) {
        Write-Host "$failed of $($downloads.Count) file(s) could not be updated." -ForegroundColor Red
    }
}

function Get-WelaDomainNtlmState {
    # ProductType distinguishes an actual DC from a member server with AD DS tools installed.
    $state = [pscustomobject]@{
        Applicable = $false
        Readable = $false
        Value = $null
        Type = $null
        Description = 'Unknown (computer role could not be determined)'
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property ProductType -ErrorAction Stop
        switch ($os.ProductType) {
            1 { $state.Description = 'Not applicable (Windows client)'; return $state }
            2 { $state.Applicable = $true }
            3 { $state.Description = 'Not applicable (member or standalone server, including non-DC AD CS)'; return $state }
            default { return $state }
        }
    } catch {
        $state.Description = "Unknown (computer role query failed: $($_.Exception.Message))"
        return $state
    }
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        $state.Description = 'Not configured'
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $property = $properties.PSObject.Properties['AuditNTLMInDomain']
            if ($null -ne $property) {
                $state.Value = $property.Value
                $state.Type = (Get-Item -LiteralPath $path -ErrorAction Stop).GetValueKind('AuditNTLMInDomain').ToString()
                if ($state.Type -ne 'DWord') {
                    $state.Description = "Unknown registry type ($($state.Type)): value $($state.Value) (expected DWord)"
                } else {
                    $state.Description = switch ($state.Value) {
                        0 { 'Disabled (0)' }
                        7 { 'Enable all (7)' }
                        default { "Value $($state.Value) (not interpreted as Enable all)" }
                    }
                }
            }
        }
        $state.Readable = $true
    } catch {
        $state.Description = "Unknown (domain NTLM registry read failed: $($_.Exception.Message))"
    }
    return $state
}

function Set-WelaDomainNtlmAudit {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ([switch]$Auto, $Context)
    if ($Context) {
        Set-WelaNtlmConfigurationControl -Context $Context -Scope Domain -WhatIf:$WhatIfPreference
        return
    }
    $state = Get-WelaDomainNtlmState
    Write-Host "Domain NTLM auditing: $($state.Description)"
    if (-not $state.Applicable) {
        Write-Host '[SKIPPED] Domain NTLM policy is only changed on a confirmed domain controller.' -ForegroundColor Yellow
        return
    }
    if (-not $state.Readable) {
        throw 'Domain NTLM policy was not changed because its current state could not be read.'
    }
    if ($state.Type -eq 'DWord' -and $state.Value -eq 7) {
        Write-Host '[SKIPPED] Domain NTLM auditing is already Enable all (7).' -ForegroundColor Yellow
        return
    }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    if (-not $PSCmdlet.ShouldProcess("$path\AuditNTLMInDomain", 'Set domain NTLM auditing to Enable all (7)')) { return }
    if (-not $Auto) {
        $response = Read-Host "Change domain NTLM auditing from '$($state.Description)' to 'Enable all (7)'? (Y/n)"
        if ($response -ne '' -and $response -ne 'Y') {
            Write-Host '[SKIPPED] Domain NTLM auditing.' -ForegroundColor Yellow
            return
        }
    }
    try {
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -LiteralPath $path -Name AuditNTLMInDomain -Value 7 -Type DWord -ErrorAction Stop
        $after = Get-WelaDomainNtlmState
        if (-not $after.Applicable -or -not $after.Readable -or $after.Type -ne 'DWord' -or $after.Value -ne 7) {
            throw "Read-back did not confirm Enable all (7). Observed: $($after.Description)"
        }
        Write-Host '[OK] Domain NTLM auditing: Enable all (7), registry value verified.' -ForegroundColor Green
        Write-Host 'Group Policy or MDM may reapply a different value; validate events on the domain controller.'
    } catch {
        throw "Domain NTLM configuration failed: $($_.Exception.Message)"
    }
}


function Set-RegistryConfig {
    # レジストリを変更するため -WhatIf / -Confirm に対応する
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RegPaths,

        [Parameter(Mandatory = $false)]
        [switch]$Auto,
        $Context
    )

    foreach ($reg in $RegPaths) {
        if ($Context) {
            if ($PSCmdlet.ShouldProcess("$($reg.Path)\$($reg.Name)", "Set to $($reg.Value)")) {
                Set-WelaRegistryControl -Context $Context -Path $reg.Path -Name $reg.Name -Value $reg.Value
            } else {
                $Context.Results.Add([pscustomobject]@{
                    Id = "Registry/$($reg.Path)/$($reg.Name)"; Kind = 'Registry'
                    Target = @{ Path = $reg.Path; Name = $reg.Name }; Desired = $reg.Value
                    Before = $null; After = $null; Status = 'Skipped'; Diagnostic = 'ShouldProcess declined the change.'
                })
            }
            continue
        }
        try {
            $currentValue = "Not Set"
            $pathExists = Test-Path $reg.Path
            if ($pathExists) {
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
                if ($PSCmdlet.ShouldProcess("$($reg.Path)\$($reg.Name)", "Set to $($reg.Value)")) {
                    if (-not $pathExists) {
                        New-Item -Path $reg.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord
                    Write-Host "[OK] Set $($reg.Name)" -ForegroundColor Green
                }
            } else {
                Write-Host "[SKIPPED] $($reg.Name)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[ERROR] Failed to set registry: $_" -ForegroundColor Red
        }
        Write-Host ""
    }
}


function Get-WelaOutgoingNtlmPolicySource {
    # RSoP is a last-applied policy snapshot, not proof of the current registry writer.
    $key = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $name = 'RestrictSendingNTLMTraffic'
    $matches = @()
    foreach ($class in @('RSOP_RegistryPolicySetting', 'RSOP_SecuritySettingNumeric')) {
        try {
            $matches += @(Get-CimInstance -Namespace 'root\RSOP\Computer' -ClassName $class -ErrorAction Stop |
                Where-Object {
                    $normalizedKey = $_.keyName -replace '^(MACHINE|HKEY_LOCAL_MACHINE|HKLM)\\', ''
                    ($normalizedKey -eq $key -and $_.valueName -eq $name) -or
                    $normalizedKey -eq "$key\$name"
                })
        } catch {
            # RSoP may be unavailable, including on standalone computers. Never infer "local".
        }
    }
    $policy = $matches | Sort-Object precedence | Select-Object -First 1
    if ($policy -and $policy.GPOID) {
        return "Last-applied RSoP GPO: $($policy.GPOID) (may be stale; current registry writer unknown)"
    }
    return 'Unknown (no matching RSoP source available; local, GPO or MDM provenance is not established)'
}

function Get-WelaOutgoingNtlmState {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $name = 'RestrictSendingNTLMTraffic'
    $value = $null
    $type = $null
    $readable = $true
    $description = 'Not configured (Allow all)'
    try {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            # Reading the key distinguishes an absent value from a failed read.
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $property = $properties.PSObject.Properties[$name]
            if ($null -ne $property) {
                $value = $property.Value
                $type = (Get-Item -LiteralPath $path -ErrorAction Stop).GetValueKind($name).ToString()
                if ($type -ne 'DWord') {
                    $description = "Unknown registry type ($type): value $value (expected DWord)"
                } else {
                    $description = switch ($value) {
                        0 { 'Allow all (0)' }
                        1 { 'Audit all (1)' }
                        2 { 'Deny all (2): authentication restriction, with block events' }
                        default { "Unknown registry value ($value)" }
                    }
                }
            }
        }
    } catch {
        $readable = $false
        $description = "Unknown (registry read failed: $($_.Exception.Message))"
    }
    [pscustomobject]@{
        Value = $value
        Type = $type
        Readable = $readable
        Description = $description
        PolicySource = Get-WelaOutgoingNtlmPolicySource
    }
}

function Set-WelaOutgoingNtlmPolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [ValidateSet('PreserveOrAudit', 'Audit', 'Deny')]
        [string]$Mode = 'PreserveOrAudit',
        [switch]$Auto,
        $Context
    )
    if ($Context) {
        Set-WelaNtlmConfigurationControl -Context $Context -Scope Outgoing -Mode $Mode -WhatIf:$WhatIfPreference
        return
    }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $name = 'RestrictSendingNTLMTraffic'
    $state = Get-WelaOutgoingNtlmState
    Write-Host "Outgoing NTLM: $($state.Description)"
    Write-Host "Policy source: $($state.PolicySource)"
    if (-not $state.Readable) {
        throw 'Outgoing NTLM was not changed because its current state could not be read.'
    }
    if ($Mode -eq 'PreserveOrAudit' -and $state.Type -eq 'DWord' -and $state.Value -eq 2) {
        Write-Host '[PRESERVED] Existing Deny all enforcement. Use -OutgoingNtlmMode Audit to explicitly replace it.' -ForegroundColor Yellow
        return
    }
    if ($Mode -eq 'PreserveOrAudit' -and $null -ne $state.Type -and ($state.Type -ne 'DWord' -or $state.Value -notin @(0, 1, 2))) {
        Write-Warning 'Unknown outgoing NTLM value/type was preserved. Select an explicit -OutgoingNtlmMode after reviewing policy.'
        return
    }
    $desired = if ($Mode -eq 'Deny') { 2 } else { 1 }
    $description = if ($desired -eq 2) { 'Deny all (2): restrict outgoing NTLM authentication' } else { 'Audit all (1): log outgoing NTLM without denying it' }
    if ($state.Type -eq 'DWord' -and $state.Value -eq $desired) {
        Write-Host "[SKIPPED] Outgoing NTLM is already $description." -ForegroundColor Yellow
        return
    }
    if ($desired -eq 2) {
        Write-Warning 'Explicit Deny mode can break NTLM authentication. This is enforcement, not audit-only configuration.'
    }
    if (-not $PSCmdlet.ShouldProcess("$path\$name", $description)) { return }
    if (-not $Auto) {
        $response = Read-Host "Change outgoing NTLM from '$($state.Description)' to '$description'? (Y/n)"
        if ($response -ne '' -and $response -ne 'Y') {
            Write-Host '[SKIPPED] Outgoing NTLM.' -ForegroundColor Yellow
            return
        }
    }
    try {
        # A prompt or ShouldProcess confirmation may outlive a Group Policy refresh.
        # Recheck immediately before mutation so default audit setup cannot undo new enforcement.
        $freshState = Get-WelaOutgoingNtlmState
        if (-not $freshState.Readable) {
            throw 'Outgoing NTLM was not changed because its current state became unreadable.'
        }
        if ($Mode -eq 'PreserveOrAudit' -and $freshState.Type -eq 'DWord' -and $freshState.Value -eq 2) {
            Write-Host '[PRESERVED] Deny all enforcement appeared before the write. Select explicit Audit mode to replace it.' -ForegroundColor Yellow
            return
        }
        if ($Mode -eq 'PreserveOrAudit' -and $null -ne $freshState.Type -and ($freshState.Type -ne 'DWord' -or $freshState.Value -notin @(0, 1, 2))) {
            Write-Warning "Outgoing NTLM changed to an unknown value/type ($($freshState.Value)/$($freshState.Type)); it was preserved."
            return
        }
        if ($freshState.Type -eq 'DWord' -and $freshState.Value -eq $desired) {
            Write-Host "[SKIPPED] Outgoing NTLM is now already $description." -ForegroundColor Yellow
            return
        }
        if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -LiteralPath $path -Name $name -Value $desired -Type DWord -ErrorAction Stop
        $after = Get-WelaOutgoingNtlmState
        if (-not $after.Readable -or $after.Type -ne 'DWord' -or $after.Value -ne $desired) {
            throw "Read-back did not match requested value $desired. Observed: $($after.Description)"
        }
        Write-Host "[OK] Outgoing NTLM: $($after.Description)" -ForegroundColor Green
        Write-Host "Policy source: $($after.PolicySource)"
        Write-Host 'Registry state was verified; Group Policy or MDM may reapply a different value.'
    } catch {
        throw "Outgoing NTLM configuration failed: $($_.Exception.Message)"
    }
}


function ConfigureAuditSettings {
    param (
        [switch]$Auto, [switch]$Debug, [switch]$DryRun, [string]$BackupPath, [string]$ResultsPath,
        [ValidateSet("PreserveOrAudit", "Audit", "Deny")]
        [string]$OutgoingNtlmMode = "PreserveOrAudit"
    )

    if (-not (TestWindows)) { throw "'configure' can only run on Windows." }
    if (-not (TestAdministrator)) { throw 'This script requires Administrator privileges.' }
    # Never use the debug cache to decide whether mutating controls are compliant.
    if ($Debug) { Write-Host 'configure always reads live state; the auditpol debug cache is not used.' -ForegroundColor Yellow }
    # Reject unsupported roles/builds or unknown required policies before any writes.
    $hostContext = Get-WelaHostContext
    $effectivePolicy = Get-WelaEffectiveAuditPolicy
    $profilePlan = Get-WelaAuditProfilePlan -Profile 'wela-2.2.0' -Role $hostContext.Role -Build $hostContext.Build -Current $effectivePolicy -IncludeOptional:$script:IncludeOptional
    Assert-WelaAuditProfileTarget -Plan $profilePlan -Context $hostContext -Current $effectivePolicy
    $context = New-WelaConfigurationContext -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath
    if (-not $DryRun) { Write-Host "Recovery journal: $($context.BackupPath)" }

    foreach ($log in @('Security', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell')) {
        Set-WelaEventLogControl -Context $context -Log $log -Property MaximumSizeInBytes -Desired 1073741824
    }
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
        Set-WelaEventLogControl -Context $context -Log $log -Property MaximumSizeInBytes -Desired 134217728
    }
    foreach ($log in @('Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-DriverFrameworks-UserMode/Operational', 'Microsoft-Windows-Crypto-DPAPI/Debug')) {
        Set-WelaEventLogControl -Context $context -Log $log -Property IsEnabled -Desired $true
    }

    $regPaths = @()
    foreach ($root in $script:PowerShellPolicyRoots) {
        $regPaths += @{Path = "$root\ModuleLogging"; Name = 'EnableModuleLogging'; Value = 1}
        $regPaths += @{Path = "$root\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Value = 1}
    }
    Set-RegistryConfig -RegPaths $regPaths -Auto:$Auto -Context $context
    foreach ($root in $script:PowerShellPolicyRoots) {
        Set-WelaRegistryControl -Context $context -Path "$root\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
    }
    Set-WelaRegistryControl -Context $context -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name ProcessCreationIncludeCmdLine_Enabled -Value 1

    # NTLM audit/restriction decisions share the recovery and verification context.
    Set-WelaOutgoingNtlmPolicy -Mode $OutgoingNtlmMode -Auto:$Auto -Context $context
    $regPaths = @(
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "AuditReceivingNTLMTraffic"; Value = 2}
    )
    Set-RegistryConfig -RegPaths $regPaths -Auto:$Auto -Context $context
    Set-WelaDomainNtlmAudit -Auto:$Auto -Context $context
    if ($hostContext.Role -eq 'DomainController') {
        Set-RegistryConfig -RegPaths @(
            @{Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'; Name = '15 Field Engineering'; Value = 5}
        ) -Auto:$Auto -Context $context
    }

    # Both audit display and mutation use the versioned role-aware profile.
    Show-WelaAuditProfilePrerequisites -Plan $profilePlan
    Set-WelaProfileAuditControls -Context $context -Plan $profilePlan
    Set-WelaCertificateAuditControl -Context $context
    Complete-WelaConfiguration -Context $context -ResultsPath $ResultsPath -Plan $profilePlan
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

function Enable-WelaPrivilege {
    # Enable SeSecurityPrivilege (required to read/write SACLs) + backup/restore (for reg load/unload).
    # Returns @{ PrivName = $true/$false } - AdjustTokenPrivileges returns true even when a privilege is
    # NOT held (it sets ERROR_NOT_ALL_ASSIGNED=1300), so the last Win32 error is validated per privilege.
    param([string[]] $Privileges = @("SeSecurityPrivilege","SeBackupPrivilege","SeRestorePrivilege"))
    if (-not ("WELA.PrivHelper" -as [type])) {
        Add-Type -Namespace WELA -Name PrivHelper -MemberDefinition @"
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool LookupPrivilegeValue(string host, string name, out long luid);
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKEN_PRIVILEGES np, uint len, IntPtr prev, IntPtr rl);
[DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
// Layout must match native TOKEN_PRIVILEGES exactly: DWORD Count; LUID(LowPart DWORD, HighPart LONG); DWORD Attr.
// (A single 8-byte 'long' Luid would be 8-byte aligned on x64 and insert padding, misaligning the struct.)
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES { public uint Count; public uint LuidLow; public int LuidHigh; public uint Attr; }
public static bool Enable(string priv) {
    IntPtr tok; if(!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;
    long luid; if(!LookupPrivilegeValue(null, priv, out luid)) return false;
    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
    tp.Count=1; tp.LuidLow=(uint)(luid & 0xFFFFFFFF); tp.LuidHigh=(int)(luid >> 32); tp.Attr=0x2;
    bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return ok && System.Runtime.InteropServices.Marshal.GetLastWin32Error() == 0;
}
"@
    }
    $res = @{}
    foreach ($p in $Privileges) { $res[$p] = [WELA.PrivHelper]::Enable($p) }
    return $res
}

function Test-WelaAuditRulePresent {
    # Idempotency: is an audit rule for $Sid already present that covers $RightsValue with matching
    # inheritance and audit flags? Compares translated SIDs (Get-Acl returns NTAccount by default).
    param($AuditRules, [string]$Sid, [int]$RightsValue, [string]$RightsProp, $Inh, $AuditFlags)
    foreach ($r in $AuditRules) {
        $rsid = try { $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $r.IdentityReference.Value }
        if ($rsid -ne $Sid) { continue }
        $rr = [int]($r.$RightsProp)
        if ((($rr -band $RightsValue) -eq $RightsValue) -and ($r.InheritanceFlags -eq $Inh) -and (($r.AuditFlags -band $AuditFlags) -eq $AuditFlags)) { return $true }
    }
    return $false
}

function Set-RegistryAuditSacl {
    # Add an audit SACL to a registry key using the .NET RegistryKey API. Get-Acl/Set-Acl -Audit is
    # unreliable on the registry provider, so we open the key with the .NET API (which honors the
    # enabled SeSecurityPrivilege for SACL read/write). CreateSubKey is idempotent - it opens the key
    # if it exists and provisions it if absent, so an ASEP created later still inherits the audit ACE.
    param($BaseKey, [string]$SubPath, $Rights, $Inh, [string]$Sid, $AuditFlags, [string]$Label, [string]$Note)
    $rk = $null
    try {
        # OpenSubKey has the RegistryRights overload (CreateSubKey does not); provision absent keys first.
        $rights2 = [System.Security.AccessControl.RegistryRights]"ReadPermissions,ChangePermissions"
        $rk = $BaseKey.OpenSubKey($SubPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights2)
        if (-not $rk) {
            $created = $BaseKey.CreateSubKey($SubPath)   # provision absent ASEP so a later write inherits the SACL
            if ($created) { $created.Close() }
            $rk = $BaseKey.OpenSubKey($SubPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights2)
        }
        if (-not $rk) { Write-Host "[ERROR] $Label : cannot open/create key" -ForegroundColor Red; return }
        $sec = $rk.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        $existing = $sec.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -eq $Sid -and (([int]$_.RegistryRights -band [int]$Rights) -eq [int]$Rights) -and ($_.InheritanceFlags -eq $Inh) -and (($_.AuditFlags -band $AuditFlags) -eq $AuditFlags) }
        if ($existing) { Write-Host "[SKIPPED] $Label : SACL already present ($Note)" -ForegroundColor Yellow; return }
        $rule = New-Object System.Security.AccessControl.RegistryAuditRule((New-Object System.Security.Principal.SecurityIdentifier($Sid)), $Rights, $Inh, "None", $AuditFlags)
        $sec.AddAuditRule($rule)
        $rk.SetAccessControl($sec)
        Write-Host "[OK] $Label  ($Note)" -ForegroundColor Green
    }
    catch {
        if ("$_" -match 'access is not allowed|Requested registry access') {
            Write-Host "[SKIPPED] $Label : access denied (tamper-protected key, e.g. Defender Exclusions)" -ForegroundColor DarkYellow
        } else { Write-Host "[ERROR] $Label : $_" -ForegroundColor Red }
    }
    finally { if ($rk) { $rk.Close() } }
}

function Set-AuditSacl {
    # Apply TARGETED audit SACLs (config/audit_sacl_targets.json) so File System (4663) / Registry (4657)
    # / Handle Manipulation (4656) auditing fires only on the specific ASEP keys and sensitive files the
    # detection rules watch - never globally. -Auto skips the confirmation prompt.
    param([switch] $Auto)

    if (-not (TestWindows)) {
        Write-Host "[ERROR] 'configure-sacl' changes Windows settings and can only run on Windows." -ForegroundColor Red; return
    }
    if (-not (TestAdministrator)) { Write-Error "This command requires Administrator privileges"; return }
    if (-not (Test-Path $script:SaclTargetsPath)) {
        Write-Host "[ERROR] Missing config: $script:SaclTargetsPath" -ForegroundColor Red
        Write-Host "        Run './WELA.ps1 update-rules' to download it, or reinstall WELA." -ForegroundColor Red; return
    }
    $priv = Enable-WelaPrivilege
    if (-not $priv['SeSecurityPrivilege']) {
        Write-Host "[ERROR] SeSecurityPrivilege could not be enabled (removed by policy?). Cannot set SACLs - aborting." -ForegroundColor Red; return
    }
    if (-not $priv['SeBackupPrivilege'] -or -not $priv['SeRestorePrivilege']) {
        Write-Host "[WARN] Backup/Restore privilege not fully enabled; offline per-user hives (reg load) may be skipped." -ForegroundColor DarkYellow
    }
    $targets = Get-Content -Path $script:SaclTargetsPath -Raw | ConvertFrom-Json
    $regN = @($targets.registry).Count; $fileN = @($targets.files).Count

    if (-not $Auto) {
        $resp = Read-Host "This enables File System/Registry/Handle auditing and sets targeted SACLs on $regN registry keys, $fileN files, plus per-user objects across all profiles (and Default). Proceed? (Y/n)"
        if ($resp -notin @('','Y','y')) { Write-Host "Aborted." -ForegroundColor Yellow; return }
    }

    $everyone   = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $auditFlags = [System.Security.AccessControl.AuditFlags]"Success,Failure"

    # 1) Enable ONLY the object-access subcategories these SACLs need (by GUID, locale-independent).
    Write-Host "Enabling Object Access subcategories (File System, Registry, Handle Manipulation)..."
    $subs = @(
        @{Name="File System";         GUID="0CCE921D-69AE-11D9-BED3-505054503030"},
        @{Name="Registry";            GUID="0CCE921E-69AE-11D9-BED3-505054503030"},
        @{Name="Handle Manipulation"; GUID="0CCE9223-69AE-11D9-BED3-505054503030"}
    )
    $subFailed = $false
    foreach ($s in $subs) {
        $p = Start-Process -FilePath "auditpol.exe" -ArgumentList "/set /subcategory:{$($s.GUID)} /success:enable /failure:enable" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "NUL"
        if ($p.ExitCode -eq 0) { Write-Host "[OK] subcategory: $($s.Name)" -ForegroundColor Green }
        else { $subFailed = $true; Write-Host "[ERROR] subcategory: $($s.Name) (ExitCode $($p.ExitCode)) -- its SACLs will NOT produce events" -ForegroundColor Red }
    }
    Write-Host ""

    # 2) Machine registry SACLs (absent keys are provisioned so future writes are audited)
    Write-Host "Applying targeted machine REGISTRY audit SACLs..."
    foreach ($t in $targets.registry) {
        if ($t.path -match 'Wow6432Node' -and -not [System.Environment]::Is64BitOperatingSystem) { continue }  # WOW64 view absent on 32-bit
        $rights = [System.Security.AccessControl.RegistryRights]($t.rights -join ",")
        $inh = if ($t.inherit) { [System.Security.AccessControl.InheritanceFlags]"ContainerInherit" } else { [System.Security.AccessControl.InheritanceFlags]"None" }
        $sub = $t.path -replace '^HKLM:\\', ''
        Set-RegistryAuditSacl -BaseKey ([Microsoft.Win32.Registry]::LocalMachine) -SubPath $sub -Rights $rights -Inh $inh -Sid $everyone.Value -AuditFlags $auditFlags -Label $t.path -Note $t.note
    }
    Write-Host ""

    # 3) Machine file / directory SACLs (absent sensitive files are skipped, never created)
    Write-Host "Applying targeted machine FILE audit SACLs..."
    foreach ($t in $targets.files) {
        $path = [System.Environment]::ExpandEnvironmentVariables($t.path)   # e.g. %SystemRoot% -> the real system drive
        try {
            if (-not (Test-Path -LiteralPath $path)) { Write-Host "[SKIPPED] $path : not present on this host" -ForegroundColor DarkYellow; continue }
            $isDir = (Get-Item -LiteralPath $path -Force).PSIsContainer
            $rights = [System.Security.AccessControl.FileSystemRights]($t.rights -join ",")
            $inh = if ($isDir -and $t.inherit) { [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit" } else { [System.Security.AccessControl.InheritanceFlags]"None" }
            $acl = Get-Acl -LiteralPath $path -Audit
            if (Test-WelaAuditRulePresent $acl.Audit $everyone.Value ([int]$rights) 'FileSystemRights' $inh $auditFlags) { Write-Host "[SKIPPED] $path : SACL already present ($($t.note))" -ForegroundColor Yellow; continue }
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, $rights, $inh, "None", $auditFlags)
            $acl.AddAuditRule($rule); Set-Acl -LiteralPath $path -AclObject $acl
            Write-Host "[OK] $path  ($($t.note))" -ForegroundColor Green
        } catch { Write-Host "[ERROR] $path : $_" -ForegroundColor Red }
    }
    Write-Host ""

    # 4) Per-user objects across every profile (+ Default template, so future users inherit the SACL)
    $hasUser = (@($targets.user_files).Count -gt 0) -or (@($targets.user_registry).Count -gt 0)
    if ($hasUser) {
        Write-Host "Enumerating user profiles for per-user SACLs..."
        $profiles = Get-WelaUserProfiles
        Write-Host "Found $($profiles.Count) profile(s) (incl. Default template)."; Write-Host ""

        if (@($targets.user_files).Count -gt 0) {
            foreach ($prof in $profiles) {
                foreach ($t in $targets.user_files) {
                    $path = Join-Path $prof.Path $t.relpath
                    try {
                        if (-not (Test-Path -LiteralPath $path)) { continue }
                        $isDir = (Get-Item -LiteralPath $path -Force).PSIsContainer
                        $rights = [System.Security.AccessControl.FileSystemRights]($t.rights -join ",")
                        $inh = if ($isDir -and $t.inherit) { [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit" } else { [System.Security.AccessControl.InheritanceFlags]"None" }
                        $acl = Get-Acl -LiteralPath $path -Audit
                        if (Test-WelaAuditRulePresent $acl.Audit $everyone.Value ([int]$rights) 'FileSystemRights' $inh $auditFlags) { continue }
                        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, $rights, $inh, "None", $auditFlags)
                        $acl.AddAuditRule($rule); Set-Acl -LiteralPath $path -AclObject $acl
                        Write-Host "[OK] $path  ($($t.note))" -ForegroundColor Green
                    } catch { Write-Host "[ERROR] $path : $_" -ForegroundColor Red }
                }
            }
        }

        if (@($targets.user_registry).Count -gt 0) {
            foreach ($prof in $profiles) {
                $loadedHere = $false; $mount = $null
                if ($prof.Loaded) {
                    $userRoot = $prof.Sid
                } else {
                    $hive = Join-Path $prof.Path "NTUSER.DAT"
                    if (-not (Test-Path -LiteralPath $hive)) { continue }
                    $mount = "WELA_$($prof.Sid)"
                    $out = reg load "HKU\$mount" "$hive" 2>&1
                    if ($LASTEXITCODE -ne 0) { Write-Host "[SKIPPED] hive $($prof.Sid) : cannot load ($out)" -ForegroundColor DarkYellow; continue }
                    $loadedHere = $true
                    $userRoot = $mount
                }
                try {
                    foreach ($t in $targets.user_registry) {
                        $rights = [System.Security.AccessControl.RegistryRights]($t.rights -join ",")
                        $inh = if ($t.inherit) { [System.Security.AccessControl.InheritanceFlags]"ContainerInherit" } else { [System.Security.AccessControl.InheritanceFlags]"None" }
                        Set-RegistryAuditSacl -BaseKey ([Microsoft.Win32.Registry]::Users) -SubPath "$userRoot\$($t.key)" -Rights $rights -Inh $inh -Sid $everyone.Value -AuditFlags $auditFlags -Label "HKU\$userRoot\$($t.key)" -Note "$($t.note) [$($prof.Sid)]"
                    }
                }
                finally {
                    if ($loadedHere) {
                        # release .NET handles before unloading, or 'reg unload' fails and the hive stays mounted
                        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                        $u = reg unload "HKU\$mount" 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            Start-Sleep -Milliseconds 500; [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                            $u = reg unload "HKU\$mount" 2>&1
                            if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] could not unload hive HKU\$mount (it remains mounted!): $u" -ForegroundColor Red }
                        }
                    }
                }
            }
        }
        Write-Host ""
    }

    if ($subFailed) {
        Write-Host "WARNING: one or more Object Access subcategories failed to enable -- SACLs on the affected class will NOT produce events. Fix the auditpol error above and re-run." -ForegroundColor Red
    } else {
        Write-Host "Done. Targeted object-access auditing is enabled without global file/registry auditing." -ForegroundColor Cyan
    }
    Write-Host "Per-user objects were applied to existing profiles and the Default profile (future users)." -ForegroundColor DarkCyan
    Write-Host "Not covered: folder-redirected AppData on network shares, and mandatory profiles." -ForegroundColor DarkCyan
}

function Get-WelaUserProfiles {
    # Enumerate real user profiles from ProfileList (SID + path + whether the hive is loaded),
    # plus the Default profile template so SACLs propagate to future users.
    $result = @()
    $pl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    foreach ($k in (Get-ChildItem -LiteralPath $pl -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }   # local/domain (S-1-5-21) + Entra/Azure AD (S-1-12-1) users; skip system SIDs
        $p = (Get-ItemProperty -LiteralPath $k.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        $loaded = Test-Path -LiteralPath "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$sid"
        $result += [pscustomobject]@{ Sid = $sid; Path = $p; Loaded = $loaded }
    }
    $def = Join-Path $env:SystemDrive "Users\Default"
    if (Test-Path -LiteralPath $def) { $result += [pscustomobject]@{ Sid = "DEFAULT"; Path = $def; Loaded = $false } }
    return $result
}

$usage = @"
Usage:
  ./WELA.ps1 profiles                                   # List versioned advanced audit-policy profiles
  ./WELA.ps1 plan -Profile wela-2.2.0 -Role Client -Build 26100 -PlanPath plan.json
  ./WELA.ps1 audit-settings -Profile microsoft-sct-win11-24h2 -PlanPath audit.json
  ./WELA.ps1 configure -Profile asd-native-2021-10 -PlanPath result.json -Auto
  # -Profile changes advanced audit policy plus its precedence prerequisite. Optional controls need -IncludeOptional.
  ./WELA.ps1 audit-settings -Baseline YamatoSecurity     # Audit current setting and show in stdout, save to csv
  ./WELA.ps1 audit-settings -Baseline ASD -OutType gui   # Audit current setting and show in gui, save to csv
  ./WELA.ps1 audit-filesize -Baseline YamatoSecurity     # Audit current file size and show in stdout, save to csv
  ./WELA.ps1 configure -Baseline YamatoSecurity          # Configure audit settings based on the specified baseline
  ./WELA.ps1 configure -Baseline YamatoSecurity -Auto    # Configure audit settings automatically without prompts
  ./WELA.ps1 configure-sacl                              # Add targeted File System/Registry audit SACLs (ASEP keys + sensitive files) needed by the rules, without global auditing
  ./WELA.ps1 configure-sacl -Auto                        # ...automatically without prompts
  ./WELA.ps1 update-rules         # Update rule config files from https://github.com/Yamato-Security/WELA
  ./WELA.ps1 version     # Show the WELA version
  ./WELA.ps1 help        # Show this help
"@


[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host $logo -ForegroundColor Green
Write-Host ""
Write-Host "WELA v$WELAVersion - $WELAReleaseName"
Write-Host ""

# Reject unsupported dry-run requests before reaching any command's mutation path.
if ($DryRun -and $Cmd -ne 'configure') {
    throw "-DryRun is supported only by configure (including configure -Profile). No command was run."
}

if ($Profile -and $Cmd.ToLower() -in @('plan', 'audit', 'audit-settings', 'configure') -and -not $Help) {
    Invoke-WelaProfileCommand -Command $Cmd.ToLower()
    return
}

switch ($Cmd.ToLower()) {
    "profiles" {
        (Import-WelaAuditProfiles).profiles | Select-Object id, version, scope, appliesTo | Format-List
    }
    "plan" { Invoke-WelaProfileCommand -Command 'plan' }
    "audit" { Invoke-WelaProfileCommand -Command 'audit' }
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
        $validGuides = GetBaselineNames
        if (-not ($validGuides -contains $Baseline)) {
            Write-Host "Invalid Guide specified. Valid options are: $($validGuides -join ', ')."
            break
        }
        AuditLogSetting -outType $OutType -Baseline $Baseline -debug:$Debug
    }
    "audit-filesize" {
        if ($Help){
            Write-Host "Audit current Windows Event Log file sizes"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 audit-filesize"
            Write-Host ""
            Write-Host "Note: the recommended sizes are the same for every baseline, so -Baseline is not required."
            Write-Host ""
            return
        }
        if (-not [string]::IsNullOrEmpty($Baseline) -and $Baseline -ne "YamatoSecurity") {
            Write-Host "Note: audit-filesize uses the same recommended sizes for every baseline; '-Baseline $Baseline' is ignored." -ForegroundColor DarkYellow
            Write-Host ""
        }
        AuditFileSize
    }

    "configure" {
        if ($Help){
            Write-Host "Configure Windows Event Log audit settings based on the YamatoSecurity baseline"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 configure [-Profile <id>] [-Auto] [-DryRun] [-BackupPath <new-directory>] [-ResultsPath <json-file>] [-OutgoingNtlmMode <PreserveOrAudit|Audit|Deny>]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Profile     Configure advanced audit policy and precedence from a versioned profile; list IDs with profiles"
            Write-Host "  -Auto        Automatically configure without prompts"
            Write-Host "  -OutgoingNtlmMode  PreserveOrAudit (default): audit, preserving existing deny; Audit: explicitly replace deny; Deny: opt into enforcement"
            Write-Host "  -DryRun      Read live state and report proposed changes without writing Windows settings"
            Write-Host "  -BackupPath  New directory for the pre-change recovery journal (unique default beside WELA)"
            Write-Host "  -ResultsPath Save structured per-control outcomes as JSON"
            Write-Host ""
            Write-Host "Without -Profile, configure applies the YamatoSecurity native logging settings. -Profile applies advanced audit policy and its precedence prerequisite. -DryRun and recovery/results options work with both."
            Write-Host ""
            return
        }
        if (-not [string]::IsNullOrEmpty($Baseline) -and $Baseline -ne "YamatoSecurity") {
            Write-Host "'configure' currently supports only the YamatoSecurity baseline, but '-Baseline $Baseline' was given." -ForegroundColor Red
            Write-Host "Re-run with '-Baseline YamatoSecurity' (or omit -Baseline) if that is what you want."
            break
        }
        try {
            $report = ConfigureAuditSettings -Auto:$Auto -Debug:$Debug -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath -OutgoingNtlmMode $OutgoingNtlmMode
            $report
            if ($report.ExitCode -ne 0) { exit $report.ExitCode }
        } catch {
            Write-Host "[Failed] Configuration aborted: $_" -ForegroundColor Red
            exit 1
        }
    }

    "configure-sacl" {
        if ($Help){
            Write-Host "Add TARGETED object-access audit SACLs so File System (4663) / Registry (4657) /"
            Write-Host "Handle Manipulation (4656) auditing fires only on the specific autostart/persistence"
            Write-Host "registry keys and sensitive files the Hayabusa/Sigma rules watch - never globally."
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 configure-sacl [-Auto]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Auto        Apply without the confirmation prompt"
            Write-Host ""
            Write-Host "Targets are defined in config/audit_sacl_targets.json (edit to customize; 'update-rules' refreshes it)."
            Write-Host "Per-user HKCU keys and profile AppData ARE covered: applied across every user profile and the"
            Write-Host "Default profile (so future users inherit). Absent registry ASEP keys are provisioned; absent files"
            Write-Host "are skipped. Not covered: folder-redirected AppData on network shares, and mandatory profiles."
            Write-Host ""
            return
        }
        Set-AuditSacl -Auto:$Auto
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
    "version" {
        # バージョンはバナーで表示済みなので、ここでは何もしない
    }
    "help" {
        Write-Host $usage
    }
    default {
        Write-Host "Invalid command. Use 'help' to see available commands."
        Write-Host $usage
    }
}
