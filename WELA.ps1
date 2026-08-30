param (
    [string]$Cmd,
    [string]$OutType = "std",
    [switch]$Debug,
    [string]$Baseline,
    [switch]$Auto,
    [switch]$Help
)

# 実行時のカレントディレクトリに依存しないよう、すべてスクリプトの場所を基準にする
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$BaselineConfigPath = Join-Path $ScriptRoot "config/baselines.json"
$SecurityRulesPath  = Join-Path $ScriptRoot "config/security_rules.json"
$EidMappingPath     = Join-Path $ScriptRoot "config/eid_subcategory_mapping.csv"
$AuditpolTxtPath    = Join-Path $ScriptRoot "auditpol.txt"

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

    foreach ($item in $config.catalog) {
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

    # ベースラインが扱っていないサブカテゴリでも、そのサブカテゴリが有効ならルールは動く。
    # ルール自身が持つ subcategory_guids を見て救済する。
    $all_rules | ForEach-Object {
        if (-not $_.applicable) {
            foreach ($guid in $_.subcategory_guids) {
                if ($enabledguid -contains $guid) {
                    $_.applicable = $true
                    break
                }
            }
        }
    }

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
            $enabledCount = ($_.Group |  Where-Object { $notEnabled -notcontains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $disabledCount = ($_.Group |  Where-Object { $notEnabled -contains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $out = ""
            $color = ""
            if (@($_.Group | Where-Object { $_.CurrentSetting -ne "Unknown" }).Count -eq 0) {
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
                # ATT&CK Navigator のレイヤに載るのはテクニックIDのみ。
                # tactic(TA....)や cve./car./attack.g.... といったタグは対象外。
                if ($tag -notmatch '^T\d{4}(\.\d{3})?$') {
                    return
                }
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
            "attack" = "18"
            "navigator" = "5.2.0"
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
        @{ Url = "$baseUrl/security_rules.json";         Path = $script:SecurityRulesPath }
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

function Set-RegistryConfig {
    # レジストリを変更するため -WhatIf / -Confirm に対応する
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RegPaths,

        [Parameter(Mandatory = $false)]
        [switch]$Auto
    )

    foreach ($reg in $RegPaths) {
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


function ConfigureAuditSettings {
    param (
        [switch] $Auto,
        [switch] $Debug
    )

    if (-not (TestWindows)) {
        Write-Host "[ERROR] 'configure' changes Windows settings and can only run on Windows." -ForegroundColor Red
        return
    }

    # 管理者権限の確認
    if (-not (TestAdministrator)) {
        Write-Error "This script requires Administrator privileges"
        exit 1
    }

    if (-not (CollectAuditpol -UseCached:$Debug)) {
        return
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
    # 64bit の PowerShell と GPO が読むのは Wow6432Node の無いパス。
    # 32bit の PowerShell 用に Wow6432Node 側も併せて設定する。
    $regPaths = @()
    foreach ($root in $script:PowerShellPolicyRoots) {
        $regPaths += @{Path = "$root\ModuleLogging";      Name = "EnableModuleLogging";      Value = 1}
        $regPaths += @{Path = "$root\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Value = 1}
    }
    Set-RegistryConfig -RegPaths $regPaths -Auto:$Auto

    # モジュール名レジストリの設定
    foreach ($root in $script:PowerShellPolicyRoots) {
    try {
        $moduleLoggingPath = "$root\ModuleLogging\ModuleNames"
        $currentValue = "Not Set"
        $pathExists = Test-Path $moduleLoggingPath
        if ($pathExists) {
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
                if (-not $pathExists)
                {
                    New-Item -Path $moduleLoggingPath -Force | Out-Null
                }
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
    }

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

    # NTLM認証の監査設定
    Write-Host "Configuring NTLM Audit Settings..."
    Write-Host ""
    $regPaths = @(
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "RestrictSendingNTLMTraffic"; Value = 2},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "AuditReceivingNTLMTraffic"; Value = 2},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name = "AuditNTLMInDomain"; Value = 2}
    )
    Set-RegistryConfig -RegPaths $regPaths -Auto:$Auto

    # 監査ポリシーの設定
    Write-Host "Configuring Audit Policies..."
    Write-Host ""
    $auditPolicies = @(
        @{Category = "Account Logon"; Name = "Credential Validation"; GUID = "0CCE923F-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Logon"; Name = "Kerberos Authentication Service"; GUID = "0CCE9242-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Logon"; Name = "Kerberos Service Ticket Operations"; GUID = "0CCE9240-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "Computer Account Management"; GUID = "0CCE9236-69AE-11D9-BED3-505054503030"},
        @{Category = "Account Management"; Name = "Distribution Group Management"; GUID = "0CCE9238-69AE-11D9-BED3-505054503030"},
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

    # AD CS AuditFilter の設定
    Write-Host "Configuring AD CS Audit Settings..."
    try {
        $installed = (Get-WindowsFeature -Name AD-Certificate).InstallState -eq "Installed"
    } catch {
        $installed = $false
    }

    if ($installed) {
        try {
            $csRootKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\"
            $caName = (Get-ItemProperty $csRootKey -ErrorAction Stop).Active
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
            $prop = Get-ItemProperty -Path $regPath -Name "AuditFilter" -ErrorAction SilentlyContinue
            $currentValue = if ($null -ne $prop) { [int]$prop.AuditFilter } else { "Not Set" }
            if ($currentValue -eq 127) {
                Write-Host "[OK] AuditFilter is already 127" -ForegroundColor Green
            }
            else {
                $proceed = $false
                if ($Auto) {
                    $proceed = $true
                }
                else {
                    $response = Read-Host "Do you want to set AuditFilter to 127 and restart Certificate Services? (Y/n)"
                    $proceed = ($response -eq "" -or $response -match "^[Yy]$")
                }

                if ($proceed) {
                    try {
                        # AuditFilter の設定
                        & certutil.exe -setreg "CA\AuditFilter" 127 >$null 2>&1
                        # 証明書サービスの再起動
                        Restart-Service -Name "CertSvc" -Force -ErrorAction Stop
                        # 反映確認
                        $propAfter = Get-ItemProperty -Path $regPath -Name "AuditFilter" -ErrorAction SilentlyContinue
                        $newValue = if ($null -ne $propAfter) { [int]$propAfter.AuditFilter } else { $null }

                        if ($newValue -eq 127) {
                            Write-Host "[OK] AuditFilter set to 127 and CertSvc restarted" -ForegroundColor Green
                        }
                        else {
                            Write-Host "[ERROR] AuditFilter did not apply as expected (current: $newValue)" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "[ERROR] Failed to set AuditFilter or restart CertSvc: $_" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "[SKIP] No changes applied to AuditFilter"
                }
            }
        }
        catch {
            Write-Host "[ERROR] Failed to process AD CS audit settings: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[INFO] AD Certificate Services is not installed. Skipping." -ForegroundColor Yellow
    }
    Write-Host ""

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
Write-Host ""
Write-Host "WELA v2.1.0 - Winter Release"
Write-Host ""

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
            Write-Host "Usage: ./WELA.ps1 configure [-Auto]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Auto        Automatically configure without prompts"
            Write-Host ""
            Write-Host "Note: only the YamatoSecurity baseline is currently supported for 'configure'."
            Write-Host ""
            return
        }
        if (-not [string]::IsNullOrEmpty($Baseline) -and $Baseline -ne "YamatoSecurity") {
            Write-Host "'configure' currently supports only the YamatoSecurity baseline, but '-Baseline $Baseline' was given." -ForegroundColor Red
            Write-Host "Re-run with '-Baseline YamatoSecurity' (or omit -Baseline) if that is what you want."
            break
        }
        ConfigureAuditSettings -Auto:$Auto -Debug:$Debug
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
