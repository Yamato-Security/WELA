param (
    [string]$Cmd,
    [string]$OutType = "std",
    [switch]$Debug,
    [string]$Baseline,
    [string]$Profile,
    [string]$ProfileFile,
    [string]$LogProfile,
    [switch]$ResizeLogs,
    [switch]$ApplyLogMode,
    [ValidateSet("Client", "MemberServer", "DomainController", "ADCS")][string]$Role,
    [int]$Build,
    [string]$PlanPath,
    [switch]$IncludeOptional,
    [ValidateSet('Plan', 'Skip')][string]$SaclMode = 'Plan',
    [switch]$Auto,
    [ValidateSet("PreserveOrAudit", "Audit", "Deny")]
    [string]$OutgoingNtlmMode = "PreserveOrAudit",
    [switch]$DryRun,
    [string]$BackupPath,
    [string]$ResultsPath,
    [ValidateSet('Audit', 'Plan', 'Configure')][string]$FirewallAction = 'Audit',
    [ValidateSet('Preserve', 'CisV4')][string]$FirewallPathMode = 'Preserve',
    [ValidateRange(16384, 32767)][int]$FirewallMinimumSizeKiB = 16384,
    [string]$HtmlPath,
    [ValidateSet('Audit', 'Plan', 'Configure')][string]$SmbAction = 'Audit',
    [ValidateSet('Audit', 'Plan', 'Configure', 'Rollback')][string]$AdSaclAction = 'Audit',
    [string]$AdServer,
    [ValidateSet('MdiDomain', 'MdiConfiguration', 'PkiObjects')][string[]]$AdSaclProfile,
    [string[]]$AdObjectDn,
    [string]$AdReceiptPath,
    [ValidateSet('Audit', 'Plan', 'Configure')][string]$ChannelAction = 'Audit',
    [string]$ChannelProfile = 'microsoft-wef-appendix-c',
    [ValidateSet('Baseline', 'Suspect', 'Both')][string]$WefQuerySet = 'Both',
    [switch]$GrantEventLogReaders,
    [ValidateSet('Audit', 'Plan', 'Configure')][string]$WefAction = 'Audit',
    [string]$WefConfigPath,
    [string]$RetentionConfigPath,
    [string]$RetentionPreviousPath,
    [ValidateSet('Audit', 'Plan', 'Import')][string]$AppLockerAction = 'Audit',
    [string]$AppLockerPolicyPath,
    [ValidateSet('List', 'Audit', 'Plan', 'Configure')][string]$WmiAction = 'List',
    [string[]]$WmiNamespace,
    [switch]$WmiIncludeChildren,
    [string]$RuleEvidencePath,
    [string]$RuleCorpusPath,
    [string]$RuleManifestPath,
    [ValidateSet('Audit', 'Plan', 'Configure')][string]$TranscriptionAction = 'Audit',
    [string]$TranscriptDirectory,
    [ValidateSet('Audit','Plan','Configure')][string]$LdapAction = 'Audit',
    [ValidateSet('Preserve','Diagnostic','MdiCleanup')][string]$LdapMode = 'Preserve',
    [ValidateRange(1,2147483647)][int]$LdapSearchTimeMs,
    [ValidateRange(1,2147483647)][int]$LdapExpensiveThreshold,
    [ValidateRange(1,2147483647)][int]$LdapInefficientThreshold,
    [ValidateSet('Audit','Plan','Configure')][string]$IntegrityAction = 'Audit',
    [string]$IntegrityProfile,
    [switch]$AllowPrivilegeRemoval,
    [ValidateSet('Capture','Compare')][string]$DefaultEvidenceAction = 'Capture',
    [string]$DefaultEvidencePath,
    [ValidateSet('List','Audit','Plan','Configure')][string]$ProviderAction = 'List',
    [string[]]$ProviderPack,
    [ValidateSet('Audit','Plan','Configure')][string]$NotificationAction = 'Audit',
    [ValidateSet('OneSettings','SecurityWarning')][string[]]$NotificationControl,
    [ValidateRange(1,90)][int]$WarningPercent = 90,
    [switch]$EnablePrivacyChannel,
    [string]$ScoreProfile,
    [string]$ScoreEvidencePath,
    [ValidateSet('Plan','Export','Verify')][string]$GpoAction = 'Plan',
    [string]$GpoProfile,
    [string]$GpoOutputPath,
    [ValidateSet('Reject','PromoteToBoth')][string]$GpoMinimumMode = 'Reject',
    [string]$IntuneProfile,
    [int]$IntuneBuild,
    [string]$IntuneEdition,
    [string]$IntuneOutputPath,
    [ValidateSet('Reject','PromoteToBoth')][string]$IntuneMinimumMode = 'Reject',
    [ValidateSet('Plan','Run')][string]$ProbeAction = 'Plan',
    [string]$ProbeOutputPath,
    [ValidateRange(1,30)][int]$ProbeTimeoutSeconds = 15,
    [ValidateSet('Export','Verify')][string]$EvtxAction = 'Verify',
    [string]$EvtxProbePath,
    [string]$EvtxArchivePath,
    [string]$EvtxOutputPath,
    [ValidateSet('Plan','Restore')][string]$RecoveryAction = 'Plan',
    [string]$RecoveryJournalPath,
    [string]$RecoveryOriginalResultsPath,
    [string[]]$RecoveryControlId,
    [string]$RecoveryPlanPath,
    [string]$RecoveryOutputPath,
    [string]$ArrivalProbePath,
    [string]$ArrivalOutputPath,
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
. (Join-Path $ScriptRoot "scripts/AuditIntegrity.ps1")
. (Join-Path $ScriptRoot "scripts/FirewallLogging.ps1")
. (Join-Path $ScriptRoot "scripts/SmbAuditing.ps1")
. (Join-Path $ScriptRoot "scripts/LdapDiagnostics.ps1")
. (Join-Path $ScriptRoot "scripts/ControlApplicability.ps1")
. (Join-Path $ScriptRoot "scripts/NativeValidation.ps1")
. (Join-Path $ScriptRoot "scripts/WefArrival.ps1")
. (Join-Path $ScriptRoot "scripts/AuditNotifications.ps1")
. (Join-Path $ScriptRoot "scripts/AdObjectSacl.ps1")
. (Join-Path $ScriptRoot "scripts/AppLockerReadiness.ps1")
. (Join-Path $ScriptRoot "scripts/WmiNamespaceAuditing.ps1")
. (Join-Path $ScriptRoot "scripts/PowerShellTranscription.ps1")
Import-Module (Join-Path $ScriptRoot "modules/AuditProfiles.psm1") -ErrorAction Stop
Import-Module (Join-Path $ScriptRoot "modules/RuleEligibility.psm1") -ErrorAction Stop
Import-Module (Join-Path $ScriptRoot "modules/AuditCatalog.psm1") -ErrorAction Stop
Import-Module (Join-Path $ScriptRoot "modules/NativeProviders.psm1") -ErrorAction Stop
Import-Module (Join-Path $ScriptRoot "modules/EventLogSettings.psm1") -ErrorAction Stop
. (Join-Path $ScriptRoot "scripts/EventLogConfiguration.ps1")
Import-Module (Join-Path $ScriptRoot "modules/NativeChannelAccess.psm1") -ErrorAction Stop
. (Join-Path $ScriptRoot "scripts/NativeChannelConfiguration.ps1")
. (Join-Path $ScriptRoot "scripts/NativeProviderPacks.ps1")
Import-Module (Join-Path $ScriptRoot "modules/WefSubscriptions.psm1") -ErrorAction Stop
. (Join-Path $ScriptRoot "scripts/WefDeployment.ps1")
. (Join-Path $ScriptRoot "scripts/RetentionHealth.ps1")
. (Join-Path $ScriptRoot "scripts/AuditScoring.ps1")
. (Join-Path $ScriptRoot "scripts/TargetedSaclPlanning.ps1")
. (Join-Path $ScriptRoot "scripts/GpoAuditPackages.ps1")
. (Join-Path $ScriptRoot "scripts/IntuneAuditExport.ps1")
. (Join-Path $ScriptRoot "scripts/EvtxRecovery.ps1")
. (Join-Path $ScriptRoot "scripts/AuditRecovery.ps1")

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
    [string] $ChannelState = ""
    [string] $GenerationReadiness = ""
    [array] $NativeSources = @()
    [array] $Rules
    [hashtable] $RulesCount
    [string] $DefaultSetting = "Unknown"
    [string] $LegacyDefaultHint = ""
    [string] $DefaultEvidence = "No exact-context reviewed default evidence; historical hints are not host defaults."
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
        $this.LegacyDefaultHint = $DefaultSetting
        $this.DefaultSetting = "Unknown"
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
                         elseif ($this.CurrentSetting -in @("Unknown", "Conditional", "Not installed", "Not applicable")) { "DarkYellow" }
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
                    Write-Host "    - Default Evidence: $($this.DefaultEvidence)"
                }
                if ($this.CurrentSetting) {
                    Write-Host "    - Current Setting: $($this.CurrentSetting)"
                }
                foreach ($source in $this.NativeSources) {
                    Write-Host "    - Channel: $($source.Channel.Name); state: $($source.Channel.State); mode: $($source.Channel.LogMode)"
                    Write-Host "      Provider readiness: $($source.Provider.Readiness); rule coverage: $($source.RuleCoverage)"
                    if ($source.Channel.Error) { Write-Host "      Channel read: $($source.Channel.Error.Category): $($source.Channel.Error.Message)" }
                    if ($source.Provider.Error) { Write-Host "      Provider read: $($source.Provider.Error.Category): $($source.Provider.Error.Message)" }
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
        if (-not ($rule.channel | Where-Object {
            $ruleChannel = $_
            # Catalog channels are concrete names/aliases; rule channels are patterns,
            # matching the convention used by Get-WelaNativeSources.
            $category_channels | Where-Object { $_ -like $ruleChannel }
        })) {
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
    $data = Get-Content -Path $script:BaselineConfigPath -Raw | ConvertFrom-Json
    Assert-WelaAuditCatalog -Catalog $data.catalog -CanonicalCatalog (Import-WelaAuditProfiles).catalog
    return $data
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
    $planArguments = @{}
    if ($script:ProfileFile) {
        # Complete strict file/identifier/source validation before Windows reads.
        $custom = Import-WelaCustomAuditProfiles -Path $script:ProfileFile
        if ($script:Profile -cnotin @($custom.profiles.id)) { throw 'Selected profile is not present in the custom file; built-in fallback is disabled.' }
        foreach ($output in @($script:PlanPath,$script:ResultsPath,$script:BackupPath)) {
            if (-not $output) { continue }
            $full = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($output))
            if ($full -ieq $custom.customSource.Path -or $full -ieq $custom.customSource.CanonicalPath) { throw 'Profile input/catalog and output/backup paths must differ.' }
        }
        $reportPaths=@()
        foreach ($output in @($script:PlanPath,$script:ResultsPath)) {
            if (-not $output) { continue }
            $full=Get-WelaCustomReportPath $output
            if ($full -iin $reportPaths) { throw 'Custom PlanPath and ResultsPath require distinct new report files.' }
            $reportPaths+=$full
        }
        $planArguments = @{Path=$custom.customSource.Path;CustomFile=$true}
        if ($script:Role -and $script:Build) {
            $null = Get-WelaAuditProfilePlan -Profile $script:Profile -Role $script:Role -Build $script:Build @planArguments
        }
    }
    $context = Get-WelaSelectedContext
    $current = @{}
    $saclLive = $false
    if (TestWindows) {
        $actual = Get-WelaHostContext
        if ($actual.Role -eq $context.Role -and $actual.Build -eq $context.Build) { $current = Get-WelaEffectiveAuditPolicy; $saclLive = $true }
        elseif ($Command -ne 'plan') { throw "Requested role/build does not match this Windows host." }
        else { Write-Host "Planning for another role/build: effective state remains Unknown." }
    }
    elseif ($Command -ne 'plan') { throw "Audit and configure require Windows. Offline planning requires explicit -Role and -Build." }
    $plan = Get-WelaAuditProfilePlan -Profile $script:Profile -Role $context.Role -Build $context.Build -Current $current -IncludeOptional:$script:IncludeOptional @planArguments
    if ($script:ProfileFile) {
        Assert-WelaCustomProfileSource $custom.customSource
        if ($plan.CustomProfileSource.Sha256 -cne $custom.customSource.Sha256) { throw 'Custom profile changed during host assessment.' }
    }
    $precedence = Get-WelaAuditPrecedenceState -Offline:($current.Count -eq 0)
    $plan | Add-Member NoteProperty AuditPrecedence $precedence
    $saclPlan = Get-WelaTargetedSaclPlan -AuditPlan $plan -Mode $script:SaclMode -Live:$saclLive
    $plan | Add-Member NoteProperty SaclPrerequisites $saclPlan
    Write-Host "Profile: $($plan.profile); role: $($plan.role); build: $($plan.build)"
    Write-Host "Scope: advanced audit policy and its subcategory-precedence prerequisite. Channels, command-line capture, PowerShell, NTLM, SACL writes, CA AuditFilter and forwarding are separate."
    Write-Host "Audit precedence: $($precedence.State); required SCENoApplyLegacyAuditPolicy=1 (DWORD). $($precedence.Diagnostic)"
    if ($precedence.PolicySource) { Write-Host $precedence.PolicySource.Description }
    Show-WelaAuditProfilePrerequisites -Plan $plan
    Write-Host "Targeted SACL companion plan: $($saclPlan.Mode), $($saclPlan.Targets.Count) targets; $($saclPlan.TelemetryGap)" -ForegroundColor DarkYellow
    $saclPlan.Targets | Select-Object Scope, Path, Rights, Inheritance, PolicyMode, @{Name='PathState';Expression={$_.Observation.PathState}} | Format-Table -AutoSize
    $result = $plan
    if ($Command -eq 'configure') {
        if (-not (TestAdministrator)) { throw "Configuring advanced audit policy requires Administrator privileges." }
        Assert-WelaAuditProfileTarget -Plan $plan -Context $actual -Current $current
        $configurationContext = New-WelaConfigurationContext -Auto:$script:Auto -DryRun:$script:DryRun -BackupPath $script:BackupPath
        Set-WelaProfileAuditControls -Context $configurationContext -Plan $plan
        $sharedResultsPath=if ($script:ProfileFile) { $null } else { $script:ResultsPath }
        $result = Complete-WelaConfiguration -Context $configurationContext -ResultsPath $sharedResultsPath -Plan $plan -Scope advanced-audit-policy-and-precedence
        $result | Add-Member NoteProperty SaclPrerequisites $saclPlan
        if ($script:ResultsPath) {
            if ($script:ProfileFile) { Write-WelaCustomProfileReport $result $script:ResultsPath }
            else { $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:ResultsPath -Encoding UTF8 -ErrorAction Stop }
        }
        $result.Results | Format-Table Id, Before, Desired, After, Status -AutoSize
    } else {
        $plan.policies | Format-Table id, mode, currentMask, requiredMask, action -AutoSize
        if ($script:ProfileFile -and $script:ResultsPath) {
            Assert-WelaCustomProfileSource $custom.customSource
            Write-WelaCustomProfileReport $plan $script:ResultsPath
        }
    }
    if ($script:PlanPath) {
        if ($script:ProfileFile) {
            if ($Command -ne 'configure') { Assert-WelaCustomProfileSource $custom.customSource }
            Write-WelaCustomProfileReport $result $script:PlanPath
        } else { $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:PlanPath -Encoding UTF8 -ErrorAction Stop }
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
    $nativeCache = @{}
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
        $nativeSources = @()
        switch ($item.currentSetting.type) {
            "native-channel" {
                # Channel availability is observed separately from event generation.
                # Rule-specific source mappings are attached after filtering below.
                $enabled = $false
                $current = 'Unknown'
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
            if ($item.currentSetting.type -eq 'native-channel') {
                $channels = @($channels) + @($item.currentSetting.channels)
            }
            $guid     = $item.select.guid
            $rules    = $all_rules | Where-Object { RuleFilter $_ $eids $channels $guid }
        }
        if ($item.currentSetting.type -eq 'native-channel') {
            $nativeSources = @(Get-WelaNativeSources -Definition $item.currentSetting -Rules @($rules) -Cache $nativeCache)
            $sourceRuleIds = @($nativeSources | ForEach-Object { $_.MappedRuleIds })
            $rules = @($rules | Where-Object { $sourceRuleIds -contains $_.id })
            $current = Get-WelaNativeSourceState -Sources $nativeSources
        }

        # 1つのルールは複数カテゴリに属しうるので、有効なカテゴリが1つでもあれば
        # 利用可能とする(OR)。カテゴリごとに上書きすると最後のカテゴリで結果が決まってしまう。
        if ($enabled) {
            $rules | ForEach-Object { $_.applicable = $true }
        }
        if ($setting.ideal -and $item.currentSetting.type -ne 'native-channel') {
            $rules | ForEach-Object { $_.ideal = $true }
        }

        $entry = [WELA]::New(
                $item.category,
                $item.subCategory,
                $current,
                [array]$rules,
                $setting.defaultSetting,
                $setting.recommendedSetting,
                $setting.volume,
                $setting.note
        )
        $entry.NativeSources = $nativeSources
        if ($nativeSources.Count) {
            $entry.ChannelState = (@($nativeSources | ForEach-Object { $_.Channel.State } | Select-Object -Unique)) -join '; '
            $entry.GenerationReadiness = (@($nativeSources | ForEach-Object { $_.Provider.Readiness } | Select-Object -Unique)) -join '; '
            $entry.Note = ($entry.Note + ' Channel availability does not establish event generation. Native provider rule coverage remains unconfirmed; inspect source evidence and validate representative events.').Trim()
        }
        $auditResult += $entry
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
        [switch] $debug,
        [string] $ResultsPath,
        [string] $HtmlPath
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
    # Policy/channel matches are configuration estimates, not executed rules.
    # Imported lab Ready states are reviewed separately by rule-eligibility and
    # never silently reused as evidence for this currently audited machine.
    $eligibility = Get-WelaRuleEligibility -CorpusPath $script:SecurityRulesPath -Observations $auditResult
    $eligibilityById = @{}
    foreach ($entry in $eligibility.Results) { $eligibilityById[$entry.Id] = $entry }
    foreach ($rule in $all_rules) {
        $entry = $eligibilityById[$rule.id]
        $rule | Add-Member NoteProperty ConfigurationEstimate ([bool]$rule.applicable) -Force
        $rule | Add-Member NoteProperty IdealConfigurationEstimate ([bool]$rule.ideal) -Force
        $rule | Add-Member NoteProperty EligibilityState $entry.State -Force
        $rule | Add-Member NoteProperty EligibilityReasons ($entry.Reasons -join '; ') -Force
        $rule.applicable = $entry.State -eq 'Ready'
        $rule.ideal = $false # A future configuration plan is never execution evidence.
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
        Write-Host 'Configuration observations: category percentages below are policy-mapping estimates, not detection readiness.' -ForegroundColor DarkYellow
        $auditResult | Group-Object -Property Category | ForEach-Object {
            $notEnabled = @("No Auditing", "Disabled", "Unknown", "Conditional", "Not installed")
            $summaryRows = @($_.Group | Where-Object { $_.CurrentSetting -ne 'Not applicable' })
            $enabledCount = ($summaryRows | Where-Object { $notEnabled -notcontains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $disabledCount = ($summaryRows | Where-Object { $notEnabled -contains $_.CurrentSetting } | ForEach-Object { $_.Rules.Count } | Measure-Object -Sum).Sum
            $out = ""
            $color = ""
            if ($summaryRows.Count -eq 0) {
                $out = 'Not applicable'
                $color = 'DarkYellow'
            }
            elseif (@($summaryRows | Where-Object { $_.NativeSources.Count -eq 0 }).Count -eq 0) {
                $out = ($summaryRows | Select-Object -ExpandProperty CurrentSetting -Unique) -join '; '
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
            if (($_.Name -notmatch "Powershell" -and $_.Name -notmatch "Security Advanced") -or
                @($summaryRows | Where-Object { $_.NativeSources.Count -gt 0 }).Count -gt 0) {
                $enabledPercentage = ""
            }
            Write-Host "$( $_.Name ): $out$($enabledPercentage)" -ForegroundColor $color
            $_.Group | ForEach-Object {
                $_.Output($outType)
            }
            Write-Host ""
        }
    } elseif ($outType -eq "table") {
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, DefaultSetting, DefaultEvidence, CurrentSetting, ChannelState, GenerationReadiness, RecommendedSetting, Volume | Format-Table
    }

    # 1つのルールが複数カテゴリに属するため、集計とCSVはルールID単位で重複排除する
    $uniqueRules = $auditResult | Select-Object -ExpandProperty Rules | Sort-Object -Property id -Unique
    $usableRules   = @($uniqueRules | Where-Object { $_.applicable -eq $true })
    $unUsableRules = @($uniqueRules | Where-Object { $_.applicable -eq $false })

    $auditCsv    = Join-Path $script:ScriptRoot "WELA-Audit-Result.csv"
    $usableCsv   = Join-Path $script:ScriptRoot "UsableRules.csv"
    $unusableCsv = Join-Path $script:ScriptRoot "UnusableRules.csv"
    $eligibilityCsv = Join-Path $script:ScriptRoot "RuleEligibility.csv"
    $currentJson = Join-Path $script:ScriptRoot "mitre-ttp-navigator-current.json"
    $idealJson   = Join-Path $script:ScriptRoot "mitre-ttp-navigator-ideal.json"

    $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, DefaultEvidence, LegacyDefaultHint, CurrentSetting, ChannelState, GenerationReadiness, RecommendedSetting, Volume, Note,
        @{ Name = 'NativeSourceEvidence'; Expression = { if ($_.NativeSources.Count) { ConvertTo-Json -InputObject $_.NativeSources -Depth 12 -Compress } else { '' } } } |
        Export-Csv -Path $auditCsv -NoTypeInformation
    $usableRules   | Select-Object title, level, service, category, description, id, EligibilityState, EligibilityReasons | Export-Csv -Path $usableCsv -NoTypeInformation
    $unUsableRules | Select-Object title, level, service, category, description, id, EligibilityState, EligibilityReasons | Export-Csv -Path $unusableCsv -NoTypeInformation
    $eligibility.Results | Select-Object Id, Title, State, ScopeExclusion, ConfigurationEstimate, MetadataSha256,
        @{Name='Reasons'; Expression={$_.Reasons -join '; '}} | Export-Csv -LiteralPath $eligibilityCsv -NoTypeInformation
    if ($ResultsPath -or $HtmlPath) {
        Export-WelaAuditAssessment -Rows $auditResult -Rules @($uniqueRules) -Baseline $Baseline -ResultsPath $ResultsPath -HtmlPath $HtmlPath -Eligibility $eligibility
    }

    if ($outType -eq "gui") {
        $usableRules   | Select-Object title, level, service, category, description, id | Out-GridView -Title "Usable Detection Rules"
        $unUsableRules | Select-Object title, level, service, category, description, id | Out-GridView -Title "Unusable Detection Rules"
        $auditResult | Select-Object -Property Category, SubCategory, RuleCount, RuleCountByLevel, DefaultSetting, DefaultEvidence, LegacyDefaultHint, CurrentSetting, ChannelState, GenerationReadiness, RecommendedSetting, Volume, Note | Out-GridView -Title "WELA Audit Result"
    }

    Write-Output "Audit check result saved to: $auditCsv"
    Write-Output "Usable detection rules list saved to: $usableCsv"
    Write-Output "Unusable detection rules list saved to: $unusableCsv"
    Write-Output "Per-rule readiness and reasons saved to: $eligibilityCsv"
    if ($ResultsPath) { Write-Output "Audit assessment JSON saved to: $ResultsPath" }
    if ($HtmlPath) { Write-Output "Audit assessment HTML saved to: $HtmlPath" }
    if (@($auditResult | Where-Object { $_.NativeSources.Count -gt 0 }).Count) {
        Write-Host 'Native provider rules remain unconfirmed until event-specific generation is validated; enabled channels alone receive no usable-rule credit.' -ForegroundColor DarkYellow
    }

    Export-MitreHeatmap -sigmaRules $uniqueRules -OutputPath $currentJson
    Write-Output "MITRE ATT&CK Navigator data (evidence-qualified Ready rules) saved to: $currentJson"
    Export-MitreHeatmap -sigmaRules $uniqueRules -OutputPath $idealJson -UseIdealCount $true
    Write-Output "MITRE ATT&CK Navigator ideal data (no readiness credit from configuration alone) saved to: $idealJson"

    $totalRulesCount  = @($uniqueRules).Count
    $usableRulesCount = $usableRules.Count
    Write-Host ""
    if ($totalRulesCount -eq 0) {
        Write-Host "No detection rules were loaded, so utilization cannot be calculated." -ForegroundColor Red
    } else {
        # 数値のまま閾値判定する。書式化した文字列で比較すると辞書順比較になる
        $utilization = ($usableRulesCount / $totalRulesCount) * 100
        $color = if ($utilization -ge 70) { "Green" } elseif ($utilization -ge 10) { "DarkYellow" } else { "Red" }
        Write-Host ("Evidence-qualified Ready: {0}/{1} native candidates ({2:N2}% of all {3} unique input rules)." -f $usableRulesCount, $eligibility.Summary.NativeCandidates, $utilization, $totalRulesCount) -ForegroundColor $color
        Write-Host 'Configuration matches are estimates only. Use rule-eligibility to review complete imported lab evidence; Conditional rules are not counted as Ready.' -ForegroundColor DarkYellow
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
    param([string]$LogProfile = 'wela-source-2.2.0')
    if (-not (TestWindows)) { throw "'audit-filesize' reads Windows event logs and can only run on Windows." }
    $results = @(Get-WelaEventLogAudit -Profile $LogProfile)
    $results | Format-Table Log, ReadStatus, CurrentMaximumMiB, MinimumBytes, SizeStatus, CurrentMode, RecommendedMode, ModeStatus -AutoSize | Out-Host
    Write-Host 'Sizes use exact bytes (MiB = 1048576 bytes). Retention days: Unknown; measure event volume and verify collection/archive storage.'
    Write-Host 'Mode recommendations are separate from size compliance. configure-eventlogs changes modes only with -ApplyLogMode.'
    $fileSizeCsv = Join-Path $script:ScriptRoot "WELA-FileSize-Result.csv"
    $results | Export-Csv -LiteralPath $fileSizeCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "Event-log audit saved to: $fileSizeCsv"
}


function UpdateRules {
    $baseUrl = "https://raw.githubusercontent.com/Yamato-Security/WELA/main/config"
    $downloads = @(
        @{ Url = "$baseUrl/eid_subcategory_mapping.csv"; Path = $script:EidMappingPath },
        @{ Url = "$baseUrl/security_rules.json";         Path = $script:SecurityRulesPath },
        @{ Url = "$baseUrl/audit_sacl_targets.json";     Path = $script:SaclTargetsPath },
        @{ Url = "$baseUrl/rule_eligibility_manifest.json"; Path = (Join-Path $script:ScriptRoot 'config/rule_eligibility_manifest.json') }
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

    # Audit and configure consume the same default size thresholds; modes stay unchanged.
    Set-WelaEventLogProfileControls -Context $context -Profile 'wela-source-2.2.0'
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
        Write-Host 'LDAP 1644 diagnostics are preserved. MDI no longer requires them; use ldap-diagnostics for explicit Diagnostic or MdiCleanup changes.' -ForegroundColor Yellow
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
  ./WELA.ps1 gpo-package -GpoAction Plan -GpoProfile wela-2.2.0 -Role Client -Build 26100
  ./WELA.ps1 gpo-package -GpoAction Export -GpoProfile wela-2.2.0 -Role Client -Build 26100 -GpoOutputPath .\audit-components
  ./WELA.ps1 gpo-package -GpoAction Verify -GpoOutputPath .\audit-components

  ./WELA.ps1 audit-integrity -IntegrityAction Audit -ResultsPath integrity.json
  ./WELA.ps1 audit-integrity -IntegrityAction Plan -IntegrityProfile cis-server2022-v4-dc
  ./WELA.ps1 audit-integrity -IntegrityAction Configure -IntegrityProfile cis-win11-v4-l1 -DryRun
  ./WELA.ps1 ldap-diagnostics -LdapAction Audit
  ./WELA.ps1 ldap-diagnostics -LdapAction Plan -LdapMode Diagnostic -LdapSearchTimeMs 100
  ./WELA.ps1 ldap-diagnostics -LdapAction Configure -LdapMode Diagnostic -LdapSearchTimeMs 100 -DryRun
  ./WELA.ps1 channel-settings -ChannelAction Audit -WefQuerySet Both -ResultsPath channels.json
  ./WELA.ps1 channel-settings -ChannelAction Plan -GrantEventLogReaders
  ./WELA.ps1 channel-settings -ChannelAction Configure -GrantEventLogReaders -DryRun
  ./WELA.ps1 provider-packs -ProviderAction List
  ./WELA.ps1 provider-packs -ProviderAction Plan -ProviderPack dns-client,capi2 -ResultsPath provider-plan.json

  ./WELA.ps1 wef-source -WefAction Plan -WefConfigPath source.json -ResultsPath source-plan.json
  ./WELA.ps1 wec-collector -WefAction Configure -WefConfigPath collector.json -DryRun

  ./WELA.ps1 retention-health -ResultsPath source-retention.json
  ./WELA.ps1 retention-health -RetentionConfigPath collector-health.json -HtmlPath retention.html
  # Native channels only; ACL changes require -GrantEventLogReaders. Forwarding identity access needs a separate test.
  ./WELA.ps1 wmi-auditing -WmiAction List
  ./WELA.ps1 wmi-auditing -WmiAction Plan -WmiNamespace root\cimv2 -ResultsPath wmi-plan.json
  ./WELA.ps1 wmi-auditing -WmiAction Configure -WmiNamespace root\cimv2 -DryRun
  # Namespace SACLs are opt-in; descendants require -WmiIncludeChildren. See docs/wmi-namespace-auditing.md.
  ./WELA.ps1 firewall-logging -FirewallAction Audit -ResultsPath firewall.json
  ./WELA.ps1 firewall-logging -FirewallAction Plan -FirewallPathMode CisV4
  ./WELA.ps1 firewall-logging -FirewallAction Configure -DryRun
  # Firewall text logging is opt-in; it does not change firewall enforcement or rules.
  ./WELA.ps1 smb-auditing -SmbAction Audit -ResultsPath smb-audit.json
  ./WELA.ps1 smb-auditing -SmbAction Plan
  ./WELA.ps1 rule-eligibility -ResultsPath eligibility.json -HtmlPath eligibility.html
  ./WELA.ps1 rule-eligibility -RuleEvidencePath reviewed-lab-evidence.json -ResultsPath evidence-review.json
  ./WELA.ps1 smb-auditing -SmbAction Configure -DryRun
  ./WELA.ps1 powershell-transcription -TranscriptionAction Plan -TranscriptDirectory C:\Transcripts -ResultsPath transcription-plan.json
  ./WELA.ps1 applocker-readiness -ResultsPath applocker.json
  ./WELA.ps1 applocker-readiness -AppLockerAction Plan -AppLockerPolicyPath operator-audit.xml
  # SMB auditing is opt-in and never changes signing/encryption requirements or guest access.
  ./WELA.ps1 ad-object-sacl -AdSaclAction Plan -AdServer dc01.example.test -AdSaclProfile MdiDomain
  ./WELA.ps1 profiles                                   # List versioned advanced audit-policy profiles
  ./WELA.ps1 profiles -ProfileFile config/custom-audit-profile.example.json
  ./WELA.ps1 plan -Profile custom-example -ProfileFile config/custom-audit-profile.example.json -Role Client -Build 26100
  ./WELA.ps1 plan -Profile wela-2.2.0 -Role Client -Build 26100 -PlanPath plan.json
  ./WELA.ps1 audit-settings -Profile microsoft-sct-win11-24h2 -PlanPath audit.json
  ./WELA.ps1 configure -Profile asd-native-2021-10 -PlanPath result.json -Auto
  # -Profile changes advanced audit policy plus its precedence prerequisite. Optional controls need -IncludeOptional.
  ./WELA.ps1 audit-settings -Baseline YamatoSecurity     # Audit current setting and show in stdout, save to csv
  ./WELA.ps1 audit-settings -Baseline ASD -OutType gui   # Audit current setting and show in gui, save to csv
  ./WELA.ps1 audit-settings -Baseline YamatoSecurity -ResultsPath audit.json -HtmlPath audit.html
  ./WELA.ps1 eventlog-profiles                          # List size/mode profiles (separate from -Profile)
  ./WELA.ps1 audit-filesize -LogProfile wela-source-2.2.0 # Audit live sizes/modes, save to CSV
  ./WELA.ps1 configure-eventlogs -LogProfile asd-source-2021-10 -DryRun
  ./WELA.ps1 configure-eventlogs -LogProfile asd-collector-archive-2021-10 -ApplyLogMode # Explicit archive choice
  ./WELA.ps1 configure -Baseline YamatoSecurity          # Configure audit settings based on the specified baseline
  ./WELA.ps1 configure -Baseline YamatoSecurity -Auto    # Configure audit settings automatically without prompts
  ./WELA.ps1 plan -Profile asd-native-2021-10 -Role Client -Build 26100 -IncludeOptional -SaclMode Plan
  # Profile plan/audit/configure include read-only SACL prerequisites; -SaclMode Skip reports the telemetry gap.
  ./WELA.ps1 configure-sacl                              # Add targeted File System/Registry audit SACLs (ASEP keys + sensitive files) needed by the rules, without global auditing
  ./WELA.ps1 configure-sacl -Auto                        # ...automatically without prompts
  ./WELA.ps1 update-rules         # Update rule config files from https://github.com/Yamato-Security/WELA
  ./WELA.ps1 control-applicability     # Read-only historical native feature/build assessment
  ./WELA.ps1 default-evidence -Help    # Exact-context observed snapshots and reviewed reference comparison
  ./WELA.ps1 audit-notifications -Help  # OneSettings audit and Security warning policy
  ./WELA.ps1 score -Help    # Separate configuration compliance and evidence-qualified readiness
  ./WELA.ps1 intune-export -Help      # Offline native audit OMA-URI/Graph artifacts; no tenant changes
  ./WELA.ps1 wef-arrival -Help       # Verify exact native probe presence on the local collector
  ./WELA.ps1 native-validation -Help   # Collect a fixed native 4688 probe without changing policy
  ./WELA.ps1 version     # Show the WELA version
  ./WELA.ps1 help        # Show this help
"@


[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host $logo -ForegroundColor Green
Write-Host ""
Write-Host "WELA v$WELAVersion - $WELAReleaseName"
Write-Host ""

if ($Cmd -ne 'score' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('ScoreProfile','ScoreEvidencePath') }).Count) {
    throw 'Scoring options require score. No command was run.'
}
if ($Cmd -eq 'score' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','ScoreProfile','ScoreEvidencePath','Role','Build','IncludeOptional','ResultsPath','HtmlPath','Help') }).Count) {
    throw 'score accepts only score, scenario, optional-selection and report options. No command was run.'
}

if ($Cmd -ne 'gpo-package' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('GpoAction','GpoProfile','GpoOutputPath','GpoMinimumMode') }).Count) {
    throw 'GPO package options require gpo-package. No command was run.'
}

if ($Cmd -ne 'intune-export' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('IntuneProfile','IntuneBuild','IntuneEdition','IntuneOutputPath','IntuneMinimumMode') }).Count) {
    throw 'Intune options require the offline intune-export command. No command was run.'
}
if ($Cmd -eq 'intune-export' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','IntuneProfile','IntuneBuild','IntuneEdition','IntuneOutputPath','IntuneMinimumMode','IncludeOptional','Help') }).Count) {
    throw 'intune-export accepts only Intune target/export options, IncludeOptional and Help. No command was run.'
}

if ($Cmd -ne 'evtx-recovery' -and @($PSBoundParameters.Keys | Where-Object {$_ -like 'Evtx*'}).Count) {throw 'EVTX options require evtx-recovery. No command was run.'}
if ($Cmd -eq 'evtx-recovery' -and @($PSBoundParameters.Keys | Where-Object {$_ -notin @('Cmd','EvtxAction','EvtxProbePath','EvtxArchivePath','EvtxOutputPath','Help')}).Count) {throw 'evtx-recovery accepts only its dedicated options. No command was run.'}
if ($Cmd -ne 'audit-recovery' -and @($PSBoundParameters.Keys | Where-Object {$_ -like 'Recovery*'}).Count) {throw 'Recovery options require audit-recovery. No command was run.'}
if ($Cmd -eq 'audit-recovery' -and @($PSBoundParameters.Keys | Where-Object {$_ -notin @('Cmd','RecoveryAction','RecoveryJournalPath','RecoveryOriginalResultsPath','RecoveryControlId','RecoveryPlanPath','RecoveryOutputPath','Auto','DryRun','Help')}).Count) {throw 'audit-recovery accepts only dedicated recovery options, Auto and DryRun. No command was run.'}

if ($PSBoundParameters.ContainsKey('ProfileFile')) {
    if ([string]::IsNullOrWhiteSpace($ProfileFile) -or $Cmd -notin @('profiles','plan','audit','audit-settings','configure')) { throw '-ProfileFile requires profiles, plan, audit, audit-settings or configure. No command was run.' }
    if ($Baseline -or ($Cmd -ne 'profiles' -and -not $Profile)) { throw '-ProfileFile requires an explicit -Profile and cannot be combined with -Baseline (profiles lists the file). No command was run.' }
    $allowed = @('Cmd','Profile','ProfileFile','Role','Build','PlanPath','IncludeOptional','SaclMode','Auto','DryRun','BackupPath','ResultsPath','Help')
    if (@($PSBoundParameters.Keys | Where-Object { $_ -notin $allowed }).Count) { throw 'Unsupported option for custom audit profiles. No command was run.' }
    if ($Cmd -eq 'profiles' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','ProfileFile','Help') }).Count) { throw 'profiles -ProfileFile lists the selected file and accepts no assessment/configuration options.' }
}

if ($Cmd -ne 'wef-arrival' -and @($PSBoundParameters.Keys | Where-Object {$_ -in @('ArrivalProbePath','ArrivalOutputPath')}).Count) {
    throw 'Arrival options require wef-arrival. No command was run.'
}
if ($Cmd -eq 'wef-arrival' -and @($PSBoundParameters.Keys | Where-Object {$_ -notin @('Cmd','ArrivalProbePath','ArrivalOutputPath','Help')}).Count) {
    throw 'wef-arrival accepts only its dedicated source and output paths. No command was run.'
}
if ($Cmd -ne 'native-validation' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('ProbeAction','ProbeOutputPath','ProbeTimeoutSeconds') }).Count) {
    throw 'Probe options require native-validation. No command was run.'
}
if ($Cmd -eq 'native-validation' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','ProbeAction','ProbeOutputPath','ProbeTimeoutSeconds','Help') }).Count) {
    throw 'native-validation accepts only its dedicated probe options. No command was run.'
}

if ($Cmd -ne 'audit-integrity' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('IntegrityAction','IntegrityProfile','AllowPrivilegeRemoval') }).Count) {
    throw 'Integrity options require the dedicated audit-integrity command. No command was run.'
}

if ($Cmd -ne 'default-evidence' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('DefaultEvidenceAction','DefaultEvidencePath') }).Count) {
    throw 'Default evidence options require default-evidence. No command was run.'
}

if ($Cmd -eq 'audit-notifications' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','NotificationAction','NotificationControl','WarningPercent','EnablePrivacyChannel','Auto','DryRun','BackupPath','ResultsPath','Help') }).Count) {
    throw 'audit-notifications accepts only notification, consent/dry-run, recovery and JSON output options. No command was run.'
}

if ($Cmd -ne 'audit-notifications' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('NotificationAction','NotificationControl','WarningPercent','EnablePrivacyChannel') }).Count) {
    throw 'Notification options require audit-notifications. No command was run.'
}

if ($Cmd -ne 'rule-eligibility' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('RuleEvidencePath', 'RuleCorpusPath', 'RuleManifestPath') }).Count) {
    throw '-RuleEvidencePath, -RuleCorpusPath and -RuleManifestPath require the read-only rule-eligibility command. No command was run.'
}
if (($PSBoundParameters.ContainsKey('AppLockerAction') -or $AppLockerPolicyPath) -and $Cmd -ne 'applocker-readiness') {
    throw '-AppLockerAction and -AppLockerPolicyPath require applocker-readiness. No command was run.'
}
if (($PSBoundParameters.ContainsKey('WefAction') -or $PSBoundParameters.ContainsKey('WefConfigPath')) -and $Cmd -notin @('wef-source','wec-collector')) {
    throw '-WefAction and -WefConfigPath require wef-source or wec-collector. No command was run.'
}
if (($PSBoundParameters.ContainsKey('RetentionConfigPath') -or $PSBoundParameters.ContainsKey('RetentionPreviousPath')) -and $Cmd -ne 'retention-health') {
    throw 'Retention options require retention-health. No command was run.'
}
if ($Cmd -eq 'retention-health' -and @($PSBoundParameters.Keys | Where-Object { $_ -notin @('Cmd','RetentionConfigPath','RetentionPreviousPath','ResultsPath','HtmlPath','Help') }).Count) {
    throw 'retention-health is read-only and accepts only its config/previous report paths, ResultsPath, HtmlPath and Help. No command was run.'
}
if ($Cmd -eq 'applocker-readiness' -and ($Profile -or $Baseline)) {
    throw 'applocker-readiness uses its own operator-supplied policy, not -Profile or -Baseline. No command was run.'
}
# SaclMode belongs only to the read-only profile companion plan. In particular,
# configure-sacl must never silently ignore an explicit request to Skip.
if ($PSBoundParameters.ContainsKey('SaclMode') -and
    (-not $Profile -or $Cmd -notin @('plan', 'audit', 'audit-settings', 'configure'))) {
    throw '-SaclMode requires -Profile with plan, audit, audit-settings or configure. It does not control configure-sacl. No command was run.'
}
# Reject unsupported dry-run requests before reaching any command's mutation path.
if ($Cmd -ne 'provider-packs' -and ($PSBoundParameters.ContainsKey('ProviderAction') -or $PSBoundParameters.ContainsKey('ProviderPack'))) {
    throw 'Provider options require provider-packs. No command was run.'
}
if ($Cmd -ne 'powershell-transcription' -and
    ($PSBoundParameters.ContainsKey('TranscriptionAction') -or $PSBoundParameters.ContainsKey('TranscriptDirectory'))) {
    throw 'Transcription options require the dedicated powershell-transcription command. No command was run.'
}
if ($Cmd -ne 'ad-object-sacl' -and @($PSBoundParameters.Keys | Where-Object {
    $_ -in @('AdSaclAction', 'AdServer', 'AdSaclProfile', 'AdObjectDn', 'AdReceiptPath')
}).Count) {
    throw 'AD object SACL options require the dedicated ad-object-sacl command. No command was run.'
}
if ($DryRun -and -not ($Cmd -eq 'audit-recovery' -and $RecoveryAction -eq 'Restore') -and -not ($Cmd -eq 'gpo-package' -and $GpoAction -eq 'Export') -and -not ($Cmd -eq 'audit-integrity' -and $IntegrityAction -eq 'Configure') -and -not ($Cmd -eq 'audit-notifications' -and $NotificationAction -eq 'Configure') -and -not ($Cmd -eq 'ldap-diagnostics' -and $LdapAction -eq 'Configure') -and -not ($Cmd -eq 'applocker-readiness' -and $AppLockerAction -eq 'Import') -and $Cmd -notin @('configure', 'configure-eventlogs') -and
    -not ($Cmd -eq 'provider-packs' -and $ProviderAction -eq 'Configure') -and
    -not ($Cmd -eq 'firewall-logging' -and $FirewallAction -eq 'Configure') -and
    -not ($Cmd -eq 'smb-auditing' -and $SmbAction -eq 'Configure') -and
    -not ($Cmd -eq 'powershell-transcription' -and $TranscriptionAction -eq 'Configure') -and
    -not ($Cmd -eq 'channel-settings' -and $ChannelAction -eq 'Configure') -and
    -not ($Cmd -in @('wef-source','wec-collector') -and $WefAction -eq 'Configure') -and
    -not ($Cmd -eq 'ad-object-sacl' -and $AdSaclAction -in @('Configure', 'Rollback')) -and
    -not ($Cmd -eq 'wmi-auditing' -and $WmiAction -eq 'Configure')) {
    throw "-DryRun is supported only by configure (including configure -Profile), configure-eventlogs, firewall-logging -FirewallAction Configure, smb-auditing -SmbAction Configure, powershell-transcription -TranscriptionAction Configure, wmi-auditing -WmiAction Configure, channel-settings -ChannelAction Configure, wef-source/wec-collector -WefAction Configure, applocker-readiness -AppLockerAction Import, ad-object-sacl -AdSaclAction Configure|Rollback, ldap-diagnostics -LdapAction Configure, provider-packs -ProviderAction Configure, audit-integrity -IntegrityAction Configure, and audit-notifications -NotificationAction Configure; gpo-package -GpoAction Export writes component files only. No command was run."
}
if (($WmiNamespace -or $WmiIncludeChildren -or $PSBoundParameters.ContainsKey('WmiAction')) -and $Cmd -ne 'wmi-auditing') {
    throw '-WmiAction, -WmiNamespace and -WmiIncludeChildren require wmi-auditing. No command was run.'
}
if ($Profile -and $Cmd -in @('eventlog-profiles', 'audit-filesize', 'configure-eventlogs')) {
    throw '-Profile selects advanced audit policy only. Use -LogProfile for event-log size/mode settings.'
}
if ($LogProfile -and $Cmd -notin @('audit-filesize', 'configure-eventlogs')) {
    throw '-LogProfile is supported only by audit-filesize and configure-eventlogs.'
}
if (($ResizeLogs -or $ApplyLogMode) -and $Cmd -ne 'configure-eventlogs') {
    throw '-ResizeLogs and -ApplyLogMode require configure-eventlogs. No command was run.'
}

if (($PSBoundParameters.ContainsKey('ChannelAction') -or $PSBoundParameters.ContainsKey('ChannelProfile') -or
    $PSBoundParameters.ContainsKey('WefQuerySet') -or $GrantEventLogReaders) -and $Cmd -ne 'channel-settings') {
    throw 'Channel options require channel-settings. No command was run.'
}

if ($Cmd -ne 'ldap-diagnostics' -and @($PSBoundParameters.Keys | Where-Object { $_ -in @('LdapAction','LdapMode','LdapSearchTimeMs','LdapExpensiveThreshold','LdapInefficientThreshold') }).Count) {
    throw 'LDAP options require the dedicated ldap-diagnostics command. No command was run.'
}

if ($Profile -and $Cmd.ToLower() -in @('plan', 'audit', 'audit-settings', 'configure') -and -not $Help) {
    Invoke-WelaProfileCommand -Command $Cmd.ToLower()
    return
}

switch ($Cmd.ToLower()) {
    'score' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 score -ScoreProfile profile-id [-Role role -Build build] [-IncludeOptional] [-ScoreEvidencePath evidence.json] [-ResultsPath new.json] [-HtmlPath new.html]. Explicit role/build is an offline scenario; omit both to observe this Windows host. Two separate measures, no overall security grade. See docs/audit-scoring.md.'; return }
        if (-not $ScoreProfile) { throw 'score requires an explicit -ScoreProfile. Use profiles to list built-in profiles.' }
        $report=Invoke-WelaAuditScore -Profile $ScoreProfile -EvidencePath $ScoreEvidencePath -Role $Role -Build $Build -IncludeOptional:$IncludeOptional
        Export-WelaAuditScore -Report $report -ResultsPath $ResultsPath -HtmlPath $HtmlPath
        $report.Configuration | Select-Object Label,Numerator,Denominator,Percent,Unknown | Format-List
        $report.Readiness | Select-Object Label,Numerator,Denominator,Percent,Ready,ApplicableUniqueRules | Format-List
    }
    'gpo-package' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 gpo-package [-GpoAction Plan|Export|Verify] [-GpoProfile profile-id -Role Client|MemberServer|DomainController|ADCS -Build number] [-GpoMinimumMode Reject|PromoteToBoth] [-IncludeOptional] [-GpoOutputPath directory] [-DryRun]. Export requires a fresh directory. These are offline components, not an importable GPO backup. See docs/gpo-audit-packages.md.'; return }
        if ($Profile -or $Baseline -or $HtmlPath -or $Auto -or $BackupPath -or $PlanPath -or $ResultsPath) { throw 'gpo-package uses GpoProfile and GpoOutputPath. Export contains its JSON manifest/review; other profile, result, backup and configuration options are unsupported.' }
        if ($GpoAction -eq 'Verify' -and @($PSBoundParameters.Keys|Where-Object {$_ -in @('GpoProfile','Role','Build','GpoMinimumMode','IncludeOptional')}).Count) {throw 'Verify reads package context; do not supply profile, role/build or expansion overrides.'}
        $report=Invoke-WelaGpoPackageCommand -Action $GpoAction -Profile $GpoProfile -Role $Role -Build $Build -MinimumMode $GpoMinimumMode -IncludeOptional:$IncludeOptional -Path $GpoOutputPath -DryRun:$DryRun
        $report
        if ($report.ExitCode) {exit $report.ExitCode}
    }
    'intune-export' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 intune-export -IntuneProfile shared-profile-id -IntuneBuild 26100|26200 -IntuneEdition Pro|Enterprise|Education|IoTEnterprise -IntuneOutputPath new-local-directory [-IntuneMinimumMode Reject|PromoteToBoth] [-IncludeOptional]. Offline native audit artifacts only; no tenant or Windows changes. See docs/intune-audit-export.md.'; return }
        try {
            if (-not $IntuneProfile -or -not $IntuneBuild -or -not $IntuneEdition -or -not $IntuneOutputPath) { throw 'IntuneProfile, IntuneBuild, IntuneEdition and IntuneOutputPath are required.' }
            $report=Invoke-WelaIntuneAuditExport -Profile $IntuneProfile -Build $IntuneBuild -Edition $IntuneEdition -OutputPath $IntuneOutputPath -MinimumMode $IntuneMinimumMode -IncludeOptional:$IncludeOptional
            $report | Select-Object Status,OutputPath,PayloadEmitted,ExitCode
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] Intune export: $_" -ForegroundColor Red; exit 1 }
    }
    'evtx-recovery' {
        if ($Help) {Write-Host 'Usage: evtx-recovery -EvtxAction Export -EvtxProbePath validated-probe-directory -EvtxOutputPath new-directory; or -EvtxAction Verify -EvtxProbePath validated-probe-directory -EvtxArchivePath probe.evtx -EvtxOutputPath new-directory. No policy changes. See docs/evtx-recovery.md.';return}
        $report=Invoke-WelaEvtxRecovery -Action $EvtxAction -ProbePath $EvtxProbePath -ArchivePath $EvtxArchivePath -OutputPath $EvtxOutputPath
        $report
        if ($report.ExitCode) {exit $report.ExitCode}
    }
    'audit-recovery' {
        if ($Help) {Write-Host 'Usage: audit-recovery [-RecoveryAction Plan] -RecoveryJournalPath before.jsonl -RecoveryOriginalResultsPath results.json -RecoveryControlId IDs -RecoveryOutputPath new-directory; then -RecoveryAction Restore -RecoveryPlanPath reviewed-plan.json -RecoveryOutputPath new-directory [-Auto], or -DryRun without output. See docs/audit-recovery.md.';return}
        $report=Invoke-WelaAuditRecovery -Action $RecoveryAction -JournalPath $RecoveryJournalPath -OriginalResultsPath $RecoveryOriginalResultsPath -ControlId $RecoveryControlId -PlanPath $RecoveryPlanPath -OutputPath $RecoveryOutputPath -Auto:$Auto -DryRun:$DryRun
        $report
        if ($report.ExitCode) {exit $report.ExitCode}
    }
    'wef-arrival' {
        if ($Help) {Write-Host 'Usage: ./WELA.ps1 wef-arrival -ArrivalProbePath existing-native-probe-directory -ArrivalOutputPath new-private-directory. Reads local ForwardedEvents and matches the exact original probe payload. No subscriptions, policy changes, latency or Sigma readiness claims. See docs/wef-arrival.md.'; return}
        if (-not $ArrivalProbePath -or -not $ArrivalOutputPath) {throw 'ArrivalProbePath and ArrivalOutputPath are required.'}
        $report=Invoke-WelaWefArrival -ProbePath $ArrivalProbePath -OutputPath $ArrivalOutputPath
        $report
        if ($report.ExitCode) {exit $report.ExitCode}
    }
    'native-validation' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 native-validation [-ProbeAction Plan|Run] [-ProbeOutputPath new-directory] [-ProbeTimeoutSeconds 1..30]. Plan reads prerequisites; Run launches a fixed benign cmd.exe probe and collects exact native Security 4688 XML. No policy changes or Sigma readiness credit. See docs/native-validation.md.'; return }
        $report=Invoke-WelaNativeValidation -Action $ProbeAction -OutputPath $ProbeOutputPath -TimeoutSeconds $ProbeTimeoutSeconds
        $report
        if ($report.ExitCode -ne 0) { exit 1 }
    }

    'audit-integrity' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 audit-integrity [-IntegrityAction Audit|Plan|Configure] [-IntegrityProfile source-id] [-AllowPrivilegeRemoval] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath report.json]. Audit is read-only; Plan/Configure require an exact source profile. See docs/audit-integrity.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath) { throw 'audit-integrity observes the actual local Windows host; use -IntegrityProfile and -ResultsPath, without Security profiles, role/build overrides or HTML.' }
        if ($IntegrityAction -eq 'Configure' -and -not (TestAdministrator)) { throw 'Audit-integrity Configure requires Administrator privileges.' }
        $report=Invoke-WelaIntegrityCommand -Action $IntegrityAction -Profile $IntegrityProfile -AllowPrivilegeRemoval:$AllowPrivilegeRemoval -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
        $report
        if ($report.ExitCode) { exit $report.ExitCode }
    }
    'retention-health' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 retention-health [-RetentionConfigPath operator.json] [-RetentionPreviousPath prior-local-report.json] [-ResultsPath report.json] [-HtmlPath report.html]'
            Write-Host 'Read-only local native source/collector buffer, event-age, bounded XML rate, archive declaration/inventory, WEF and time evidence. Default: Source with Security/System/Application and no archive declaration. No retention-compliance or delivery claim. See docs/retention-health.md.'
            return
        }
        try {
            $report=Invoke-WelaRetentionHealth -ConfigPath $RetentionConfigPath -PreviousPath $RetentionPreviousPath -ResultsPath $ResultsPath -HtmlPath $HtmlPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] Retention health: $_" -ForegroundColor Red; exit 1 }
    }
    'control-applicability' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 control-applicability [-ResultsPath report.json]. Read-only historical feature/build assessment; see docs/control-applicability.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath -or $Auto -or $BackupPath -or $PlanPath) { throw 'control-applicability reads actual local context and only accepts -ResultsPath; configuration and context overrides are unsupported.' }
        $context=Get-WelaDefaultContext
        $controls=@(Get-WelaHistoricalControls -Context $context)
        $report=[pscustomobject]@{Scope='Native historical controls; Sysmon excluded';Context=$context;Controls=$controls;Catalog=(Get-WelaControlCatalog)}
        if ($ResultsPath) { $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8 -ErrorAction Stop }
        $report
        if (@($controls | Where-Object {$_.Applicability.Status -eq 'Unknown' -or $_.PolicyState -eq 'Unknown'}).Count) { exit 1 }
    }
    'default-evidence' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 default-evidence [-DefaultEvidenceAction Capture|Compare] [-DefaultEvidencePath reviewed-snapshot.json] [-ResultsPath report.json]. Capture observes current settings and never labels them as defaults. See docs/control-applicability.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath -or $Auto -or $BackupPath -or $PlanPath) { throw 'default-evidence reads actual local context and accepts only evidence/output options.' }
        $report=Invoke-WelaDefaultEvidenceCommand -Action $DefaultEvidenceAction -ReferencePath $DefaultEvidencePath -ResultsPath $ResultsPath
        $report
        if ($report.ExitCode) { exit $report.ExitCode }
    }
    'audit-notifications' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 audit-notifications [-NotificationAction Audit|Plan|Configure] [-NotificationControl OneSettings,SecurityWarning] [-WarningPercent 1..90] [-EnablePrivacyChannel] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath report.json]. See docs/audit-notifications.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath) { throw 'audit-notifications uses actual host context and -ResultsPath; profile/role/build overrides and HTML are unsupported.' }
        if ($NotificationAction -eq 'Configure' -and -not (TestAdministrator)) { throw 'Notification Configure requires Administrator privileges.' }
        $report=Invoke-WelaNotificationCommand -Action $NotificationAction -Control $NotificationControl -WarningPercent $WarningPercent -EnablePrivacyChannel:$EnablePrivacyChannel -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
        $report
        if ($report.ExitCode) { exit $report.ExitCode }
    }

    'rule-eligibility' {
        if ($Profile -or $Baseline -or $Auto -or $PlanPath) { throw 'rule-eligibility reviews native rule metadata and optional lab artifacts; use -ResultsPath/-HtmlPath, not configuration options.' }
        $arguments = @{}
        if ($RuleCorpusPath) { $arguments.CorpusPath = $RuleCorpusPath }
        if ($RuleManifestPath) { $arguments.ManifestPath = $RuleManifestPath }
        if ($RuleEvidencePath) { $arguments.EvidencePath = $RuleEvidencePath }
        if ($Role) { $arguments.Role = $Role }
        if ($Build) { $arguments.Build = $Build }
        $report = Get-WelaRuleEligibility @arguments
        Export-WelaRuleEligibility -Report $report -ResultsPath $ResultsPath -HtmlPath $HtmlPath
        Write-Host $report.AssessmentBasis
        $report.Summary | Format-List
        if ($ResultsPath) { Write-Host "Per-rule JSON: $ResultsPath" }
        if ($HtmlPath) { Write-Host "HTML report: $HtmlPath" }
    }
    { $_ -in @('wef-source','wec-collector') } {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 wef-source|wec-collector -WefConfigPath operator.json [-WefAction Audit|Plan|Configure] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Native domain/Kerberos HTTP source configuration and create-only collector subscriptions. Existing collector listener and explicit scoped ingress are prerequisites. Optional ASD hardening is explicit in JSON. See docs/wef-deployment.md; forwarding/event arrival remain unverified.'
            return
        }
        if ($Profile -or $Baseline -or $HtmlPath) { throw 'WEF commands require their own explicit JSON config and use -ResultsPath; -Profile, -Baseline and -HtmlPath are unsupported.' }
        if ($WefAction -eq 'Configure' -and -not (TestAdministrator)) { throw 'WEF Configure requires Administrator privileges.' }
        try {
            $wefRole=if ($Cmd -eq 'wef-source') { 'Source' } else { 'Collector' }
            $report=Invoke-WelaWefCommand -Role $wefRole -Action $WefAction -ConfigPath $WefConfigPath -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] WEF configuration: $_" -ForegroundColor Red; exit 1 }
    }
    'ldap-diagnostics' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 ldap-diagnostics [-LdapAction Audit|Plan|Configure] [-LdapMode Preserve|Diagnostic|MdiCleanup] [-LdapSearchTimeMs positive-ms] [-LdapExpensiveThreshold positive-count] [-LdapInefficientThreshold positive-count] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath report.json]. See docs/ldap-diagnostics.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath) { throw 'ldap-diagnostics observes the actual local DC and uses -LdapMode/-ResultsPath; audit profiles, role overrides and HTML output do not apply.' }
        if ($LdapAction -eq 'Configure' -and $LdapMode -ne 'Preserve' -and -not (TestAdministrator)) { throw 'LDAP configuration requires Administrator privileges.' }
        $thresholds=@{}
        if ($PSBoundParameters.ContainsKey('LdapSearchTimeMs')) { $thresholds.SearchTime=$LdapSearchTimeMs }
        if ($PSBoundParameters.ContainsKey('LdapExpensiveThreshold')) { $thresholds.Expensive=$LdapExpensiveThreshold }
        if ($PSBoundParameters.ContainsKey('LdapInefficientThreshold')) { $thresholds.Inefficient=$LdapInefficientThreshold }
        $report=Invoke-WelaLdapCommand -Action $LdapAction -Mode $LdapMode -Thresholds $thresholds -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
        $report
        if ($report.ExitCode) { exit $report.ExitCode }
    }
    'provider-packs' {
        if ($Help) { Write-Host 'Usage: ./WELA.ps1 provider-packs [-ProviderAction List|Audit|Plan|Configure] [-ProviderPack dns-client,capi2,winrm,rdp-client,dns-server-audit] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath report.json]. DNS classic/analytical packs are manual inventory. See docs/native-provider-packs.md.'; return }
        if ($Profile -or $Baseline -or $Role -or $Build -or $HtmlPath -or $PlanPath) { throw 'provider-packs uses explicit pack names, actual host role/build and -ResultsPath JSON; audit profiles and context overrides do not apply.' }
        if ($ProviderAction -ne 'Configure' -and ($Auto -or $BackupPath)) { throw '-Auto and -BackupPath require ProviderAction Configure.' }
        if ($ProviderAction -eq 'Configure' -and -not (TestAdministrator)) { throw 'Provider pack configuration requires Administrator privileges.' }
        $report=Invoke-WelaProviderPackCommand -Action $ProviderAction -Names $ProviderPack -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
        $report
        if ($report.ExitCode) { exit $report.ExitCode }
    }
    'channel-settings' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 channel-settings [-ChannelAction Audit|Plan|Configure] [-ChannelProfile microsoft-wef-appendix-c] [-WefQuerySet Baseline|Suspect|Both] [-GrantEventLogReaders] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Audits CAPI2/native WEF prerequisites. Configure enables/grows declared channels; only -GrantEventLogReaders permits adding the CAPI2 read ACE. Existing descriptor entries and retention are preserved. See docs/native-channel-access.md.'
            return
        }
        if ($Profile -or $Baseline) { throw 'channel-settings uses -ChannelProfile; -Profile and -Baseline select Security audit settings.' }
        if ($HtmlPath) { throw 'channel-settings exports JSON through -ResultsPath; -HtmlPath is not supported.' }
        if ($ChannelAction -eq 'Configure' -and -not (TestAdministrator)) { throw 'channel-settings Configure requires Administrator privileges.' }
        try {
            $report = Invoke-WelaNativeChannelCommand -Action $ChannelAction -Profile $ChannelProfile -QuerySet $WefQuerySet -GrantEventLogReaders:$GrantEventLogReaders -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] Native channel settings: $_" -ForegroundColor Red; exit 1 }
    }
    'wmi-auditing' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 wmi-auditing -WmiAction List|Audit|Plan|Configure [-WmiNamespace root\cimv2,root\subscription] [-WmiIncludeChildren] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Select exact local namespaces explicitly. Default action List is read-only. Configure appends ASD success audit ACEs; descendant inheritance requires an explicit switch. No access permissions, audit policy or forwarding changes.'
            return
        }
        if ($Profile -or $Baseline) { throw 'wmi-auditing uses its own namespace selections, not -Profile or -Baseline.' }
        try {
            $report = Invoke-WelaWmiAuditCommand -Action $WmiAction -Namespace $WmiNamespace -IncludeChildren:$WmiIncludeChildren -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] WMI namespace auditing: $_" -ForegroundColor Red; exit 1 }
    }
    'firewall-logging' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 firewall-logging [-FirewallAction Audit|Plan|Configure] [-FirewallPathMode Preserve|CisV4] [-FirewallMinimumSizeKiB 16384..32767] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Audits/plans Domain, Private and Public text logs. Configure enables allowed/dropped logging, preserves larger sizes and existing paths by default, and verifies effective policy. CisV4 explicitly selects domainfw.log/privatefw.log/publicfw.log. See docs/firewall-logging.md.'
            return
        }
        if ($Profile -or $Baseline) { throw 'firewall-logging uses its own options; -Profile and -Baseline apply to Security audit settings.' }
        try {
            $report = Invoke-WelaFirewallLoggingCommand -Action $FirewallAction -PathMode $FirewallPathMode -MinimumSizeKiB $FirewallMinimumSizeKiB -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] Firewall logging: $_" -ForegroundColor Red; exit 1 }
    }
    'smb-auditing' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 smb-auditing [-SmbAction Audit|Plan|Configure] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Checks six version-aware SMB audit policies against local ADMX and available runtime properties. Configure writes supported audit DWORDs only. See docs/smb-auditing.md.'
            return
        }
        if ($Profile -or $Baseline) { throw 'smb-auditing uses -SmbAction; -Profile and -Baseline apply to Security audit settings.' }
        try {
            $report = Invoke-WelaSmbAuditCommand -Action $SmbAction -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] SMB auditing: $_" -ForegroundColor Red; exit 1 }
    }
    'powershell-transcription' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 powershell-transcription [-TranscriptionAction Audit|Plan|Configure] [-TranscriptDirectory absolute-existing-directory] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Explicit CIS v4.0.0 Level 2 option for Windows PowerShell 5.1. Plan/Configure require an operator-reviewed output directory; ACLs, quotas and retention are not changed. Text transcripts provide no automatic Sigma EVTX credit. See docs/powershell-transcription.md.'
            return
        }
        if ($Profile -or $Baseline) { throw 'powershell-transcription is an explicit Level 2 option; -Profile and -Baseline select separate Security audit policies.' }
        try {
            $report = Invoke-WelaTranscriptCommand -Action $TranscriptionAction -OutputDirectory $TranscriptDirectory -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] PowerShell transcription: $_" -ForegroundColor Red; exit 1 }
    }
    'ad-object-sacl' {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 ad-object-sacl -AdServer exact-dc-fqdn [-AdSaclAction Audit|Plan|Configure] -AdSaclProfile MdiDomain|MdiConfiguration|PkiObjects [-AdObjectDn exact-dn] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            Write-Host 'Rollback uses -AdSaclAction Rollback -AdReceiptPath trusted-receipt.json without profile selection. See docs/ad-object-sacl.md for prerequisites, scope, recovery and required DC lab evidence.'
            return
        }
        if ($Profile -or $Baseline) { throw 'ad-object-sacl uses explicit -AdSaclProfile; Security audit policy is a separate prerequisite.' }
        try {
            $report = Invoke-WelaAdSaclCommand -Action $AdSaclAction -Server $AdServer -Profiles $AdSaclProfile -ObjectDn $AdObjectDn `
                -ReceiptPath $AdReceiptPath -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode) { exit $report.ExitCode }
        } catch { Write-Host "[Failed] AD object SACL: $_" -ForegroundColor Red; exit 1 }
    }
    "applocker-readiness" {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 applocker-readiness [-AppLockerAction Audit|Plan|Import] [-AppLockerPolicyPath operator.xml] [-Auto] [-DryRun] [-BackupPath new-directory] [-ResultsPath file.json]'
            return
        }
        if ($AppLockerAction -eq 'Import' -and -not (TestAdministrator)) { throw 'AppLocker policy import requires Administrator privileges.' }
        $report = Invoke-WelaAppLockerCommand -Action $AppLockerAction -PolicyPath $AppLockerPolicyPath -Auto:$Auto -DryRun:$DryRun -BackupPath $BackupPath -ResultsPath $ResultsPath
        if ($report.PSObject.Properties['Assessment']) {
            $report.Assessment.Collections | Format-Table Type, EnforcementMode, RuleCount, PrerequisiteState, GenerationReadiness -AutoSize
            Write-Host 'GP observations only; CSP policies and actual event generation remain unverified.' -ForegroundColor Yellow
            if ($report.ImportBlocker) { Write-Host "Import blocked: $($report.ImportBlocker)" -ForegroundColor Yellow }
        } else { $report.Results | Format-Table Id, Status, Diagnostic -AutoSize }
        if ($report.ExitCode -ne 0) { throw 'AppLocker assessment/import failed; see structured results.' }
    }
    "profiles" {
        $data = if ($ProfileFile) { Import-WelaCustomAuditProfiles -Path $ProfileFile } else { Import-WelaAuditProfiles }
        if ($ProfileFile) { $data.customSource | Format-List }
        $data.profiles | Select-Object id, version, scope, appliesTo | Format-List
    }
    "plan" { Invoke-WelaProfileCommand -Command 'plan' }
    "audit" { Invoke-WelaProfileCommand -Command 'audit' }
    "audit-settings"  {
        if ($Help -or [string]::IsNullOrEmpty($Baseline)){
            Write-Host "Audit current Windows Event Log settings and compare with baseline"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 audit-settings -Baseline <YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server> [-OutType <std|gui|table>] [-ResultsPath <json-file>] [-HtmlPath <html-file>]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Baseline    Specify the baseline (YamatoSecurity, ASD, Microsoft_Client, Microsoft_Server)"
            Write-Host "  -OutType     Output type: std (default) or gui or table"
            Write-Host "  -ResultsPath Save JSON assessment including native channel/provider evidence"
            Write-Host "  -HtmlPath    Save a self-contained HTML assessment with the same evidence"
            Write-Host ""
            return
        }
        $validGuides = GetBaselineNames
        if (-not ($validGuides -contains $Baseline)) {
            Write-Host "Invalid Guide specified. Valid options are: $($validGuides -join ', ')."
            break
        }
        AuditLogSetting -outType $OutType -Baseline $Baseline -debug:$Debug -ResultsPath $ResultsPath -HtmlPath $HtmlPath
    }
    "eventlog-profiles" {
        (Import-WelaEventLogProfiles).profiles | Select-Object id, kind, scope, note | Format-List
    }
    "audit-filesize" {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 audit-filesize [-LogProfile <id>]'
            Write-Host 'Read live sizes and retention modes; list IDs with eventlog-profiles. Default: wela-source-2.2.0.'
            return
        }
        if ($Baseline -and $Baseline -ne 'YamatoSecurity') { throw 'Use -LogProfile for source-specific event-log sizes; -Baseline does not select a log profile.' }
        if (-not $LogProfile) { $LogProfile = 'wela-source-2.2.0' }
        AuditFileSize -LogProfile $LogProfile
    }
    "configure-eventlogs" {
        if ($Help) {
            Write-Host 'Usage: ./WELA.ps1 configure-eventlogs [-LogProfile <id>] [-ApplyLogMode] [-ResizeLogs] [-Auto] [-DryRun] [-BackupPath <new-directory>] [-ResultsPath <json-file>]'
            Write-Host 'Default: wela-source-2.2.0, minimum sizes, modes unchanged. -ResizeLogs explicitly permits shrinking; -ApplyLogMode explicitly applies circular source or collector archive behavior.'
            Write-Host 'This command changes only event-log size/mode. It does not enable channels, configure forwarding or establish retention days.'
            return
        }
        if ($Baseline) { throw 'configure-eventlogs uses -LogProfile, not -Baseline.' }
        if (-not (TestWindows)) { throw 'configure-eventlogs requires Windows.' }
        if (-not (TestAdministrator)) { throw 'configure-eventlogs requires Administrator privileges.' }
        if (-not $LogProfile) { $LogProfile = 'wela-source-2.2.0' }
        try {
            $report = Invoke-WelaEventLogConfiguration -Profile $LogProfile -Auto:$Auto -DryRun:$DryRun -ResizeLogs:$ResizeLogs -ApplyLogMode:$ApplyLogMode -BackupPath $BackupPath -ResultsPath $ResultsPath
            $report
            if ($report.ExitCode -ne 0) { exit $report.ExitCode }
        } catch {
            Write-Host "[Failed] Event-log configuration aborted: $_" -ForegroundColor Red
            exit 1
        }
    }

    "configure" {
        if ($Help){
            Write-Host "Configure Windows Event Log audit settings based on the YamatoSecurity baseline"
            Write-Host ""
            Write-Host "Usage: ./WELA.ps1 configure [-Profile <id>] [-Auto] [-DryRun] [-BackupPath <new-directory>] [-ResultsPath <json-file>] [-OutgoingNtlmMode <PreserveOrAudit|Audit|Deny>]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  -Profile     Configure advanced audit policy and precedence from a versioned profile; list IDs with profiles"
            Write-Host "  -ProfileFile Select a validated custom JSON profile file; requires an explicit -Profile"
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
