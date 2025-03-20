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

function Set-Applicable {
    param (
        [string]$autidpolTxt,
        [string]$jsonRulePath
    )

    $extractedGuids = [System.Collections.Generic.HashSet[string]]::new()
    Get-Content -Path $autidpolTxt | Select-String -NotMatch "No Auditing" | ForEach-Object {
        if ($_ -match '{(.*?)}') {
            [void]$extractedGuids.Add($matches[1])
        }
    }

    $pwshModuleLogging = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
    $pwshScriptLogging = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1

    $jsonContent = Get-Content -Path $jsonRulePath -Raw | ConvertFrom-Json
    foreach ($rule in $jsonContent) {
        $rule | Add-Member -MemberType NoteProperty -Name "applicable" -Value $false
        if ($rule.channel -eq "pwsh") {
            if ($rule.event_ids -contains "400") {
                $rule.applicable = $true
            } elseif ($rule.event_ids -contains "4103") {
                $rule.applicable = $pwshModuleLogging
            } elseif ($rule.event_ids -contains "4104") {
                $rule.applicable = $pwshScriptLogging
            }
            continue
        }
        foreach ($guid in $rule.subcategory_guids) {
            if ($extractedGuids.Contains($guid)) {
                $rule.applicable = $true
                break
            }
        }
    }
    return $jsonContent
}

function Get-RuleCounts {
    param ($rules)
    $levels = @("critical", "high", "medium", "low", "informational")
    $counts = @{}

    $rules | Group-Object -Property level | ForEach-Object {
        $counts[$_.Name] = $_.Count
    }

    foreach ($level in $levels) {
        if (-not $counts.ContainsKey($level)) {
            $counts[$level] = 0
        }
    }

    return $counts.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Level = $_.Key
            Count = $_.Value
        }
    }
}

function CalculateUsableRate {
    param ($counts, $totalCounts)
    $result = @()
    $totalCounts | ForEach-Object {
        $level = $_.Level
        $total = $_.Count
        $usableCount = ($counts | Where-Object Level -eq $level | Select-Object -ExpandProperty Count -First 1)
        if ($null -eq $usableCount) { $usableCount = 0 }
        $percentage = if ($total -ne 0) { "{0:N2}" -f ($usableCount / $total * 100) } else { "0.00" }
        $result += [PSCustomObject]@{
            Level = $level
            UsableCount = $usableCount
            TotalCount = $total
            Percentage = $percentage
        }
    }
    return $result
}

function ShowRulesCountsByLevel {
    param ($usableRate, $msg)
    Write-Output $msg
    $levelColorMap = [ordered]@{
        "critical" = "Red"
        "high" = "DarkYellow"
        "medium" = "Yellow"
        "low" = "Green"
        "informational" = "White"  # Assuming a default color for informational
    }
    $i = 0
    Write-Host -NoNewline " - "
    $usableRate | Sort-Object { $levelColorMap.Keys.IndexOf($_.Level) } | ForEach-Object {
        $color = $levelColorMap[$_.Level]
        Write-Host -NoNewline "$($_.Level) rules: $($_.UsableCount) / $($_.TotalCount) ($($_.Percentage)%)" -ForegroundColor $color
        if ($i -lt $usableRate.Count - 1)
        {
            Write-Host -NoNewline ", "
        }
        $i++
    }
    Write-Output ""
    Write-Output ""
}

function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole($adminRole)
}

if (-not (Test-IsAdministrator)) {
    Write-Output "This script must be run as an Administrator."
    exit
}

# Set the console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Step 1: Run the auditpol command using cmd.exe and redirect its output to a file
$autidpolTxt = "auditpol_output.txt"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $autidpolTxt

$logo = @"
┏┓┏┓┏┳━━━┳┓  ┏━━━┓
┃┃┃┃┃┃┏━━┫┃  ┃┏━┓┃
┃┃┃┃┃┃┗━━┫┃  ┃┃ ┃┃
┃┗┛┗┛┃┏━━┫┃ ┏┫┗━┛┃
┗┓┏┓┏┫┗━━┫┗━┛┃┏━┓┃
 ┗┛┗┛┗━━━┻━━━┻┛ ┗┛
  by Yamato Security

"@
Write-Host $logo -ForegroundColor Green

# Step 3: Set the applicable flag for each rule
$rules = Set-Applicable -autidpolTxt $autidpolTxt -jsonRulePath "./config/security_rules.json"


$allSecRules    = $rules | Where-Object { $_.channel -eq "sec" }
$allPwsClaRules = $rules | Where-Object { $_.channel -eq "pwsh" -and $_.event_ids -contains "400" }
$allPwsModRules    = $rules | Where-Object { $_.channel -eq "pwsh" -and $_.event_ids -contains "4103" }
$allPwsScrRules    = $rules | Where-Object { $_.channel -eq "pwsh" -and $_.event_ids -contains "4104" }

$usableSecRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "sec" }
$usablePwsRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" }
$usablePwsClaRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and ($_.event_ids -contains "400" -or $_.event_ids -contains "600" -or $_.event_ids.Count -eq 0) }
$usablePwsModRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and $_.event_ids -contains "4103" }
$usablePwsScrRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and $_.event_ids -contains "4104" }

$unusableRules  = $rules | Where-Object { $_.applicable -eq $false }

# Step 4: Count the number of usable and unusable rules for each level
$totalCounts     = Get-RuleCounts -rules $rules
$totalSecCounts  = Get-RuleCounts -rules $allSecRules
$totalPwsCounts  = Get-RuleCounts -rules $allPwsClaRules
$totalPwsClaCounts  = Get-RuleCounts -rules $allPwsClaRules
$totalPwsModCounts  = Get-RuleCounts -rules $allPwsModRules
$totalPwsScrCounts  = Get-RuleCounts -rules $allPwsScrRules

$usableSecCounts = Get-RuleCounts -rules $usableSecRules
$usablePwsCounts = Get-RuleCounts -rules $usablePwsRules
$usablePwsClaCounts = Get-RuleCounts -rules $usablePwsClaRules
$usablePwsModCounts = Get-RuleCounts -rules $usablePwsModRules
$usablePwsScrCounts = Get-RuleCounts -rules $usablePwsScrRules

# Step 5: Calculate the usable rate for each level
$usableSecRate = CalculateUsableRate -counts $usableSecCounts -totalCounts $totalSecCounts
$usablePwsRate = CalculateUsableRate -counts $usablePwsCounts -totalCounts $totalPwsCounts
$usablePwsClaRate = CalculateUsableRate -counts $usablePwsClaCounts -totalCounts $totalPwsClaCounts
$usablePwsModRate = CalculateUsableRate -counts $usablePwsModCounts -totalCounts $totalPwsModCounts
$usablePwsScrRate = CalculateUsableRate -counts $usablePwsScrCounts -totalCounts $totalPwsScrCounts

# Step 6: Show the number of usable and unusable rules for each level
$pwsModEnabled = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
$pwsScrEnabled = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
$pwsModStatus = if ($pwsModEnabled) { "Enabled" } else { "Disabled" }
$pwsSrcStatus = if ($pwsScrEnabled) { "Enabled" } else { "Disabled" }

# 123 / 1860 (6%)


ShowRulesCountsByLevel -usableRate $usableSecRate -msg "Security event log detection rules: (Partially Enabled)"
ShowRulesCountsByLevel -usableRate $usablePwsClaRate -msg "PowerShell classic logging detection rules: (Enabled)"
ShowRulesCountsByLevel -usableRate $usablePwsModRate -msg "PowerShell module logging detection rules: ($pwsModStatus)"
ShowRulesCountsByLevel -usableRate $usablePwsScrRate -msg "PowerShell script block logging detection rules: ($pwsSrcStatus)"

Write-Output "Usable detection rules list saved to: UsableRules.csv"
Write-Output "Unusable detection rules list saved to: UnusableRules.csv"
Write-Output ""
$totalUsable = ($usableSecRate + $usablePwsRate | Measure-Object -Property UsableCount -Sum).Sum
$totalRulesCount = ($totalCounts | Measure-Object -Property Count -Sum).Sum
$utilizationPercentage = "{0:N2}" -f (($totalUsable / $totalRulesCount) * 100)
Write-Output "You can utilize $utilizationPercentage% of your detection rules."

# Step 7: Save the lists of usable and unusable rules to CSV files
$usableSecRules | Select-Object title, level, id | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
$unusableRules  | Select-Object title, level, id | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation
