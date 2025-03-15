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
    $rules | Group-Object -Property level | ForEach-Object {
        [PSCustomObject]@{
            Level = $_.Name
            Count = $_.Count
        }
    }
}

function CalculateUsableRate {
    param ($counts, $totalCounts)
    $counts | ForEach-Object {
        $total = ($totalCounts | Where-Object Level -match $PSItem.Level | Select-Object -ExpandProperty Count)[0]
        [PSCustomObject]@{
            Level = $PSItem.Level
            UsableCount = $PSItem.Count
            TotalCount = $total
            Percentage = "{0:N2}" -f ($PSItem.Count / $total * 100)
        }
    }
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
    $usableRate | Sort-Object { $levelColorMap.Keys.IndexOf($_.Level) } | ForEach-Object {
        $color = $levelColorMap[$_.Level]
        Write-Host "$($_.Level) rules: $($_.UsableCount) / $($_.TotalCount) ($($_.Percentage)%)" -ForegroundColor $color
    }
    Write-Output ""
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

$usableSecRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "sec" }
$usablePwsRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" }
$unusableRules  = $rules | Where-Object { $_.applicable -eq $false }
$allSecRules    = $rules | Where-Object { $_.channel -eq "sec" }

# Step 4: Count the number of usable and unusable rules for each level
$totalCounts     = Get-RuleCounts -rules $rules
$totalSecCounts  = Get-RuleCounts -rules $allSecRules
$usableSecCounts = Get-RuleCounts -rules $usableSecRules
$usablePwsCounts = Get-RuleCounts -rules $usablePwsRules

# Step 5: Calculate the usable rate for each level
$usableSecRate = CalculateUsableRate -counts $usableSecCounts -totalCounts $totalSecCounts
$usablePwsRate = CalculateUsableRate -counts $usablePwsCounts -totalCounts $usablePwsCounts

# Step 6: Show the number of usable and unusable rules for each level
ShowRulesCountsByLevel -usableRate $usableSecRate -msg "Security event log detection rules:"
ShowRulesCountsByLevel -usableRate $usablePwsRate -msg "PowerShell event log detection rules:"

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
