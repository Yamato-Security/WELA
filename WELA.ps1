function Get-ApplicableRules {
    param (
        [string]$outputFilePath,
        [string]$jsonFilePath
    )

    $extractedGuids = [System.Collections.Generic.HashSet[string]]::new()
    Get-Content -Path $outputFilePath | Select-String -NotMatch "No Auditing" | ForEach-Object {
        if ($_ -match '{(.*?)}') {
            [void]$extractedGuids.Add($matches[1])
        }
    }

    $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
    foreach ($rule in $jsonContent) {
        $rule | Add-Member -MemberType NoteProperty -Name "applicable" -Value $false
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

function CalculatePercentages {
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

function DisplayRulePercentages {
    param ($usablePercentages, $msg)
    Write-Output $msg
    $customOrder = @("critical", "high", "medium", "low", "informational")
    $usablePercentages = $usablePercentages | Sort-Object { $customOrder.IndexOf($_.Level) }
    $usablePercentages | ForEach-Object {
        Write-Output "$($_.Level) rules: $($_.UsableCount) / $($_.TotalCount) ($($_.Percentage)%)"
    }
    Write-Output ""
}

# Set the console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Step 1: Run the auditpol command using cmd.exe and redirect its output to a file
$outputFilePath = "auditpol_output.txt"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $outputFilePath

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

# Step 3: Get the applicable rules
$rules = Get-ApplicableRules -outputFilePath $outputFilePath -jsonFilePath "./config/security_rules.json"

# Step 4: Count the number of usable and unusable rules for each level
$usableSecRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "sec" }
$usablePwshRules = $rules | Where-Object { $_.channel -eq "pwsh" }
$unusableRules = $rules | Where-Object { $_.applicable -eq $false -and $_.channel -eq "sec" }

$totalCounts = Get-RuleCounts -rules $rules
$usableSecCounts = Get-RuleCounts -rules $usableSecRules
$usablePwsCounts = Get-RuleCounts -rules $usablePwshRules

# Step 5: Calculate the percentages
$usableSecPercentages = CalculatePercentages -counts $usableSecCounts -totalCounts $totalCounts
$usablePwsPercentages = CalculatePercentages -counts $usablePwsCounts -totalCounts $usablePwsCounts

# Step 6: Generate the required outputtotal
DisplayRulePercentages -usablePercentages $usableSecPercentages -msg "Security event log detection rules:"
DisplayRulePercentages -usablePercentages $usablePwsPercentages -msg "PowerShell event log detection rules:"

Write-Output "Usable detection rules list saved to: UsableRules.csv"
Write-Output "Unusable detection rules list saved to: UnusableRules.csv"
Write-Output ""
$totalUsable = ($usableSecPercentages + $usablePwsPercentages| Measure-Object -Property UsableCount -Sum).Sum
$totalRulesCount = ($totalCounts | Measure-Object -Property Count -Sum).Sum
$utilizationPercentage = "{0:N2}" -f (($totalUsable / $totalRulesCount) * 100)
Write-Output "You can utilize $utilizationPercentage% of your detection rules."

# Step 7: Save the lists of usable and unusable rules to CSV files
$usableSecRules | Select-Object title, level, id | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
$unusableRules | Select-Object title, level, id | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation
