Import-Module -Name ./WELAFunctions.psm1
Import-Module -Name ./WELAVerboseSecAudit.psm1
$logo = @"
┏┓┏┓┏┳━━━┳┓  ┏━━━┓
┃┃┃┃┃┃┏━━┫┃  ┃┏━┓┃
┃┃┃┃┃┃┗━━┫┃  ┃┃ ┃┃
┃┗┛┗┛┃┏━━┫┃ ┏┫┗━┛┃
┗┓┏┓┏┫┗━━┫┗━┛┃┏━┓┃
 ┗┛┗┛┗━━━┻━━━┻┛ ┗┛
  by Yamato Security

"@

# Set the console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Step 1: Run the auditpol command using cmd.exe and redirect its output to a file
$autidpolTxt = "auditpol_output.txt"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" -NoNewWindow -Wait -RedirectStandardOutput $autidpolTxt

Write-Host $logo -ForegroundColor Green

# Step 3: Set the applicable flag for each rule
$rules = Set-Applicable -autidpolTxt $autidpolTxt -jsonRulePath "./config/security_rules.json"

$allSecRules       = $rules | Where-Object { $_.channel -eq "sec" }
$allPwsRules       = $rules | Where-Object { $_.channel -eq "pwsh" }
$allPwsClaRules    = $rules | Where-Object { $_.channel -eq "pwsh" -and ($_.event_ids -contains "400" -or $_.event_ids -contains "600" -or $_.event_ids.Count -eq 0)  }
$allPwsModRules    = $rules | Where-Object { $_.channel -eq "pwsh" -and $_.event_ids -contains "4103" }
$allPwsScrRules    = $rules | Where-Object { $_.channel -eq "pwsh" -and $_.event_ids -contains "4104" }
$allOtherRules     = $rules | Where-Object { $_.channel -eq "other" }

$usableSecRules    = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "sec" }
$usablePwsRules    = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" }
$usablePwsClaRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and ($_.event_ids -contains "400" -or $_.event_ids -contains "600" -or $_.event_ids.Count -eq 0) }
$usablePwsModRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and $_.event_ids -contains "4103" }
$usablePwsScrRules = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "pwsh" -and $_.event_ids -contains "4104" }
$usableOtherRules  = $rules | Where-Object { $_.applicable -eq $true -and $_.channel -eq "other" }


# Step 4: Count the number of usable and unusable rules for each level
$totalCounts        = Get-RuleCounts -rules $rules
$totalSecCounts     = Get-RuleCounts -rules $allSecRules
$totalPwsCounts     = Get-RuleCounts -rules $allPwsRules
$totalPwsClaCounts  = Get-RuleCounts -rules $allPwsClaRules
$totalPwsModCounts  = Get-RuleCounts -rules $allPwsModRules
$totalPwsScrCounts  = Get-RuleCounts -rules $allPwsScrRules
$totalOtherCounts   = Get-RuleCounts -rules $allOtherRules

$usableSecCounts    = Get-RuleCounts -rules $usableSecRules
$usablePwsCounts    = Get-RuleCounts -rules $usablePwsRules
$usablePwsClaCounts = Get-RuleCounts -rules $usablePwsClaRules
$usablePwsModCounts = Get-RuleCounts -rules $usablePwsModRules
$usablePwsScrCounts = Get-RuleCounts -rules $usablePwsScrRules
$usableOtherCounts  = Get-RuleCounts -rules $usableOtherRules

# Step 5: Calculate the usable rate for each level
$usableSecRate    = CalculateUsableRate -counts $usableSecCounts -totalCounts $totalSecCounts
$usablePwsRate    = CalculateUsableRate -counts $usablePwsCounts -totalCounts $totalPwsCounts
$usablePwsClaRate = CalculateUsableRate -counts $usablePwsClaCounts -totalCounts $totalPwsClaCounts
$usablePwsModRate = CalculateUsableRate -counts $usablePwsModCounts -totalCounts $totalPwsModCounts
$usablePwsScrRate = CalculateUsableRate -counts $usablePwsScrCounts -totalCounts $totalPwsScrCounts
$usableOtherRate  = CalculateUsableRate -counts $usableOtherCounts -totalCounts $totalOtherCounts

# Step 6: Show the number of usable and unusable rules for each level
$pwsModEnabled = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -valueName "EnableModuleLogging" -expectedValue 1
$pwsScrEnabled = CheckRegistryValue -registryPath "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -valueName "EnableScriptBlockLogging" -expectedValue 1
$pwsModStatus = if ($pwsModEnabled) { "Enabled" } else { "Disabled" }
$pwsSrcStatus = if ($pwsScrEnabled) { "Enabled" } else { "Disabled" }

# Step 7: Calculate the total usable rate
$totalUsableSecRate    = CalculateTotalUsableRate -usableRate $usableSecRate
$totalUsablePwsClaRate = CalculateTotalUsableRate -usableRate $usablePwsClaRate
$totalUsablePwsModRate = CalculateTotalUsableRate -usableRate $usablePwsModRate
$totalUsablePwsScrRate = CalculateTotalUsableRate -usableRate $usablePwsScrRate
$totalUsableOtherRate  = CalculateTotalUsableRate -usableRate $usableOtherRate

ShowRulesCountsByLevel -usableRate $usablePwsClaRate -msg "PowerShell classic logging detection rules: " -colorMsg "$totalUsablePwsClaRate (Enabled)"
ShowRulesCountsByLevel -usableRate $usablePwsModRate -msg "PowerShell module logging detection rules: " -colorMsg "$totalUsablePwsModRate ($pwsModStatus)"
ShowRulesCountsByLevel -usableRate $usablePwsScrRate -msg "PowerShell script block logging detection rules: " -colorMsg "$totalUsablePwsScrRate ($pwsSrcStatus)"
ShowRulesCountsByLevel -usableRate $usableOtherRate -msg "OtherLog rules: " -colorMsg "$totalUsableOtherRate (Enabled)"
ShowRulesCountsByLevel -usableRate $usableSecRate -msg "Security event log detection rules: " -colorMsg "$totalUsableSecRate (Partially Enabled)"
ShowVerboseSecurity -rules $rules

Write-Output "Usable detection rules list saved to: UsableRules.csv"
Write-Output "Unusable detection rules list saved to: UnusableRules.csv"
Write-Output ""
$totalUsable = ($usableSecRate + $usablePwsRate | Measure-Object -Property UsableCount -Sum).Sum
$totalRulesCount = ($totalCounts | Measure-Object -Property Count -Sum).Sum
$utilizationPercentage = "{0:N2}" -f (($totalUsable / $totalRulesCount) * 100)
Write-Output "You can utilize $utilizationPercentage% of your detection rules."

# Step 8: Save the lists of usable and unusable rules to CSV files
$unusableRules  = $rules | Where-Object { $_.applicable -eq $false }
$usableSecRules | Select-Object title, level, id | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
$unusableRules  | Select-Object title, level, id | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation
