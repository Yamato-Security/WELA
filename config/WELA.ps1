# Step 1: Run the auditpol command using cmd.exe and redirect its output to a file
$outputFilePath = "auditpol_output.txt"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c chcp 437 & auditpol /get /category:* /r > $outputFilePath" -NoNewWindow -Wait
$auditpolOutput = Get-Content -Path $outputFilePath
$filteredOutput = $auditpolOutput | Select-String -NotMatch "No Auditing"
Write-Host "DEBUG2"
$extractedStrings = [System.Collections.Generic.HashSet[string]]::new()
Write-Host "DEBUG"
$filteredOutput | ForEach-Object {
    if ($_ -match '{(.*?)}') {
        $extractedStrings.Add($matches[1])
    }
}

Write-Host "Extracted GUIDs:"

# Step 2: Read the rules from security_rules.json
$jsonFilePath = "./config/security_rules.json"
$jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json

foreach ($rule in $jsonContent) {
    $rule | Add-Member -MemberType NoteProperty -Name "applicable" -Value $false
    foreach ($guid in $rule.subcategory_guids) {
        if ($filteredOutput -contains $guid) {
            $rule.applicable = $true
            break
        }
    }
}
$rules = $jsonContent

# Step 4: Count the number of usable and unusable rules for each level
$usableRules = $rules | Where-Object { $_.applicable -eq $true }
$unusableRules = $rules | Where-Object { $_.applicable -eq $false }

$totalCounts = $rules | Group-Object -Property level | ForEach-Object {
    [PSCustomObject]@{
        Level = $_.Name
        Count = $_.Count
    }
}

$usableCounts = $usableRules | Group-Object -Property level | ForEach-Object {
    [PSCustomObject]@{
        Level = $_.Name
        Count = $_.Count
    }
}

$unusableCounts = $unusableRules | Group-Object -Property level | ForEach-Object {
    [PSCustomObject]@{
        Level = $_.Name
        Count = $_.Count
    }
}

# Step 5: Calculate the percentages
$usablePercentages = $usableCounts | ForEach-Object {
    $total = ($totalCounts | Where-Object Level -match $PSItem.Level | Select-Object -ExpandProperty Count)[0]
    [PSCustomObject]@{
        Level = $PSItem.Level
        UsableCount = $PSItem.Count
        TotalCount = $total
        Percentage = "{0:N2}" -f ($PSItem.Count / $total * 100)
    }
}

$unusablePercentages = $unusableCounts | ForEach-Object {
    $total = ($totalCounts | Where-Object Level -match $PSItem.Level | Select-Object -ExpandProperty Count)[0]
    [PSCustomObject]@{
        Level = $PSItem.Level
        UnusableCount = $PSItem.Count
        TotalCount = $total
        Percentage = "{0:N2}" -f ($PSItem.Count / $total * 100)
    }
}

# Step 6: Generate the required outputtotal
Write-Output "Checking event log audit settings. Please wait."
Write-Output ""
Write-Output "Detection rules that can be used on this system versus total possible rules:"
$usablePercentages | ForEach-Object {
    Write-Output "$($_.Level) rules: $($_.UsableCount) / $($_.TotalCount) ($($_.Percentage)%)"
}
Write-Output ""
Write-Output "Detection rules that cannot be used on this system:"
$unusablePercentages | ForEach-Object {
    Write-Output "$($_.Level) rules: $($_.UnusableCount) / $($_.TotalCount) ($($_.Percentage)%)"
}
Write-Output ""
Write-Output "Usable detection rules list saved to: UsableRules.csv"
Write-Output "Unusable detection rules list saved to: UnusableRules.csv"
Write-Output ""
$totalUsable = ($usablePercentages | Measure-Object -Property UsableCount -Sum).Sum
$totalRulesCount = ($totalCounts | Measure-Object -Property Count -Sum).Sum
$utilizationPercentage = ($totalUsable / $totalRulesCount) * 100
Write-Output "You can only utilize $utilizationPercentage% of your Security detection rules."

# Step 7: Save the lists of usable and unusable rules to CSV files
$usableRules | Export-Csv -Path "UsableRules.csv" -NoTypeInformation
$unusableRules | Export-Csv -Path "UnusableRules.csv" -NoTypeInformation