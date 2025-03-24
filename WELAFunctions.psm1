<#
.SYNOPSIS
    Checks if a registry value matches the expected value.
.DESCRIPTION
    This function retrieves a registry value and compares it to the expected value.
.PARAMETER registryPath
    The path to the registry key.
.PARAMETER valueName
    The name of the registry value.
.PARAMETER expectedValue
    The expected value to compare against.
.RETURNS
    [bool] $true if the registry value matches the expected value, otherwise $false.
#>
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


<#
.SYNOPSIS
    Sets the applicable rules based on the provided audit policy text and JSON rule path.

.DESCRIPTION
    This function reads the audit policy text file and extracts GUIDs. It then checks the registry values for PowerShell logging settings and updates the applicability of rules in the JSON file based on these settings and the extracted GUIDs.

.PARAMETER autidpolTxt
    The path to the audit policy text file.

.PARAMETER jsonRulePath
    The path to the JSON rule file.

.RETURNS
    The updated JSON content with the applicability of rules set.

.EXAMPLE
    Set-Applicable -autidpolTxt "C:\path\to\auditpol.txt" -jsonRulePath "C:\path\to\rules.json"
#>
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
            if ($rule.event_ids -contains "400" -or $rule.event_ids -contains "600" -or $rule.event_ids.Count -eq 0) {
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


<#
.SYNOPSIS
    Groups the rules by their level and counts the number of rules in each level.
.PARAMETER rules
    The collection of rules to be grouped and counted.
.RETURNS
    A hashtable with the count of rules for each level.
#>
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

<#
.SYNOPSIS
    Calculates the usable rate of rules based on their counts and total counts.
.PARAMETER counts
    The counts of usable rules for each level.
.PARAMETER totalCounts
    The total counts of rules for each level.
.RETURNS
    A collection of objects representing the usable rate for each level.
#>
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


<#
.SYNOPSIS
    Calculates the total usable rate of rules.
.PARAMETER usableRate
    The collection of objects representing the usable rate for each level.
.RETURNS
    A string representing the total usable rate as a percentage.
#>
function CalculateTotalUsableRate {
    param ($usableRate)
    $totalUsable = ($usableRate | Measure-Object -Property UsableCount -Sum).Sum
    $totalRulesCount = ($usableRate | Measure-Object -Property TotalCount -Sum).Sum
    return "{0:N2}%" -f ($totalUsable / $totalRulesCount * 100)
}


<#
.SYNOPSIS
    Displays the counts of rules by their level with color-coded output.
.PARAMETER usableRate
    The collection of objects representing the usable rate for each level.
.PARAMETER msg
    The message to display before the counts.
.PARAMETER colorMsg
    The message to display with color coding.
#>
function ShowRulesCountsByLevel {
    param ($usableRate, $msg, $colorMsg)
    Write-Host -NoNewline $msg
    $color = if ($colorMsg -match "Disabled") { "Red" } elseif ($colorMsg -match "Partially") { "Yellow" } else { "Green" }
    Write-Host "$colorMsg" -ForegroundColor $color
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
        $level = if ($_.Level -match "informational") { "info" } else { $_.Level }
        Write-Host -NoNewline "$($level): $($_.UsableCount)/$($_.TotalCount) ($($_.Percentage)%)" -ForegroundColor $color
        if ($i -lt $usableRate.Count - 1)
        {
            Write-Host -NoNewline ", "
        }
        $i++
    }
    Write-Output ""
    Write-Output ""
}

<#
.SYNOPSIS
    Checks if the current user is an administrator.
.DESCRIPTION
    This function determines if the current user has administrative privileges.
.RETURNS
    [bool] $true if the current user is an administrator, otherwise $false.
#>
function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole($adminRole)
}

if (-not (Test-IsAdministrator)) {
    Write-Output "This script must be run as an Administrator."
    exit
}

