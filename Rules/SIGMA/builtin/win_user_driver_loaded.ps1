# Get-WinEvent -LogName Security | where {(($_.ID -eq "4673" -and $_.message -match "PrivilegeList.*SeLoadDriverPrivilege" -and $_.message -match "Service.*-") -and  -not (($_.message -match "ProcessName.*.*\Windows\System32\Dism.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\rundll32.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\fltMC.exe" -or $_.message -match "ProcessName.*.*\Windows\HelpPane.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\mmc.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\svchost.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\wimserv.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\procmon64.exe" -or $_.message -match "ProcessName.*.*\procmon.exe" -or $_.message -match "ProcessName.*.*\Google\Chrome\Application\chrome.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_user_driver_loaded";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4673" -and $_.message -match "PrivilegeList.*SeLoadDriverPrivilege" -and $_.message -match "Service.*-") -and -not (($_.message -match "ProcessName.*.*\Windows\System32\Dism.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\rundll32.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\fltMC.exe" -or $_.message -match "ProcessName.*.*\Windows\HelpPane.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\mmc.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\svchost.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\wimserv.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\procmon64.exe" -or $_.message -match "ProcessName.*.*\procmon.exe" -or $_.message -match "ProcessName.*.*\Google\Chrome\Application\chrome.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}