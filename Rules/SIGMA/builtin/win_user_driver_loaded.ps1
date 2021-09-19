# Get-WinEvent -LogName Security | where {(($_.ID -eq "4673" -and $_.message -match "PrivilegeList.*SeLoadDriverPrivilege" -and $_.message -match "Service.*-") -and  -not (($_.message -match "ProcessName.*.*\Windows\System32\Dism.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\rundll32.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\fltMC.exe" -or $_.message -match "ProcessName.*.*\Windows\HelpPane.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\mmc.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\svchost.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\wimserv.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\procmon64.exe" -or $_.message -match "ProcessName.*.*\procmon.exe" -or $_.message -match "ProcessName.*.*\Google\Chrome\Application\chrome.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_user_driver_loaded";
    $detectedMessage = "Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "4673" -and $_.message -match "PrivilegeList.*SeLoadDriverPrivilege" -and $_.message -match "Service.*-") -and -not (($_.message -match "ProcessName.*.*\Windows\System32\Dism.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\rundll32.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\fltMC.exe" -or $_.message -match "ProcessName.*.*\Windows\HelpPane.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\mmc.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\svchost.exe" -or $_.message -match "ProcessName.*.*\Windows\System32\wimserv.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\procmon64.exe" -or $_.message -match "ProcessName.*.*\procmon.exe" -or $_.message -match "ProcessName.*.*\Google\Chrome\Application\chrome.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
