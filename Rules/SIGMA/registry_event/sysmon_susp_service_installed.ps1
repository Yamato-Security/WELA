# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath" -or $_.message -match "HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath") -and  -not (($_.message -match "Image.*.*\procexp64.exe" -or $_.message -match "Image.*.*\procexp.exe" -or $_.message -match "Image.*.*\procmon64.exe" -or $_.message -match "Image.*.*\procmon.exe"))) -and  -not (($_.message -match "Details.*.*\WINDOWS\system32\Drivers\PROCEXP152.SYS.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_service_installed";
    $detectedMessage = "Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders. Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath" -or $_.message -match "HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath") -and -not (($_.message -match "Image.*.*\procexp64.exe" -or $_.message -match "Image.*.*\procexp.exe" -or $_.message -match "Image.*.*\procmon64.exe" -or $_.message -match "Image.*.*\procmon.exe"))) -and -not (($_.message -match "Details.*.*\WINDOWS\system32\Drivers\PROCEXP152.SYS.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
(.*)Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
