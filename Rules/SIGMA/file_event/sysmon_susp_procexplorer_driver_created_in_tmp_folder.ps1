# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\AppData\Local\Temp\.*" -and $_.message -match "TargetFilename.*.*PROCEXP152.sys") -and  -not (($_.message -match "Image.*.*\procexp64.exe.*" -or $_.message -match "Image.*.*\procexp.exe.*" -or $_.message -match "Image.*.*\procmon64.exe.*" -or $_.message -match "Image.*.*\procmon.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_procexplorer_driver_created_in_tmp_folder";
    $detectedMessage = "Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\AppData\Local\Temp\.*" -and $_.message -match "TargetFilename.*.*PROCEXP152.sys") -and -not (($_.message -match "Image.*.*\procexp64.exe.*" -or $_.message -match "Image.*.*\procexp.exe.*" -or $_.message -match "Image.*.*\procmon64.exe.*" -or $_.message -match "Image.*.*\procmon.exe.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
