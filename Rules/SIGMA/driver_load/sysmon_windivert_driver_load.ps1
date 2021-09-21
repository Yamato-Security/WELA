# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and ($_.message -match "ImageLoaded.*.*\WinDivert.sys.*" -or $_.message -match "ImageLoaded.*.*\WinDivert64.sys.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_windivert_driver_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_windivert_driver_load";
            $detectedMessage = "Detects the load of the Windiver driver, a powerful user-mode capture/sniffing/modification/blocking/re-injection package for Windows";
            $result = $event |  where { ($_.ID -eq "6" -and ($_.message -match "ImageLoaded.*.*\\WinDivert.sys.*" -or $_.message -match "ImageLoaded.*.*\\WinDivert64.sys.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
