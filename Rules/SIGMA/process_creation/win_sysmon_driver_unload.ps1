﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\fltmc.exe" -and $_.message -match "CommandLine.*.*unload.*" -and $_.message -match "CommandLine.*.*sys.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sysmon_driver_unload";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_sysmon_driver_unload";
            $detectedMessage = "Detect possible Sysmon driver unload";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\fltmc.exe" -and $_.message -match "CommandLine.*.*unload.*" -and $_.message -match "CommandLine.*.*sys.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}