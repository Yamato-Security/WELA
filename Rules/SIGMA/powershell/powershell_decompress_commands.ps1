﻿# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Expand-Archive.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Expand-Archive.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_decompress_commands";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_decompress_commands";
            $detectedMessage = "A General detection for specific decompress commands in PowerShell logs. This could be an adversary decompressing files.";
            $result = $event |  where { ((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Expand-Archive.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Expand-Archive.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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