﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Imphash.*6834B1B94E49701D77CCB3C0895E1AFD" -and  -not ($_.message -match "Image.*.*\\dctask64.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_renamed_dctask64";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_renamed_dctask64";
            $detectedMessage = "Detects a renamed dctask64.exe used for process injection, command execution, process creation with a signed binary by ZOHO Corporation";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "Imphash.*6834B1B94E49701D77CCB3C0895E1AFD" -and -not ($_.message -match "Image.*.*\\dctask64.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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