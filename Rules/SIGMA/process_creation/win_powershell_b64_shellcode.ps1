﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*AAAAYInlM.*" -and ($_.message -match "CommandLine.*.*OiCAAAAYInlM.*" -or $_.message -match "CommandLine.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_b64_shellcode";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_b64_shellcode";
            $detectedMessage = "Detects Base64 encoded Shellcode";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*AAAAYInlM.*" -and ($_.message -match "CommandLine.*.*OiCAAAAYInlM.*" -or $_.message -match "CommandLine.*.*OiJAAAAYInlM.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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