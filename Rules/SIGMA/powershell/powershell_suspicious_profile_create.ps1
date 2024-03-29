﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\profile.ps1" -and ($_.message -match "TargetFilename.*.*\My Documents\PowerShell\" -or $_.message -match "TargetFilename.*.*C:\Windows\System32\WindowsPowerShell\v1.0\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_profile_create";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_profile_create";
            $detectedMessage = "Detects a change in profile.ps1 of the Powershell profile";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\profile.ps1" -and ($_.message -match "TargetFilename.*.*\\My Documents\\PowerShell\\" -or $_.message -match "TargetFilename.*.*C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
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
