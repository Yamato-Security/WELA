﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*winzip.exe.*" -or $_.message -match "CommandLine.*.*winzip64.exe.*") -and ($_.message -match "CommandLine.*.*-s".*") -and ($_.message -match "CommandLine.*.* -min .*" -or $_.message -match "CommandLine.*.* -a .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_winzip";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_susp_winzip";
            $detectedMessage = "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*winzip.exe.*" -or $_.message -match "CommandLine.*.*winzip64.exe.*") -and ($_.message -match "CommandLine.*.*-s.*") -and ($_.message -match "CommandLine.*.* -min .*" -or $_.message -match "CommandLine.*.* -a .*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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