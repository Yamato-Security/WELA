﻿# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "OriginalFileName.*sdelete.exe" -and  -not (($_.message -match "CommandLine.*.* -h.*" -or $_.message -match "CommandLine.*.* -c.*" -or $_.message -match "CommandLine.*.* -z.*" -or $_.message -match "CommandLine.*.* /?.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_SDelete";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "process_creation_SDelete";
                    $detectedMessage = "Use of SDelete to erase a file not the free space";
                $result = $event  | where { (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*sdelete.exe" -and -not (($_.message -match "CommandLine.*.* -h.*" -or $_.message -match "CommandLine.*.* -c.*" -or $_.message -match "CommandLine.*.* -z.*" -or $_.message -match "CommandLine.*.* /?.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

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