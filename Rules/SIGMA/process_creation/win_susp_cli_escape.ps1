# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*h^t^t^p.*" -or $_.message -match "CommandLine.*.*h"t"t"p.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_cli_escape";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_cli_escape";
                    $detectedMessage = "Detects suspicious process that use escape characters";
                $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*h^t^t^p.*" -or $_.message -match "CommandLine.*.*h""t""t""p.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
