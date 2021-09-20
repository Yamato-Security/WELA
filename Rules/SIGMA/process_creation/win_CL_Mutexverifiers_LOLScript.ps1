# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*CL_Mutexverifiers.ps1.*" -and $_.message -match "CommandLine.*.*runAfterCancelProcess.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_CL_Mutexverifiers_LOLScript";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_CL_Mutexverifiers_LOLScript";
                    $detectedMessage = "Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module";
                $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*CL_Mutexverifiers.ps1.*" -and $_.message -match "CommandLine.*.*runAfterCancelProcess.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
