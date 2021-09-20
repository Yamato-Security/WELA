# Get-WinEvent -LogName Security | where {($_.ID -eq "4699") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_scheduled_task_deletion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_scheduled_task_deletion";
            $detectedMessage = "Detects scheduled task deletion events. Scheduled tasks are likely to be deleted if not used for persistence. Malicious Software often creates tasks directly under the root node e.g. TASKNAME";
            $result = $event |  where { ($_.ID -eq "4699") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
