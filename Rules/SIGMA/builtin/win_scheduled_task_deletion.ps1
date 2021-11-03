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
