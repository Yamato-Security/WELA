# Get-WinEvent -LogName Security | where {($_.ID -eq "4674" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\Device\ConDrv") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lateral_movement_condrv";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lateral_movement_condrv";
            $detectedMessage = "This event was observed on the target host during lateral movement. The process name within the event contains the process spawned post compromise. Account Name within the event contains the compromised user account name. This event should to be correlated with 4624 and 4688 for further intrusion context.";
            $result = $event |  where { ($_.ID -eq "4674" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\\Device\\ConDrv") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
