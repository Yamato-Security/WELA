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
