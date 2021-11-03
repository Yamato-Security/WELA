# Get-WinEvent -LogName Security | where {($_.ID -eq "4704" -and ($_.message -match "SeEnableDelegationPrivilege")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_active_directory_user_control";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_active_directory_user_control";
            $detectedMessage = "Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.";
            $result = $event |  where { ($_.ID -eq "4704" -and ($_.message -match "SeEnableDelegationPrivilege")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
