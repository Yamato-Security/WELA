# Get-WinEvent -LogName Security | where {($_.ID -eq "4704" -and ($_.message -match ".*SeEnableDelegationPrivilege.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_active_directory_user_control";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_active_directory_user_control";
            $detectedMessage = "Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.";
            $result = $event |  where { ($_.ID -eq "4704" -and ($_.message -match ".*SeEnableDelegationPrivilege.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
