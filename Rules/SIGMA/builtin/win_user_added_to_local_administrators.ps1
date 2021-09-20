# Get-WinEvent -LogName Security | where {(($_.ID -eq "4732" -and ($_.message -match "TargetUserName.*Administr.*" -or $_.message -match "TargetSid.*S-1-5-32-544")) -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_user_added_to_local_administrators";
    $detectedMessage = "This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4732" -and ($_.message -match "TargetUserName.*Administr.*" -or $_.message -match "TargetSid.*S-1-5-32-544")) -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
