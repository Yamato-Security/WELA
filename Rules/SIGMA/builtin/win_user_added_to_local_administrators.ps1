# Get-WinEvent -LogName Security | where {(($_.ID -eq "4732" -and ($_.message -match "TargetUserName.*Administr" -or $_.message -match "TargetSid.*S-1-5-32-544")) -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_user_added_to_local_administrators";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_user_added_to_local_administrators";
            $detectedMessage = "This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation";
            $result = $event |  where { (($_.ID -eq "4732" -and ($_.message -match "TargetUserName.*Administr" -or $_.message -match "TargetSid.*S-1-5-32-544")) -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
