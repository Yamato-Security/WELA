# Get-WinEvent -LogName Security | where {(($_.ID -eq "5140" -and $_.message -match "ShareName.*Admin$") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_admin_share_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_admin_share_access";
            $detectedMessage = "Detects access to $ADMIN share";
            $result = $event |  where { (($_.ID -eq "5140" -and $_.message -match "ShareName.*Admin$") -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
