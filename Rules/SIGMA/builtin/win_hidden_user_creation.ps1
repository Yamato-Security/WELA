# Get-WinEvent -LogName Security | where {($_.ID -eq "4720" -and $_.message -match "TargetUserName.*.*$") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hidden_user_creation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hidden_user_creation";
            $detectedMessage = "Detects the creation of a local hidden user account which should not happen for event ID 4720.";
            $result = $event |  where { ($_.ID -eq "4720" -and $_.message -match "TargetUserName.*.*$") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
