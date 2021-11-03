# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*ProcessHacker" -and $_.message -match "AccountName.*LocalSystem") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_proceshacker";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_proceshacker";
            $detectedMessage = "Detects a ProcessHacker tool that elevated privileges to a very high level";
            $result = $event |  where { ($_.ID -eq "7045" -and $_.message -match "ServiceName.*ProcessHacker" -and $_.message -match "AccountName.*LocalSystem") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
