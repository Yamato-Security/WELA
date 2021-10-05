# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.Service File Name -eq "*\execute.bat") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_smbexec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hack_smbexec";
            $detectedMessage = "Detects the use of smbexec.py tool by detecting a specific service installation";
            $result = $event |  where { ($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.message -Like "*\\execute.bat") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
