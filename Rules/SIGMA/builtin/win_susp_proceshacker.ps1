# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*ProcessHacker.*" -and $_.message -match "AccountName.*LocalSystem") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_proceshacker";
    $detectedMessage = "Detects a ProcessHacker tool that elevated privileges to a very high level";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*ProcessHacker.*" -and $_.message -match "AccountName.*LocalSystem") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
