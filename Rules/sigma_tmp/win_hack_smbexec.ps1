# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.Service File Name -eq "*\execute.bat") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_hack_smbexec";
    $detectedMessage = "Detects the use of smbexec.py tool by detecting a specific service installation"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*BTOBTO" -and $_.Service File Name -eq "*\execute.bat") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}