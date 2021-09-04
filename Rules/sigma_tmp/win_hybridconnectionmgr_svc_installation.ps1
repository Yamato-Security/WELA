# Get-WinEvent -LogName Security | where {(($_.ID -eq "4697") -and $_.message -match "ServiceName.*HybridConnectionManager" -and $_.Service File Name -eq "*HybridConnectionManager*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_hybridconnectionmgr_svc_installation";
    $detectedMessage = "Rule to detect the Hybrid Connection Manager service installation."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4697") -and $_.message -match "ServiceName.*HybridConnectionManager" -and $_.Service File Name -eq "*HybridConnectionManager*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
