# Get-WinEvent -LogName Security | where {(($_.ID -eq "4697") -and $_.message -match "ServiceName.*HybridConnectionManager" -and $_.Service File Name -eq "*HybridConnectionManager*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hybridconnectionmgr_svc_installation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hybridconnectionmgr_svc_installation";
            $detectedMessage = "Rule to detect the Hybrid Connection Manager service installation.";
            $result = $event |  where { (($_.ID -eq "4697") -and $_.message -match "ServiceName.*HybridConnectionManager" -and $_.message -Like "*HybridConnectionManager*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
