
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_exchange_transportagent";
    $detectedMessage = "Detects the Installation of a Exchange Transport Agent"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Install-TransportAgent.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Install-TransportAgent.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
