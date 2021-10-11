# Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Install-TransportAgent.*" -and $_.ID -eq "6") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_exchange_TransportAgent_failed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_exchange_TransportAgent_failed";
            $detectedMessage = "Detects a failed installation of a Exchange Transport Agent";
            $result = $event |  where { ($_.message -match ".*Install-TransportAgent.*" -and $_.ID -eq "6") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
