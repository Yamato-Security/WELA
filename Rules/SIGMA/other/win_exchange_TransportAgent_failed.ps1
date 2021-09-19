# Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Install-TransportAgent.*" -and $_.ID -eq "6") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_exchange_TransportAgent_failed";
    $detectedMessage = "Detects a failed installation of a Exchange Transport Agent";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.message -match ".*Install-TransportAgent.*" -and $_.ID -eq "6") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
