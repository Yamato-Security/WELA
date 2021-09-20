Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Install-TransportAgent.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
Get-WinEvent -LogName MSExchange Management | where { ($_.message -match ".*Install-TransportAgent.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_exchange_transportagent";
    $detectedMessage = "Detects the Installation of a Exchange Transport Agent";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Install-TransportAgent.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match ".*Install-TransportAgent.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
