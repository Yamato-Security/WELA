# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "QueryName.*.*servicebus.windows.net.*" -and $_.message -match "Image.*.*HybridConnectionManager.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_dns_hybridconnectionmgr_servicebus";
    $detectedMessage = "Detects Azure Hybrid Connection Manager services querying the Azure service bus service";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "22" -and $_.message -match "QueryName.*.*servicebus.windows.net.*" -and $_.message -match "Image.*.*HybridConnectionManager.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}