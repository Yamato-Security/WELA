# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "QueryName.*.*servicebus.windows.net" -and $_.message -match "Image.*.*HybridConnectionManager") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_dns_hybridconnectionmgr_servicebus";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_dns_hybridconnectionmgr_servicebus";
            $detectedMessage = "Detects Azure Hybrid Connection Manager services querying the Azure service bus service";
            $result = $event |  where { ($_.ID -eq "22" -and $_.message -match "QueryName.*.*servicebus.windows.net" -and $_.message -match "Image.*.*HybridConnectionManager") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                result;
                Write-Output $detectedMessage;
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
