# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "netsh firewall set opmode mode=disable" -or $_.message -match "CommandLine.*netsh advfirewall set .* state off")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_firewall_disable";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_firewall_disable";
            $detectedMessage = "Detects netsh commands that turns off the Windows firewall";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "netsh firewall set opmode mode=disable" -or $_.message -match "CommandLine.*netsh advfirewall set . .. state off")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
