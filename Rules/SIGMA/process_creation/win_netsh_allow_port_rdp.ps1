# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*netsh" -and (($_.message -match "CommandLine.*.*firewall add portopening" -and $_.message -match "CommandLine.*.*tcp 3389") -or ($_.message -match "CommandLine.*.*advfirewall firewall add rule" -and $_.message -match "CommandLine.*.*action=allow" -and $_.message -match "CommandLine.*.*protocol=TCP" -and $_.message -match "CommandLine.*.*localport=3389"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_allow_port_rdp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_netsh_allow_port_rdp";
            $detectedMessage = "Detects netsh commands that opens the port 3389 used for RDP, used in Sarwent Malware";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*netsh" -and (($_.message -match "CommandLine.*.*firewall add portopening" -and $_.message -match "CommandLine.*.*tcp 3389") -or ($_.message -match "CommandLine.*.*advfirewall firewall add rule" -and $_.message -match "CommandLine.*.*action=allow" -and $_.message -match "CommandLine.*.*protocol=TCP" -and $_.message -match "CommandLine.*.*localport=3389"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
