# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and (($_.message -match "CommandLine.*.*interface" -and $_.message -match "CommandLine.*.*portproxy" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.*v4tov4") -or ($_.message -match "CommandLine.*.*connectp" -and $_.message -match "CommandLine.*.*listena" -and $_.message -match "CommandLine.*.*c="))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_port_fwd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_netsh_port_fwd";
            $detectedMessage = "Detects netsh commands that configure a port forwarding (PortProxy)";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and (($_.message -match "CommandLine.*.*interface" -and $_.message -match "CommandLine.*.*portproxy" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.*v4tov4") -or ($_.message -match "CommandLine.*.*connectp" -and $_.message -match "CommandLine.*.*listena" -and $_.message -match "CommandLine.*.*c="))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
