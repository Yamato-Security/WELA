# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and (($_.message -match "CommandLine.*.*interface.*" -and $_.message -match "CommandLine.*.*portproxy.*" -and $_.message -match "CommandLine.*.*add.*" -and $_.message -match "CommandLine.*.*v4tov4.*") -or ($_.message -match "CommandLine.*.*connectp.*" -and $_.message -match "CommandLine.*.*listena.*" -and $_.message -match "CommandLine.*.*c=.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_port_fwd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_netsh_port_fwd";
            $detectedMessage = "Detects netsh commands that configure a port forwarding (PortProxy)";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and (($_.message -match "CommandLine.*.*interface.*" -and $_.message -match "CommandLine.*.*portproxy.*" -and $_.message -match "CommandLine.*.*add.*" -and $_.message -match "CommandLine.*.*v4tov4.*") -or ($_.message -match "CommandLine.*.*connectp.*" -and $_.message -match "CommandLine.*.*listena.*" -and $_.message -match "CommandLine.*.*c=.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
