# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*firewall" -and $_.message -match "CommandLine.*.*add") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_fw_add";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_netsh_fw_add";
            $detectedMessage = "Allow Incoming Connections by Port or Application on Windows Firewall";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and $_.message -match "CommandLine.*.*firewall" -and $_.message -match "CommandLine.*.*add") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
