# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*netsh" -and $_.message -match "CommandLine.*.*trace" -and $_.message -match "CommandLine.*.*start") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_packet_capture";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_netsh_packet_capture";
            $detectedMessage = "Detects capture a network trace via netsh.exe trace functionality";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*netsh" -and $_.message -match "CommandLine.*.*trace" -and $_.message -match "CommandLine.*.*start") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
