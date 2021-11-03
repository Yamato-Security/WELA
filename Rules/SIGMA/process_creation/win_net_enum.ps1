# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.*view") -and  -not ($_.message -match "CommandLine.*.*\\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_net_enum";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_net_enum";
            $detectedMessage = "Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*view") -and -not ($_.message -match "CommandLine.*.*\\\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
