# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*time") -or ($_.message -match "Image.*.*\\w32tm.exe" -and $_.message -match "CommandLine.*.*tz") -or ($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Date"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_remote_time_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_remote_time_discovery";
            $detectedMessage = "Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*time") -or ($_.message -match "Image.*.*\\w32tm.exe" -and $_.message -match "CommandLine.*.*tz") -or ($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Date"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
