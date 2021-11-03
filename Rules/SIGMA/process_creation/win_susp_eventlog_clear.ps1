# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\powershell.exe" -and ($_.message -match "CommandLine.*.*Clear-EventLog" -or $_.message -match "CommandLine.*.*Remove-EventLog" -or $_.message -match "CommandLine.*.*Limit-EventLog")) -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.* ClearEventLog ")) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\wevtutil.exe" -and ($_.message -match "CommandLine.*.*clear-log" -or $_.message -match "CommandLine.*.* cl " -or $_.message -match "CommandLine.*.*set-log" -or $_.message -match "CommandLine.*.* sl ")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_eventlog_clear";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_eventlog_clear";
            $detectedMessage = "Detects clearing or configuration of eventlogs using wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others).";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\powershell.exe" -and ($_.message -match "CommandLine.*.*Clear-EventLog" -or $_.message -match "CommandLine.*.*Remove-EventLog" -or $_.message -match "CommandLine.*.*Limit-EventLog")) -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.* ClearEventLog ")) -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\wevtutil.exe" -and ($_.message -match "CommandLine.*.*clear-log" -or $_.message -match "CommandLine.*.* cl " -or $_.message -match "CommandLine.*.*set-log" -or $_.message -match "CommandLine.*.* sl ")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
