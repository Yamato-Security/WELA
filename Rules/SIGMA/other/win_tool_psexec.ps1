# Get-WinEvent -LogName System | where { ($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.Service File Name -eq "*\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "17" -or $_.ID -eq "18") -and $_.message -match "PipeName.*\\PSEXESVC") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\PSEXESVC.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_tool_psexec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_tool_psexec";
            $detectedMessage = "Detects PsExec service installation and execution events (service and Sysmon)";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.message -like "*\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "17" -or $_.ID -eq "18") -and $_.message -match "PipeName.*\\PSEXESVC") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\PSEXESVC.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output ""; 
                }
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
