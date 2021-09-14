# Get-WinEvent -LogName System | where { ($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.Service File Name -eq "*\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "17" -or $_.ID -eq "18") -and $_.message -match "PipeName.*\\PSEXESVC") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\PSEXESVC.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_tool_psexec";
    $detectedMessage = "Detects PsExec service installation and execution events (service and Sysmon)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { ($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.message -like "*\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { (($_.ID -eq "17" -or $_.ID -eq "18") -and $_.message -match "PipeName.*\\PSEXESVC") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\PSEXESVC.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($entry in $results) {
                if ($entry.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $entry.Value
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
