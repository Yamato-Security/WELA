# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and ($_.message -match "CommandLine.*.*/delete.*" -or $_.message -match "CommandLine.*.*/change.*") -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4701" -and $_.message -match "TaskName.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_slingshot";
    $detectedMessage = "Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and ($_.message -match "CommandLine.*.*/delete.*" -or $_.message -match "CommandLine.*.*/change.*") -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "4701" -and $_.message -match "TaskName.*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
