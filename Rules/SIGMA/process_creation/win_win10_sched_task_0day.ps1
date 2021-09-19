# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.*/change.*" -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*/RU.*" -and $_.message -match "CommandLine.*.*/RP.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_win10_sched_task_0day";
    $detectedMessage = "Detects Task Scheduler .job import arbitrary DACL writepar";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.*/change.*" -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*/RU.*" -and $_.message -match "CommandLine.*.*/RP.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
