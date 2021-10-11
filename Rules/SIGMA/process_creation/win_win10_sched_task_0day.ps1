# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.*/change.*" -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*/RU.*" -and $_.message -match "CommandLine.*.*/RP.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_win10_sched_task_0day";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_win10_sched_task_0day";
            $detectedMessage = "Detects Task Scheduler .job import arbitrary DACL writepar";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.*/change.*" -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*/RU.*" -and $_.message -match "CommandLine.*.*/RP.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
