# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*logman .*") -and ($_.message -match "CommandLine.*.*stop .*" -or $_.message -match "CommandLine.*.*delete .*") -and ($_.message -match "CommandLine.*.*EventLog-System.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_disable_eventlog";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_disable_eventlog";
            $detectedMessage = "Detects command that is used to disable or delete Windows eventlog via logman Windows utility";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*logman .*") -and ($_.message -match "CommandLine.*.*stop .*" -or $_.message -match "CommandLine.*.*delete .*") -and ($_.message -match "CommandLine.*.*EventLog-System.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
