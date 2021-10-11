# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "EventType.*DeleteValue" -and $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") -or $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_narrator_feedback_persistance";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_narrator_feedback_persistance";
            $detectedMessage = "Detects abusing Windows 10 Narrator's Feedback-Hub";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "EventType.*DeleteValue" -and $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") -or $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
