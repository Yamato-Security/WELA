# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "7" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_silenttrinity_stage_use";
    $detectedMessage = "Detects SILENTTRINITY stager use";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "7" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
