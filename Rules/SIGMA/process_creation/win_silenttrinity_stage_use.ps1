# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Description.*.*st2stager") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "7" -and $_.message -match "Description.*.*st2stager") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_silenttrinity_stage_use";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_silenttrinity_stage_use";
            $detectedMessage = "Detects SILENTTRINITY stager use";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "Description.*.*st2stager") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "7" -and $_.message -match "Description.*.*st2stager") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
