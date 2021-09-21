# Get-WinEvent -LogName Security | where { (($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName System | where { ($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_eventlog_cleared";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_eventlog_cleared";
            $detectedMessage = "One of the Windows Eventlogs has been cleared. e.g. caused by ""wevtutil cl"" command execution"
            $results = @();
            $results += $event | where { (($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
