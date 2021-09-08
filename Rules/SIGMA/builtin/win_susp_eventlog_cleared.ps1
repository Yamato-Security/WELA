# Get-WinEvent -LogName Security | where { (($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName System | where { ($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_eventlog_cleared";
    $detectedMessage = "One of the Windows Eventlogs has been cleared. e.g. caused by ""wevtutil cl"" command execution";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
