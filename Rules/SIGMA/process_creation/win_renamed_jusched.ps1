# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*Java Update Scheduler" -or $_.message -match "Description.*Java(TM) Update Scheduler")) -and  -not (($_.message -match "Image.*.*\\jusched.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_jusched";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_jusched";
            $detectedMessage = "Detects renamed jusched.exe used by cobalt group ";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*Java Update Scheduler" -or $_.message -match "Description.*Java(TM) Update Scheduler")) -and -not (($_.message -match "Image.*.*\\jusched.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
