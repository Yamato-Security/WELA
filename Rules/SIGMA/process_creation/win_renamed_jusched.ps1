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
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
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
