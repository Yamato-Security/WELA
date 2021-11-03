# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "StartModule") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_password_dumper_lsass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_password_dumper_lsass";
            $detectedMessage = "Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.";
            $result = $event |  where { ($_.ID -eq "8" -and $_.message -match "TargetImage.*.*\\lsass.exe" -and $_.message -match "StartModule") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
