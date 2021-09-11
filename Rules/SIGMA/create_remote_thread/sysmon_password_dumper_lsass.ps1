# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "StartModule.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_password_dumper_lsass";
    $detectedMessage = "Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "8" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "StartModule.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
