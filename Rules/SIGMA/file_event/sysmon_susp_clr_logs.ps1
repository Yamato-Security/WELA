# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\AppData\Local\Microsoft\CLR.*" -and $_.message -match "TargetFilename.*.*\UsageLogs\.*" -and ($_.message -match "TargetFilename.*.*mshta.*" -or $_.message -match "TargetFilename.*.*cscript.*" -or $_.message -match "TargetFilename.*.*wscript.*" -or $_.message -match "TargetFilename.*.*regsvr32.*" -or $_.message -match "TargetFilename.*.*wmic.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_clr_logs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_clr_logs";
            $detectedMessage = "Detects suspicious .NET assembly executions ";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Microsoft\\CLR.*" -and $_.message -match "TargetFilename.*.*\\UsageLogs\\.*" -and ($_.message -match "TargetFilename.*.*mshta.*" -or $_.message -match "TargetFilename.*.*cscript.*" -or $_.message -match "TargetFilename.*.*wscript.*" -or $_.message -match "TargetFilename.*.*regsvr32.*" -or $_.message -match "TargetFilename.*.*wmic.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
