# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\AppData\Local\Microsoft\CLR" -and $_.message -match "TargetFilename.*.*\UsageLogs\" -and ($_.message -match "TargetFilename.*.*mshta" -or $_.message -match "TargetFilename.*.*cscript" -or $_.message -match "TargetFilename.*.*wscript" -or $_.message -match "TargetFilename.*.*regsvr32" -or $_.message -match "TargetFilename.*.*wmic")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_clr_logs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_clr_logs";
            $detectedMessage = "Detects suspicious .NET assembly executions ";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Microsoft\\CLR" -and $_.message -match "TargetFilename.*.*\\UsageLogs\\" -and ($_.message -match "TargetFilename.*.*mshta" -or $_.message -match "TargetFilename.*.*cscript" -or $_.message -match "TargetFilename.*.*wscript" -or $_.message -match "TargetFilename.*.*regsvr32" -or $_.message -match "TargetFilename.*.*wmic")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
