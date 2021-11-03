# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") -and (($_.message -match "TargetObject.*.*\\Image File Execution Options\\" -and $_.message -match "TargetObject.*.*\\GlobalFlag") -or ($_.message -match "TargetObject.*.*SilentProcessExit\\" -and $_.message -match "TargetObject.*.*\\ReportingMode") -or ($_.message -match "TargetObject.*.*SilentProcessExit\\" -and $_.message -match "TargetObject.*.*\\MonitorProcess"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_win_reg_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_win_reg_persistence";
            $detectedMessage = "Detects persistence registry keys";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") -and (($_.message -match "TargetObject.*.*\\Image File Execution Options\\" -and $_.message -match "TargetObject.*.*\\GlobalFlag") -or ($_.message -match "TargetObject.*.*SilentProcessExit\\" -and $_.message -match "TargetObject.*.*\\ReportingMode") -or ($_.message -match "TargetObject.*.*SilentProcessExit\\" -and $_.message -match "TargetObject.*.*\\MonitorProcess"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                result;
                Write-Output $detectedMessage;
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
