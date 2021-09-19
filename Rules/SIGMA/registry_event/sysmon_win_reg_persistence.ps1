# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion.*") -and (($_.message -match "TargetObject.*.*\Image File Execution Options\.*" -and $_.message -match "TargetObject.*.*\GlobalFlag.*") -or ($_.message -match "TargetObject.*.*SilentProcessExit\.*" -and $_.message -match "TargetObject.*.*\ReportingMode.*") -or ($_.message -match "TargetObject.*.*SilentProcessExit\.*" -and $_.message -match "TargetObject.*.*\MonitorProcess.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_win_reg_persistence";
    $detectedMessage = "Detects persistence registry keys";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion.*") -and (($_.message -match "TargetObject.*.*\Image File Execution Options\.*" -and $_.message -match "TargetObject.*.*\GlobalFlag.*") -or ($_.message -match "TargetObject.*.*SilentProcessExit\.*" -and $_.message -match "TargetObject.*.*\ReportingMode.*") -or ($_.message -match "TargetObject.*.*SilentProcessExit\.*" -and $_.message -match "TargetObject.*.*\MonitorProcess.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
