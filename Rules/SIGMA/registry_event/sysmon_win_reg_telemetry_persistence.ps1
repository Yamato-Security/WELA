# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\" -and $_.message -match "TargetObject.*.*\\Command" -and $_.message -match "Details.*.*.exe") -and  -not (($_.message -match "Details.*.*\\system32\\CompatTelRunner.exe" -or $_.message -match "Details.*.*\\system32\\DeviceCensus.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_win_reg_telemetry_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_win_reg_telemetry_persistence";
            $detectedMessage = "Detects persistence method using windows telemetry ";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\" -and $_.message -match "TargetObject.*.*\\Command" -and $_.message -match "Details.*.*.exe") -and -not (($_.message -match "Details.*.*\\system32\\CompatTelRunner.exe" -or $_.message -match "Details.*.*\\system32\\DeviceCensus.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
