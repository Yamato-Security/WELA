# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\.*" -and $_.message -match "TargetObject.*.*\Command.*" -and $_.message -match "Details.*.*.exe.*") -and  -not (($_.message -match "Details.*.*\system32\CompatTelRunner.exe.*" -or $_.message -match "Details.*.*\system32\DeviceCensus.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_win_reg_telemetry_persistence";
    $detectedMessage = "Detects persistence method using windows telemetry ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\.*" -and $_.message -match "TargetObject.*.*\Command.*" -and $_.message -match "Details.*.*.exe.*") -and -not (($_.message -match "Details.*.*\system32\CompatTelRunner.exe.*" -or $_.message -match "Details.*.*\system32\DeviceCensus.exe.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
