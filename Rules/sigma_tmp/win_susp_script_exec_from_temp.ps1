# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe") -and ($_.message -match "CommandLine.*.*\Windows\Temp.*" -or $_.message -match "CommandLine.*.*\Temporary Internet.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp.*" -or $_.message -match "CommandLine.*.*\AppData\Roaming\Temp.*" -or $_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*%TMP%.*" -or $_.message -match "CommandLine.*.*%LocalAppData%\Temp.*")) -and  -not ($_.message -match "CommandLine.*.* >.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_script_exec_from_temp";
    $detectedMessage = "Detects a suspicious script executions from temporary folder"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe") -and ($_.message -match "CommandLine.*.*\Windows\Temp.*" -or $_.message -match "CommandLine.*.*\Temporary Internet.*" -or $_.message -match "CommandLine.*.*\AppData\Local\Temp.*" -or $_.message -match "CommandLine.*.*\AppData\Roaming\Temp.*" -or $_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*%TMP%.*" -or $_.message -match "CommandLine.*.*%LocalAppData%\Temp.*")) -and -not ($_.message -match "CommandLine.*.* >.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
