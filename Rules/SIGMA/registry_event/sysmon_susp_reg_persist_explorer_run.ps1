# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -and (($_.message -match "Details.*C:\Windows\Temp\.*" -or $_.message -match "Details.*C:\ProgramData\.*" -or $_.message -match "Details.*C:\$Recycle.bin\.*" -or $_.message -match "Details.*C:\Temp\.*" -or $_.message -match "Details.*C:\Users\Public\.*" -or $_.message -match "Details.*C:\Users\Default\.*") -or ($_.message -match "Details.*.*\AppData\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_reg_persist_explorer_run";
    $detectedMessage = "Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -and (($_.message -match "Details.*C:\Windows\Temp\.*" -or $_.message -match "Details.*C:\ProgramData\.*" -or $_.message -match "Details.*C:\$Recycle.bin\.*" -or $_.message -match "Details.*C:\Temp\.*" -or $_.message -match "Details.*C:\Users\Public\.*" -or $_.message -match "Details.*C:\Users\Default\.*") -or ($_.message -match "Details.*.*\AppData\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
