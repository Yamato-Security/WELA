# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and ($_.message -match "SourceImage.*.*\System32\cscript.exe" -or $_.message -match "SourceImage.*.*\System32\wscript.exe" -or $_.message -match "SourceImage.*.*\System32\mshta.exe" -or $_.message -match "SourceImage.*.*\winword.exe" -or $_.message -match "SourceImage.*.*\excel.exe") -and $_.message -match "TargetImage.*.*\SysWOW64\.*" -and -not StartModule="*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_cactustorch";
    $detectedMessage = "Detects remote thread creation from CACTUSTORCH as described in references."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "8" -and ($_.message -match "SourceImage.*.*\System32\cscript.exe" -or $_.message -match "SourceImage.*.*\System32\wscript.exe" -or $_.message -match "SourceImage.*.*\System32\mshta.exe" -or $_.message -match "SourceImage.*.*\winword.exe" -or $_.message -match "SourceImage.*.*\excel.exe") -and $_.message -match "TargetImage.*.*\SysWOW64\.*" -and -not StartModule="*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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