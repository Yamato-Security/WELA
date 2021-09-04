# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe.*" -and ($_.message -match "CommandLine.*.*.sys,.*" -or $_.message -match "CommandLine.*.*.sys .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_rundll32_sys";
    $detectedMessage = "Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe.*" -and ($_.message -match "CommandLine.*.*.sys,.*" -or $_.message -match "CommandLine.*.*.sys .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
