# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*PAExec Application" -or $_.message -match "OriginalFileName.*PAExec.exe")) -and  -not (($_.message -match "Image.*.*\PAexec.exe" -or $_.message -match "Image.*.*\paexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_renamed_paexec";
    $detectedMessage = "Detects suspicious renamed PAExec execution as often used by attackers"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and ($_.message -match "Description.*PAExec Application" -or $_.message -match "OriginalFileName.*PAExec.exe")) -and -not (($_.message -match "Image.*.*\PAexec.exe" -or $_.message -match "Image.*.*\paexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
