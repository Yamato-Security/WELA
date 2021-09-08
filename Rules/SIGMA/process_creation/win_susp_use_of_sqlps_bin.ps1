# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sqlps.exe" -or $_.message -match "ParentImage.*.*\sqlps.exe") -or ($_.message -match "OriginalFileName.*\sqlps.exe" -and  -not ($_.message -match "ParentImage.*.*\sqlagent.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_use_of_sqlps_bin";
    $detectedMessage = "This rule detects execution of a PowerShell code through the sqlps.exe utility, which is included in the standard set of utilities supplied with the MSSQL Server. Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sqlps.exe" -or $_.message -match "ParentImage.*.*\sqlps.exe") -or ($_.message -match "OriginalFileName.*\sqlps.exe" -and -not ($_.message -match "ParentImage.*.*\sqlagent.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
