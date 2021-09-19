# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sqltoolsps.exe" -or $_.message -match "ParentImage.*.*\sqltoolsps.exe") -or ($_.message -match "OriginalFileName.*\sqltoolsps.exe" -and  -not ($_.message -match "ParentImage.*.*\smss.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_use_of_sqltoolsps_bin";
    $detectedMessage = "This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio. Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sqltoolsps.exe" -or $_.message -match "ParentImage.*.*\sqltoolsps.exe") -or ($_.message -match "OriginalFileName.*\sqltoolsps.exe" -and -not ($_.message -match "ParentImage.*.*\smss.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
