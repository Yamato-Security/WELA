# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Company.*SecurityXploded" -or $_.message -match "Image.*.*PasswordDump.exe" -or $_.message -match "OriginalFileName.*.*PasswordDump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_hack_secutyxploded";
    $detectedMessage = "Detects the execution of SecurityXploded Tools";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "Company.*SecurityXploded" -or $_.message -match "Image.*.*PasswordDump.exe" -or $_.message -match "OriginalFileName.*.*PasswordDump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
