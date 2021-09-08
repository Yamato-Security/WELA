# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\profile.ps1.*" -and ($_.message -match "TargetFilename.*.*\My Documents\PowerShell\.*" -or $_.message -match "TargetFilename.*.*C:\Windows\System32\WindowsPowerShell\v1.0\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_suspicious_profile_create";
    $detectedMessage = "Detects a change in profile.ps1 of the Powershell profile";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\profile.ps1.*" -and ($_.message -match "TargetFilename.*.*\My Documents\PowerShell\.*" -or $_.message -match "TargetFilename.*.*C:\Windows\System32\WindowsPowerShell\v1.0\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
