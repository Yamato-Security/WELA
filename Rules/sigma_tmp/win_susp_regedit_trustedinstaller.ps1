# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\regedit.exe" -and ($_.message -match "ParentImage.*.*\TrustedInstaller.exe" -or $_.message -match "ParentImage.*.*\ProcessHacker.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_regedit_trustedinstaller";
    $detectedMessage = "Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\regedit.exe" -and ($_.message -match "ParentImage.*.*\TrustedInstaller.exe" -or $_.message -match "ParentImage.*.*\ProcessHacker.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
