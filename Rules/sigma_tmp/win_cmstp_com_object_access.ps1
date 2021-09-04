# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*\DllHost.exe .*" -and ($_.message -match "ParentCommandLine.*.*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -or $_.message -match "ParentCommandLine.*.*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_cmstp_com_object_access";
    $detectedMessage = "Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*\DllHost.exe .*" -and ($_.message -match "ParentCommandLine.*.*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -or $_.message -match "ParentCommandLine.*.*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
