# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and ($_.message -match "ImageLoaded.*.*\WinDivert.sys.*" -or $_.message -match "ImageLoaded.*.*\WinDivert64.sys.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_windivert_driver_load";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "6" -and ($_.message -match "ImageLoaded.*.*\WinDivert.sys.*" -or $_.message -match "ImageLoaded.*.*\WinDivert64.sys.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
