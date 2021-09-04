# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*:\RECYCLER\.*" -or $_.message -match "Image.*.*:\SystemVolumeInformation\.*") -or ($_.message -match "Image.*C:\Windows\Tasks\.*" -or $_.message -match "Image.*C:\Windows\debug\.*" -or $_.message -match "Image.*C:\Windows\fonts\.*" -or $_.message -match "Image.*C:\Windows\help\.*" -or $_.message -match "Image.*C:\Windows\drivers\.*" -or $_.message -match "Image.*C:\Windows\addins\.*" -or $_.message -match "Image.*C:\Windows\cursors\.*" -or $_.message -match "Image.*C:\Windows\system32\tasks\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_run_locations";
    $detectedMessage = "Detects suspicious process run from unusual locations"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*:\RECYCLER\.*" -or $_.message -match "Image.*.*:\SystemVolumeInformation\.*") -or ($_.message -match "Image.*C:\Windows\Tasks\.*" -or $_.message -match "Image.*C:\Windows\debug\.*" -or $_.message -match "Image.*C:\Windows\fonts\.*" -or $_.message -match "Image.*C:\Windows\help\.*" -or $_.message -match "Image.*C:\Windows\drivers\.*" -or $_.message -match "Image.*C:\Windows\addins\.*" -or $_.message -match "Image.*C:\Windows\cursors\.*" -or $_.message -match "Image.*C:\Windows\system32\tasks\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
