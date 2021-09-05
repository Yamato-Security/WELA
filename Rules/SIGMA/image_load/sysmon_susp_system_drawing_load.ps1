# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*\System.Drawing.ni.dll" -and  -not ($_.message -match "Image.*.*\WmiPrvSE.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_system_drawing_load";
    $detectedMessage = "A General detection for processes loading System.Drawing.ni.dll. This could be an indicator of potential Screen Capture."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*\System.Drawing.ni.dll" -and -not ($_.message -match "Image.*.*\WmiPrvSE.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
