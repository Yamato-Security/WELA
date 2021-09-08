# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\scrcons.exe" -and ($_.message -match "ImageLoaded.*.*\vbscript.dll" -or $_.message -match "ImageLoaded.*.*\wbemdisp.dll" -or $_.message -match "ImageLoaded.*.*\wshom.ocx" -or $_.message -match "ImageLoaded.*.*\scrrun.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_scrcons_imageload_wmi_scripteventconsumer";
    $detectedMessage = "Detects signs of the WMI script host process %SystemRoot%system32wbemscrcons.exe functionality being used via images being loaded by a process.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7" -and $_.message -match "Image.*.*\scrcons.exe" -and ($_.message -match "ImageLoaded.*.*\vbscript.dll" -or $_.message -match "ImageLoaded.*.*\wbemdisp.dll" -or $_.message -match "ImageLoaded.*.*\wshom.ocx" -or $_.message -match "ImageLoaded.*.*\scrrun.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
