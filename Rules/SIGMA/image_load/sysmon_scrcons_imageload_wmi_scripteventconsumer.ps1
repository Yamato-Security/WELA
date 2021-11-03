# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\scrcons.exe" -and ($_.message -match "ImageLoaded.*.*\vbscript.dll" -or $_.message -match "ImageLoaded.*.*\wbemdisp.dll" -or $_.message -match "ImageLoaded.*.*\wshom.ocx" -or $_.message -match "ImageLoaded.*.*\scrrun.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_scrcons_imageload_wmi_scripteventconsumer";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_scrcons_imageload_wmi_scripteventconsumer";
            $detectedMessage = "Detects signs of the WMI script host process %SystemRoot%system32wbemscrcons.exe functionality being used via images being loaded by a process.";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\\scrcons.exe" -and ($_.message -match "ImageLoaded.*.*\\vbscript.dll" -or $_.message -match "ImageLoaded.*.*\\wbemdisp.dll" -or $_.message -match "ImageLoaded.*.*\\wshom.ocx" -or $_.message -match "ImageLoaded.*.*\\scrrun.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
