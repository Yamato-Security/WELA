# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*\System.Drawing.ni.dll" -and  -not ($_.message -match "Image.*.*\WmiPrvSE.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_system_drawing_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_system_drawing_load";
            $detectedMessage = "A General detection for processes loading System.Drawing.ni.dll. This could be an indicator of potential Screen Capture.";
            $result = $event |  where { (($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*\\System.Drawing.ni.dll" -and -not ($_.message -match "Image.*.*\\WmiPrvSE.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
