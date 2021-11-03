# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\" -and $_.message -match "TargetObject.*.*\\NonPackaged" -and ($_.message -match "TargetObject.*.*microphone" -or $_.message -match "TargetObject.*.*webcam") -and ($_.message -match "TargetObject.*.*#C:#Windows#Temp#" -or $_.message -match "TargetObject.*.*#C:#$Recycle.bin#" -or $_.message -match "TargetObject.*.*#C:#Temp#" -or $_.message -match "TargetObject.*.*#C:#Users#Public#" -or $_.message -match "TargetObject.*.*#C:#Users#Default#" -or $_.message -match "TargetObject.*.*#C:#Users#Desktop#")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_mic_cam_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_mic_cam_access";
            $detectedMessage = "Detects Processes accessing the camera and microphone from suspicious folder";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\" -and $_.message -match "TargetObject.*.*\\NonPackaged" -and ($_.message -match "TargetObject.*.*microphone" -or $_.message -match "TargetObject.*.*webcam") -and ($_.message -match "TargetObject.*.*#C:#Windows#Temp#" -or $_.message -match "TargetObject.*.*#C:#$Recycle.bin#" -or $_.message -match "TargetObject.*.*#C:#Temp#" -or $_.message -match "TargetObject.*.*#C:#Users#Public#" -or $_.message -match "TargetObject.*.*#C:#Users#Default#" -or $_.message -match "TargetObject.*.*#C:#Users#Desktop#")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
