# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\notepad.exe") -and ($_.message -match "ImageLoaded.*.*\samlib.dll" -or $_.message -match "ImageLoaded.*.*\WinSCard.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_image_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_image_load";
            $detectedMessage = "Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz";
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*\\notepad.exe") -and ($_.message -match "ImageLoaded.*.*\\samlib.dll" -or $_.message -match "ImageLoaded.*.*\\WinSCard.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
