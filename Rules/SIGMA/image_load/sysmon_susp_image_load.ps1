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
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
