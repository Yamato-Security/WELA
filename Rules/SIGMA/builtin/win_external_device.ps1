# Get-WinEvent -LogName Security | where {(((($_.ID -eq "6416") -and $_.message -match "ClassName.*DiskDrive") -or $_.message -match "DeviceDescription.*USB Mass Storage Device")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_external_device";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_external_device";
            $detectedMessage = "Detects external diskdrives or plugged in USB devices , EventID 6416 on windows 10 or later";
            $result = $event |  where { (((($_.ID -eq "6416") -and $_.message -match "ClassName.*DiskDrive") -or $_.message -match "DeviceDescription.*USB Mass Storage Device")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
