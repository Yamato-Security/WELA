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
