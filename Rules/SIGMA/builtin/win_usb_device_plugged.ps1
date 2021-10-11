# Get-WinEvent -LogName Microsoft-Windows-DriverFrameworks-UserMode/Operational | where {(($_.ID -eq "2003" -or $_.ID -eq "2100" -or $_.ID -eq "2102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_usb_device_plugged";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_usb_device_plugged";
            $detectedMessage = "Detects plugged USB devices";
            $result = $event |  where { (($_.ID -eq "2003" -or $_.ID -eq "2100" -or $_.ID -eq "2102")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
