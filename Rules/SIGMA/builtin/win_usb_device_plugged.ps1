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
