# Get-WinEvent -LogName Microsoft-Windows-DriverFrameworks-UserMode/Operational | where {(($_.ID -eq "2003" -or $_.ID -eq "2100" -or $_.ID -eq "2102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_usb_device_plugged";
    $detectedMessage = "Detects plugged USB devices";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "2003" -or $_.ID -eq "2100" -or $_.ID -eq "2102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
