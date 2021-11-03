# Get-WinEvent -LogName System | where { ($_.ID -eq "7045" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "6" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Security | where { ($_.ID -eq "4697" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_tap_driver_installation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_tap_driver_installation";
            $detectedMessage = "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "7045" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "6" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "6" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4697" -and $_.message -match "ImagePath.*.*tap0901") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $result;
                    Write-Output ""; 
                    Write-Output $detectedMessage;    
                }
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
