# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_config_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "sysmon_config_modification";
            $detectedMessage = "Someone try to hide from Sysmon";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMesssage;    
                    Write-Output $result;
                    Write-Output ""; 
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
