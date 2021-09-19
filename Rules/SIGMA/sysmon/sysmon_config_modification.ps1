# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error.*" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_config_modification";
    $detectedMessage = "Someone try to hide from Sysmon";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error.*" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
