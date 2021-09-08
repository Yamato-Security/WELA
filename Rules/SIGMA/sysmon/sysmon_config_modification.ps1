# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error.*" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_config_modification";
    $detectedMessage = "Someone try to hide from Sysmon";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ((($_.ID -eq "4" -or $_.ID -eq "16")) -and ($_.message -match "State.*Stopped" -or ($_.message -match "Sysmon config state changed.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 - $event | where { ($_.ID -eq "255" -and ($_.message -match "Description.*.*Failed to open service configuration with error.*" -or $_.message -match "Description.*.*Failed to connect to the driver to update configuration.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
