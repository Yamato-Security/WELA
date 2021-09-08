# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_regsvr32_network_activity";
    $detectedMessage = "Detects network connections and DNS queries initiated by Regsvr32.exe";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "3" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $result2 = $event | where { ($_.ID -eq "22" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
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
