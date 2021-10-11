# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "sysmon_regsvr32_network_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "sysmon_regsvr32_network_activity";
            $detectedMessage = "Detects network connections and DNS queries initiated by Regsvr32.exe";
            $results = @();
            $results += $event | where { ($_.ID -eq "3" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "22" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
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
